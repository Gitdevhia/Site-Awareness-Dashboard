"""
orchestrator.py - Top-level entry point for Site Awareness Dashboard
data collection. Two actions are available per site:

    cdp - walk CDP outward from the site's seed device, writing
          discovered devices/links into the DB as source='cdp'
    arp - connect to the site's ARP seed device, discover any VRFs,
          and pull the global + per-VRF ARP tables into arp_entries
    configs - connect to every device already in the DB for the site
          (no CDP walk) and store its running-config as a snapshot
          when it changed since the last pull

Usage (CLI - runs immediately, no prompts beyond the credential
password):
    python3 orchestrator.py --site <octet|name|code> --action cdp
    python3 orchestrator.py --all --action arp
    python3 orchestrator.py --site <key> --action all

Usage (interactive menu - just run with no arguments):
    python3 orchestrator.py

IMPORTANT: run this from the project root, not from inside utilities/.
sad.db's path is relative to the current working directory, and all
the utilities/ scripts are meant to be run from the root the same
way (e.g. `python3 utilities/inventory_import.py file.csv`) - staying
consistent about that keeps everything pointed at the same database
file.

Requires a credential store to already exist (via
utilities/credential_manager.py) with a 'tacacs' credential (username
+ password) set up.
"""

import sys
import os
import re
import importlib
import argparse
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "utilities"))

import db  # noqa: E402
import write_queue  # noqa: E402
import credential_loader  # noqa: E402
import cdp_parser  # noqa: E402
import arp_parser  # noqa: E402
import vrf_parser  # noqa: E402
import mac_parser  # noqa: E402
import tunnel_parser  # noqa: E402
import config_parser  # noqa: E402


# How many sites run_for_sites() will scan at once. Bounded rather than
# "one thread per site" so a 127-site run doesn't open 127 concurrent
# SSH sessions plus 127 concurrent DB-write contenders at once - each
# site's own writes already go through the shared write queue (safe
# under contention), but there's no reason to hammer the network/device
# side that hard just because the DB side can now tolerate it. Tune
# this if real-world timing suggests a different number works better;
# nothing else in this file assumes a specific value.
DISCOVERY_MAX_WORKERS = 8

# Seconds to wait for 'show running-config' to finish on one device. The
# default Netmiko read timeout is far too short for a big chassis config.
CONFIG_READ_TIMEOUT = 180


# Substring match against a device's known platform string -> Netmiko
# device_type, checked before paying for a full SSHDetect autodetect
# connection. Add more entries here if other platform families show
# up that aren't plain IOS/IOS-XE. Order matters only in that first
# match wins - keep more specific substrings above generic ones if
# that ever becomes relevant.
_PLATFORM_TYPE_HINTS = [
    ("nexus", "cisco_nxos"),
    ("n9k", "cisco_nxos"),
    ("n7k", "cisco_nxos"),
    ("n5k", "cisco_nxos"),
    ("n3k", "cisco_nxos"),
]


# Longer form first (most specific prefix wins) so a name like
# "TenGigabitEthernet1/1" isn't accidentally matched by a shorter,
# unrelated prefix before reaching its own correct entry.
_INTERFACE_ABBREVIATIONS = sorted([
    ("TenGigabitEthernet", "Te"),
    ("GigabitEthernet", "Gi"),
    ("FastEthernet", "Fa"),
    ("FortyGigabitEthernet", "Fo"),
    ("HundredGigE", "Hu"),
    ("TwentyFiveGigE", "Twe"),
    ("Port-channel", "Po"),
    ("Ethernet", "Eth"),  # NX-OS
], key=lambda pair: -len(pair[0]))


def _normalize_interface(name: str) -> str:
    """Reduces an interface name to a canonical, comparison-only form
    (lowercased, long platform names collapsed to their short form) -
    CDP typically reports full names (GigabitEthernet1/0/1) while
    "show mac address-table" very often reports the same port
    abbreviated (Gi1/0/1). A plain string comparison between the two
    would silently fail to recognize them as the same physical port,
    which would incorrectly treat a genuine inter-switch uplink as if
    it were a client edge port. Only used for comparison - the
    original, unnormalized name is what actually gets stored/shown.
    """
    if not name:
        return ""
    for long_form, short_form in _INTERFACE_ABBREVIATIONS:
        if name.lower().startswith(long_form.lower()):
            return (short_form + name[len(long_form):]).lower()
    return name.lower()


_SEP_HOSTNAME_RE = re.compile(r"^SEP([0-9A-Fa-f]{12})$", re.IGNORECASE)


def _extract_sep_mac(hostname: str):
    """Devices that register to CUCM - both Cisco IP phones AND video
    endpoints (Webex Room/Desk devices, TelePresence units) that
    register in phone-like SCCP/SIP mode - advertise their own CDP
    hostname as "SEP" followed by their 12-hex-digit MAC address (e.g.
    "SEP001122334455"). This is a genuine, reliable "this is a
    CUCM-registered client" signal a generalized MAC-table walk has no
    way to produce on its own - see _classify_sep_device_type() for
    telling phones and video endpoints apart once a SEP hostname is
    found. Returns the raw 12-hex-digit MAC (no separators, matching
    how Cisco itself concatenates it into the hostname) if this is a
    SEP-style hostname, else None.
    """
    match = _SEP_HOSTNAME_RE.match(hostname or "")
    return match.group(1) if match else None


def _classify_sep_device_type(platform: str) -> str:
    """Distinguishes a real desk phone from a video endpoint among
    SEP-registered CDP neighbors, using the neighbor's own CDP
    Platform string. Confirmed against real CDP output: phones
    consistently report a Platform starting with "Cisco IP Phone"
    (e.g. "Cisco IP Phone 8865NR"); video endpoints don't share any
    single consistent naming convention with each other ("Room Kit",
    "Desk Pro", "CTS-CODEC-DX80" have nothing in common) - so rather
    than try to enumerate every video-endpoint naming style (which new
    hardware would keep breaking), anything SEP-registered that ISN'T
    phone-prefixed is classified "vtc". That's a reasonable best
    guess ("SEP-registered, not phone-prefixed"), not a verified claim
    that every possible non-phone platform string is necessarily video
    conferencing gear specifically.
    """
    if (platform or "").strip().lower().startswith("cisco ip phone"):
        return "cisco_phone"
    return "vtc"


def _get_tacacs_credentials(creds: dict) -> tuple:
    """Pulls the username/password out of the credential store's
    reserved "tacacs" type (see credential_manager.py's module
    docstring - "tacacs" is the one credential type this code reads
    directly; everything else in someone's store is theirs to
    organize freely, however they like).

    Raises a clear, actionable ValueError immediately if it's missing
    or incomplete, rather than letting a None username/password
    propagate all the way into a Netmiko connection attempt before
    failing, which would produce a much more confusing error far from
    the real cause.
    """
    tacacs = creds.get("tacacs")
    if not tacacs:
        raise ValueError(
            "No 'tacacs' credential found in your credential store. "
            "Run credential_manager.py and add a 'tacacs' credential (username + password) first."
        )
    username = tacacs.get("username", {}).get("value")
    password = tacacs.get("password", {}).get("value")
    if not username or not password:
        raise ValueError(
            "Your 'tacacs' credential is missing a username or password. "
            "Run credential_manager.py and use (U)pdate to fix it."
        )
    return username, password


def _get_tacacs_secret(creds: dict):
    """Optional enable/privileged-mode secret from the 'tacacs' entry,
    if one has been added there (freeform field, same 'tacacs' type
    used for username/password) - returns None if not configured,
    which is fine for every read-only caller (CDP/ARP never need
    this). Only the command-runner harness uses this, since pushing
    config needs privileged mode.
    """
    tacacs = creds.get("tacacs") or {}
    return tacacs.get("secret", {}).get("value")


def _guess_device_type(platform: str):
    """Return a Netmiko device_type guessed from a platform string via
    substring match, or None if there's no confident guess (caller
    should fall back to SSHDetect autodetection in that case). This
    fleet is otherwise all IOS/IOS-XE, so any non-empty platform that
    doesn't match a Nexus-family substring is assumed cisco_ios rather
    than triggering a full autodetect connection.
    """
    if not platform:
        return None
    platform_lower = platform.lower()
    for substring, device_type in _PLATFORM_TYPE_HINTS:
        if substring in platform_lower:
            return device_type
    return "cisco_ios"


class _WorkerSlotRegistry:
    """Assigns a small, stable, run-scoped slot number (1, 2, 3, ...) to
    each of run_for_sites()'s ThreadPoolExecutor worker threads - the
    first time that thread actually picks up a site, not at submission
    time, since which of the pool's OS threads ends up running a given
    site isn't knowable in advance (the pool reuses its fixed set of
    worker threads across however many sites get submitted).

    A GUI showing one column per worker wants a STABLE identity per
    column across the whole run ("Worker 3" is always the same column,
    even as the actual site it's working on changes many times over
    the run) - that's exactly what this hands out. A fresh registry is
    created per run_for_sites() call, so slot numbers always start over
    at 1 for a new run rather than growing indefinitely across a long
    GUI session.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._thread_slots = {}
        self._site_slots = {}
        self._next_slot = 1

    def assign_site(self, site_octet: str) -> int:
        """Call once, from the worker thread itself, at the start of
        that thread's work on `site_octet`. Returns this thread's slot
        number (assigning it the next free one on first use), and
        records which slot is currently working on this site so
        slot_for_site() can look it up later from a different thread
        (see run_for_sites()'s own "done"/"error" events, emitted back
        on the main thread via as_completed()).
        """
        ident = threading.get_ident()
        with self._lock:
            slot = self._thread_slots.get(ident)
            if slot is None:
                slot = self._next_slot
                self._next_slot += 1
                self._thread_slots[ident] = slot
            self._site_slots[site_octet] = slot
        return slot

    def slot_for_site(self, site_octet: str):
        with self._lock:
            return self._site_slots.get(site_octet)


def _report_progress(progress_cb, event: str, site_octet: str, slot, phase: str, message: str = "") -> None:
    """Best-effort progress notification - never allowed to break the
    actual discovery work over it (a GUI-side rendering bug should
    never take down a scan). progress_cb, if given, is called with
    (event, site_octet, slot, phase, message):

      event="status" - an in-progress update (connecting to a device,
        a table collected, etc) - purely informational, doesn't mean
        this site is finished.
      event="done"   - this site's FULL action list finished
        successfully (emitted once per site by run_for_sites() itself,
        not per individual action).
      event="error"  - this site's action list failed somewhere;
        message is the error.

    slot: this site's assigned worker slot (see _WorkerSlotRegistry) -
      lets a GUI keep one stable column/row per concurrent worker
      rather than per site.
    phase: a short, fixed machine-readable tag - "connecting",
      "walking", "correlating", "arp", "done", "error", or "skipped" -
      for a GUI to key off for color-coding/abbreviated labels without
      having to parse the free-text `message`.

    Called directly from whichever thread is doing this particular
    site's work - when run_for_sites() runs many sites concurrently,
    that means progress_cb gets called concurrently from several
    different threads at once, with no serialization here. Any
    progress_cb a caller supplies must itself be safe to call that way
    (gui.py's is just a queue.Queue.put, which already is).
    """
    if progress_cb is None:
        return
    try:
        progress_cb(event, site_octet, slot, phase, message)
    except Exception as e:
        print(f"Warning: progress callback failed: {e}")


def _connect(host: str, username: str, password: str, platform_hint: str = None, session_log_dir: str = None,
             secret: str = None):
    """Connect to a device. If platform_hint gives a confident guess
    (see _guess_device_type), connects directly with that device_type -
    skipping the extra SSH login SSHDetect autodetection would cost.
    Only falls back to full autodetection when there's no usable hint
    (e.g. a device discovered but never yet identified any other way).
    Raises on failure either way.

    session_log_dir: when set, writes Netmiko's raw session log (exact
    bytes sent/received) to a timestamped file in that directory - off
    by default everywhere; only turned on explicitly for troubleshooting
    a specific connection (e.g. via orchestrator.py's --session-log
    flag), never on for routine runs.

    secret: optional enable/privileged-mode password. Every existing
    caller (CDP walks, ARP collection) is read-only and has never
    needed this - it's None by default and simply omitted from Netmiko's
    connection kwargs when not given, so nothing about those callers
    changes. Only the command-runner harness passes this, since
    send_config_set() needs privileged mode to push real changes and
    Netmiko elevates automatically using this secret when needed.
    """
    from netmiko import ConnectHandler

    device_type = _guess_device_type(platform_hint)

    if device_type is None:
        from netmiko.ssh_autodetect import SSHDetect

        remote_device = {"device_type": "autodetect", "host": host, "username": username, "password": password}
        guesser = SSHDetect(**remote_device)
        best_match = guesser.autodetect()
        guesser.connection.disconnect()
        device_type = best_match or "cisco_ios"

    connect_kwargs = {"device_type": device_type, "host": host, "username": username, "password": password}
    if secret:
        connect_kwargs["secret"] = secret

    if device_type == "cisco_nxos":
        # Netmiko's fast_cli mode (default True on recent versions) uses
        # tighter timing assumptions that some NX-OS platforms/versions
        # don't echo the prompt back quickly enough to satisfy - this
        # produces a "Pattern not detected ... terminal length 0"
        # timeout even though the device and credentials are completely
        # fine (a real interactive session works normally). This is a
        # well-documented Netmiko+Nexus interaction, not specific to any
        # one device. IOS connections are unaffected and keep the
        # faster default.
        connect_kwargs["fast_cli"] = False
        # global_delay_factor alone (deprecated/inert in this Netmiko
        # version) doesn't fix it - read_timeout_override is the real
        # constructor param that does. 30s was the original fix; some
        # N3Ks/days are slower than that to echo "terminal length 0"
        # back - confirmed via session logs showing the full correct
        # exchange present, just arriving after Netmiko's own timeout
        # had already fired (the log itself doesn't know or care that
        # Netmiko gave up - it just keeps recording whatever comes
        # through). 120s gives enough headroom for that slow-day case
        # without needing to chase the underlying AAA/device timing
        # itself, which is outside anything this code can fix directly.
        connect_kwargs["read_timeout_override"] = 120

    if session_log_dir:
        os.makedirs(session_log_dir, exist_ok=True)
        safe_host = re.sub(r"[^\w.-]", "_", host)
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        connect_kwargs["session_log"] = os.path.join(session_log_dir, f"{safe_host}_{timestamp}.log")

    return ConnectHandler(**connect_kwargs)


def fetch_command_output(host: str, username: str, password: str, command: str, platform_hint: str = None,
                          session_log_dir: str = None) -> str:
    """Connect to a device, run one command, disconnect, return raw
    output. Raises on any connection/auth failure - callers decide how
    to handle it. Used for CDP's one-command-per-device shape; ARP
    collection uses open_session() instead, since it needs several
    commands against the same connection.
    """
    conn = _connect(host, username, password, platform_hint=platform_hint, session_log_dir=session_log_dir)
    try:
        return conn.send_command(command)
    finally:
        conn.disconnect()


def fetch_cdp_output(host: str, username: str, password: str, platform_hint: str = None,
                      session_log_dir: str = None) -> str:
    """Thin wrapper over fetch_command_output for 'show cdp neighbors
    detail' - this is discover_site()'s default connect_fn.
    """
    return fetch_command_output(
        host, username, password, "show cdp neighbors detail",
        platform_hint=platform_hint, session_log_dir=session_log_dir,
    )


class _LiveSession:
    """Wraps a live Netmiko connection so a caller can run several
    commands against the same session before disconnecting - needed
    for ARP collection, where the VRF list has to be discovered first
    before knowing what else to run, all on one connection rather than
    reconnecting per command.
    """

    def __init__(self, netmiko_conn):
        self._conn = netmiko_conn

    def run(self, command: str, read_timeout: float = None) -> str:
        if read_timeout is None:
            return self._conn.send_command(command)
        return self._conn.send_command(command, read_timeout=read_timeout)

    def close(self) -> None:
        self._conn.disconnect()


def open_session(ip_candidates: list, username: str, password: str, platform_hint: str = None,
                  session_log_dir: str = None):
    """Connect to a device, trying ip_candidates in order until one
    works. Returns (session, used_ip). Raises the last exception if
    every candidate fails. This is collect_arp()'s default
    session-opener; tests pass a fake with the same (session, used_ip)
    return shape and a session object exposing .run()/.close().
    """
    last_exc = None
    for ip in ip_candidates:
        try:
            netmiko_conn = _connect(ip, username, password, platform_hint=platform_hint, session_log_dir=session_log_dir)
            return _LiveSession(netmiko_conn), ip
        except Exception as e:
            last_exc = e
    raise last_exc or ConnectionError("No usable IP for this device")


def discover_site(site_row, creds: dict, connect_fn=None, session_log_dir: str = None,
                   collect_mac_tables: bool = False, open_session_fn=None, progress_cb=None, slot=None) -> None:
    """Walk CDP outward from a site's seed device, writing discovered
    devices/links into the DB as source='cdp'.

    progress_cb: optional (event, site_octet, message) callback - see
    _report_progress()'s docstring. Purely additive to the existing
    print()-based console output (which stays exactly as it was); this
    is a structured, per-site channel a GUI can use to show live status
    without having to parse the interleaved console text of several
    concurrently-running sites.

    No `conn` parameter: this may run concurrently with other sites'
    own discover_site() calls, each in its own worker thread (see
    run_for_sites()), so there's no single shared connection/
    transaction to hand around. Every read below opens its own
    short-lived db.get_conn() - safe to do concurrently, since SQLite
    allows any number of simultaneous readers, only writers contend.
    Every write goes through write_queue.queue_and_wait() (or
    queue_batch_and_wait() for a group of writes with no read-after-
    write dependency between them - see the neighbor loop below),
    which durably queues it (safe against other GUIs/scans writing to
    the same network-shared sad.db at the same time) and blocks THIS
    thread until it's actually been applied, handing back the
    underlying db.py call's result (e.g. a device's row id) - the BFS
    walk below needs that result immediately to keep walking
    correctly.

    connect_fn(ip, username, password) -> raw output string, raising on
    failure. Defaults to the real fetch_cdp_output (live Netmiko). Tests
    pass a fake connect_fn to exercise the walk logic without a real
    connection.

    collect_mac_tables (default False - opt-in): when True, also pulls
    'show mac address-table' from every device reached, on the SAME
    connection CDP already opened (via open_session_fn - the same
    session helper collect_arp() uses - rather than a second
    independent SSH connection per device). The raw output is only
    staged (see db.stage_mac_table_raw()), not yet correlated into the
    clients table - deciding which MAC-table entries are real edge/
    client ports versus inter-switch uplinks needs this site's full
    links table to be complete, which it isn't yet mid-walk. When this
    is False (the default), connect_fn's existing one-shot behavior is
    completely unchanged - this option adds a new, separate code path
    rather than altering the existing one, so a plain CDP walk carries
    none of the extra cost or risk of the heavier MAC-table pull.

    IP selection: instead of a hardcoded mgmt_ip/entry_ip pair, this
    pulls each device's full ranked IP history via db.get_ips_for_device()
    at the moment of connecting (not when it's first queued) - so it
    always reflects everything known so far, including whatever an
    inventory sync already established. inventory_sync-sourced IPs
    outrank cdp-sourced ones automatically; this function doesn't need
    to know or care which source contributed which address.

    Cross-site neighbors: a neighbor's IP is checked against
    db.resolve_site_key_for_ip() only as an initial signal that
    something might be off (its octet doesn't match the site being
    scanned). Once that signal fires, the octet itself is NOT trusted
    to say which site it actually is - that's unreliable for anything
    reached over a non-conforming address (e.g. a WAN-facing IP, which
    doesn't follow the normal per-site addressing scheme at all).
    Instead, the neighbor's hostname is checked against every device
    already known anywhere in the database:
      - a unique match elsewhere -> that's authoritative; the device/
        link get filed under its real, existing site
      - no match anywhere, or an ambiguous multi-site match -> filed
        under the reserved "Unassigned" site for manual review, rather
        than guessing
    Either way the walk does NOT traverse into that neighbor - its own
    site's discovery run (once known) is what should walk outward from
    there.
    """
    if connect_fn is None:
        def connect_fn(host, username, password, platform_hint=None):
            return fetch_cdp_output(
                host, username, password, platform_hint=platform_hint, session_log_dir=session_log_dir,
            )
    if collect_mac_tables and open_session_fn is None:
        def open_session_fn(ip_candidates, username, password, platform_hint=None):
            return open_session(
                ip_candidates, username, password, platform_hint=platform_hint, session_log_dir=session_log_dir,
            )
    username, password = _get_tacacs_credentials(creds)
    octet = site_row["site_octet"]

    with db.get_conn() as conn:
        seed = db.get_seed_device_for_site(conn, site_row["id"])
    if seed is None:
        print(f"  Skipping site {site_row['site_octet']} - no seed device flagged.")
        _report_progress(progress_cb, "status", octet, slot, "skipped", "Skipped - no CDP seed device flagged")
        return

    _report_progress(progress_cb, "status", octet, slot, "walking", "Starting CDP walk...")
    visited = {seed["hostname"]}
    queue = [seed["hostname"]]

    devices_touched = 0
    links_written = 0
    cross_site_links = 0

    while queue:
        hostname = queue.pop(0)

        with db.get_conn() as conn:
            current_device = db.get_device_by_hostname(conn, site_row["id"], hostname)
        if current_device is None:
            print(f"  Could not find a device record for {hostname} - skipping.")
            continue
        current_device_id = current_device["id"]

        with db.get_conn() as conn:
            ip_candidates = db.get_ips_for_device(conn, current_device_id)
        if not ip_candidates:
            print(f"  No known IP for {hostname} - skipping.")
            continue

        print(f"  Connecting to {hostname}...", flush=True)
        _report_progress(progress_cb, "status", octet, slot, "connecting", f"Connecting to {hostname}...")

        raw_output = None
        mac_raw_output = None
        last_exc = None

        if collect_mac_tables:
            try:
                session, _used_ip = open_session_fn(
                    ip_candidates, username, password, platform_hint=current_device["platform"],
                )
                try:
                    raw_output = session.run("show cdp neighbors detail")
                    try:
                        mac_raw_output = session.run("show mac address-table")
                    except Exception as mac_exc:
                        # CDP already succeeded - don't treat this as a
                        # total connection failure and lose the walk's
                        # progress over it, but DO make it visible: a
                        # silently empty mac_table_raw with no error
                        # anywhere is much harder to diagnose than one
                        # clear warning line naming the actual cause.
                        print(f"    Warning: could not collect MAC address table from {hostname}: {mac_exc}")
                finally:
                    session.close()
            except Exception as e:
                last_exc = e
        else:
            for ip in ip_candidates:
                try:
                    raw_output = connect_fn(ip, username, password, platform_hint=current_device["platform"])
                    break
                except Exception as e:
                    last_exc = e

        if raw_output is None:
            print(f"    Could not connect to {hostname} (tried {ip_candidates}): {last_exc}")
            _report_progress(progress_cb, "status", octet, slot, "connecting", f"Could not connect to {hostname} - trying next device")
            continue

        devices_touched += 1

        # Reaching the device IS proof it is alive. Without this, only
        # devices that show up as someone else's CDP neighbor ever got
        # their last_seen refreshed - a one-device site aged out even
        # though every run logged into it fine.
        write_queue.queue_and_wait("touch_device_seen", device_id=current_device_id)

        if collect_mac_tables and mac_raw_output is not None:
            write_queue.queue_and_wait(
                "stage_mac_table_raw",
                site_id=site_row["id"], device_id=current_device_id, raw_output=mac_raw_output,
            )

        all_neighbors = cdp_parser.parse_cdp_neighbors(raw_output)
        neighbors = cdp_parser.filter_neighbors(all_neighbors)
        filtered_count = len(all_neighbors) - len(neighbors)
        print(f"    -> found {len(neighbors)} neighbor(s)"
              f"{f' ({filtered_count} filtered)' if filtered_count else ''}", flush=True)

        if collect_mac_tables:
            # Cisco IP phones (CDP hostname "SEP<mac>") are filtered
            # out of `neighbors` above since they have no further CDP
            # neighbors of their own worth walking into - but a phone's
            # own CDP entry already tells us exactly where it lives
            # (this device, this exact port), with no need to wait for
            # the deferred mac_table_raw correlation pass the way a
            # generic MAC-table entry does.
            # Batched (like every other bulk write in this function) -
            # a phone-facing wiring-closet switch can easily report a
            # few hundred SEP-registered neighbors alongside its normal
            # handful of real switch/AP neighbors, and each one used to
            # be its own individual queue_and_wait() round trip. No
            # read-after-write dependency between these (or with
            # anything else in this iteration), so they collect in
            # memory and go out as one batch alongside this device's
            # staged MAC table.
            sep_ops = []
            for n in all_neighbors:
                sep_mac = _extract_sep_mac(n.get("hostname"))
                if sep_mac:
                    sep_ops.append({
                        "action": "upsert_client",
                        "kwargs": {
                            "site_id": site_row["id"], "mac": sep_mac,
                            "device_id": current_device_id, "interface": n.get("local_intf"),
                            "device_type": _classify_sep_device_type(n.get("platform")), "source": "cdp",
                        },
                    })
            if sep_ops:
                write_queue.queue_batch_and_wait(sep_ops)

        for n in neighbors:
            neighbor_site_id = site_row["id"]
            is_cross_site = False
            attribution_note = None

            # Hostname is checked for EVERY neighbor, unconditionally -
            # not gated behind an octet comparison. A WAN-facing IP's
            # octet is arbitrary; it can coincidentally match the
            # scanning site's real octet just as easily as it can
            # mismatch it, and a coincidental match would otherwise
            # skip this check entirely and silently misattribute a
            # genuinely unrelated device. Octet is only consulted
            # afterward, as a tiebreaker for the one case hostname
            # can't resolve on its own: a device that matches nowhere
            # at all (see below).
            with db.get_conn() as conn:
                matches = db.find_devices_by_hostname_anywhere(conn, n["hostname"])
            matches_here = [m for m in matches if m["site_id"] == site_row["id"]]
            matches_elsewhere = [m for m in matches if m["site_id"] != site_row["id"]]

            if matches_here:
                pass  # already known at this exact site - straightforward
            elif len(matches_elsewhere) == 1:
                is_cross_site = True
                neighbor_site_id = matches_elsewhere[0]["site_id"]
                attribution_note = (
                    f"  Note: {n['hostname']} matched an existing device at site "
                    f"{matches_elsewhere[0]['owning_site_octet']} - filed there instead of {site_row['site_octet']}."
                )
            elif len(matches_elsewhere) > 1:
                is_cross_site = True
                neighbor_site_id = write_queue.queue_and_wait("get_or_create_unassigned_site")
                attribution_note = (
                    f"  Note: {n['hostname']}'s hostname matched more than one existing site - "
                    f"ambiguous, filed under Unassigned for review."
                )
            else:
                # No hostname match anywhere - genuinely new. Fall back
                # to the octet as the only remaining signal: if either
                # known IP's octet matches this site, assume it's a
                # plausible new local device; otherwise, don't guess.
                octet_matches_here = False
                for candidate_ip in (n["mgmt_ip"], n.get("entry_ip")):
                    if not candidate_ip:
                        continue
                    try:
                        with db.get_conn() as conn:
                            resolved_octet = db.resolve_site_key_for_ip(conn, candidate_ip)
                    except ValueError:
                        continue
                    if resolved_octet == site_row["site_octet"]:
                        octet_matches_here = True
                        break

                if not octet_matches_here:
                    is_cross_site = True
                    neighbor_site_id = write_queue.queue_and_wait("get_or_create_unassigned_site")
                    attribution_note = (
                        f"  Note: {n['hostname']} isn't recognized anywhere and its address doesn't "
                        f"match this site - filed under Unassigned for review."
                    )

            # No mgmt_ip passed here - platform is the only fresh field
            # CDP gives us about a neighbor's own identity. IPs go
            # through record_device_ip() below instead, which ranks
            # them rather than blindly overwriting. serial_number comes
            # for free on platforms that advertise it in their Device
            # ID (e.g. "hostname(SERIAL)") - see cdp_parser.py.
            neighbor_device_id = write_queue.queue_and_wait(
                "upsert_device",
                site_id=neighbor_site_id,
                hostname=n["hostname"],
                platform=n["platform"],
                serial_number=n.get("serial_number"),
                source="cdp",
                raw_source_data=n["raw_block"],
            )

            # upsert_device (above) still runs on its own, synchronous
            # queue_and_wait() call, since neighbor_device_id is a real
            # kwarg every op below needs. But those remaining writes -
            # up to two record_device_ip calls plus the link itself -
            # don't depend on each other or on anything written after
            # them, so they go in one batch: one round trip for this
            # neighbor's writes instead of up to three.
            neighbor_ops = []
            if n["mgmt_ip"]:
                neighbor_ops.append({
                    "action": "record_device_ip",
                    "kwargs": {
                        "device_id": neighbor_device_id, "ip": n["mgmt_ip"],
                        "source": "cdp", "raw_source_data": n["raw_block"],
                    },
                })
            if n.get("entry_ip") and n["entry_ip"] != n["mgmt_ip"]:
                neighbor_ops.append({
                    "action": "record_device_ip",
                    "kwargs": {
                        "device_id": neighbor_device_id, "ip": n["entry_ip"],
                        "source": "cdp", "raw_source_data": n["raw_block"],
                    },
                })
            # The link is attributed to the scanning site (the
            # discovering side) even when the neighbor itself belongs
            # elsewhere - it's real topology data either way.
            neighbor_ops.append({
                "action": "upsert_link",
                "kwargs": {
                    "site_id": site_row["id"],
                    "device_a_id": current_device_id,
                    "device_b_id": neighbor_device_id,
                    "local_intf": n["local_intf"],
                    "remote_intf": n["remote_intf"],
                    "source": "cdp",
                    "raw_source_data": n["raw_block"],
                },
            })
            write_queue.queue_batch_and_wait(neighbor_ops)
            links_written += 1

            if is_cross_site:
                cross_site_links += 1
                print(attribution_note)
                continue  # never enqueue - let that site's own scan discover it

            if n["hostname"] not in visited:
                visited.add(n["hostname"])
                queue.append(n["hostname"])

        _report_progress(
            progress_cb, "status", octet, slot, "walking",
            f"{hostname}: {len(neighbors)} neighbor(s) - {devices_touched} device(s) reached, "
            f"{links_written} link(s) so far, {len(queue)} queued",
        )

    write_queue.queue_and_wait("mark_site_run", site_id=site_row["id"])
    if collect_mac_tables:
        write_queue.queue_and_wait("mark_site_mac_table_run", site_id=site_row["id"])
    print(f"  Site {site_row['site_octet']}: reached {devices_touched} device(s), wrote {links_written} link(s)"
          f"{f' ({cross_site_links} cross-site)' if cross_site_links else ''}.")
    _report_progress(
        progress_cb, "status", octet, slot, "walking",
        f"CDP walk complete: {devices_touched} device(s), {links_written} link(s)"
        f"{f' ({cross_site_links} cross-site)' if cross_site_links else ''}",
    )


def correlate_mac_tables(site_row, progress_cb=None, slot=None) -> None:
    """Reads every device's staged raw MAC-table output (see
    discover_site()'s collect_mac_tables option) plus the site's now-
    complete links table, and decides which MAC-table entries are
    genuine edge/client ports versus inter-switch uplinks - a port
    that's also a known link is just a connection to another switch,
    not a real client. Only genuine edge entries get written into the
    clients table; uplink entries are simply skipped (nothing wrong
    with them, they're just not client data).

    Run this ONCE, after a site's full CDP walk (with
    collect_mac_tables=True) has finished - not mid-walk. This needs
    the site's links table to be COMPLETE to correctly recognize every
    uplink; running it against a partial walk could misclassify a
    real uplink as an edge port simply because that particular link
    hadn't been discovered yet at the point of checking.

    Interface names are compared via _normalize_interface() rather
    than as raw strings, since CDP and "show mac address-table"
    frequently report the same physical port in different forms
    (GigabitEthernet1/0/1 vs Gi1/0/1) - a plain string comparison
    would otherwise silently fail to recognize a genuine uplink,
    misfiling it as a client.

    device_type is deliberately left unset here (not overwritten with
    None either, via upsert_client()'s own COALESCE behavior) - a
    phone tagged inline during the walk (see discover_site()'s SEP
    handling) keeps its "cisco_phone" tag even if this same MAC also
    shows up in the plain MAC-table data processed here.
    """
    site_id = site_row["id"]
    octet = site_row["site_octet"]
    _report_progress(progress_cb, "status", octet, slot, "correlating", "Correlating MAC tables...")

    with db.get_conn() as conn:
        links = db.get_links_for_site(conn, site_id)
        staged_tables = db.get_staged_mac_tables_for_site(conn, site_id)

    known_link_ports = set()
    for link in links:
        known_link_ports.add((link["device_a_id"], _normalize_interface(link["local_intf"])))
        known_link_ports.add((link["device_b_id"], _normalize_interface(link["remote_intf"])))

    # No read-after-write dependency anywhere in this loop (unlike
    # CDP's BFS walk) - every entry's client_ops record is fully
    # self-contained, so the whole site's correlation pass collects in
    # memory and goes out as ONE batch at the end, rather than one
    # round trip per client. A site with a large MAC table can easily
    # produce hundreds of edge-port entries.
    edge_count = 0
    uplink_count = 0
    client_ops = []
    for staged in staged_tables:
        device_id = staged["device_id"]
        for entry in mac_parser.parse_mac_table(staged["raw_output"]):
            key = (device_id, _normalize_interface(entry["interface"]))
            if key in known_link_ports:
                uplink_count += 1
                continue
            client_ops.append({
                "action": "upsert_client",
                "kwargs": {
                    "site_id": site_id, "mac": entry["mac"],
                    "device_id": device_id, "interface": entry["interface"], "vlan": entry["vlan"],
                    "source": "mac-table", "raw_source_data": entry["raw_line"],
                },
            })
            edge_count += 1

    if client_ops:
        write_queue.queue_batch_and_wait(client_ops)

    print(f"  Site {site_row['site_octet']}: correlated {edge_count} client(s), "
          f"skipped {uplink_count} known-uplink entrie(s).")
    _report_progress(
        progress_cb, "status", octet, slot, "correlating",
        f"MAC correlation complete: {edge_count} client(s), {uplink_count} uplink(s) skipped",
    )


def collect_arp(site_row, creds: dict, open_session_fn=None, session_log_dir: str = None, progress_cb=None,
                 slot=None) -> None:
    """Connect to a site's ARP seed device, discover any VRFs
    (show vrf), and pull the global ARP table plus one per-VRF table,
    writing everything into arp_entries. Both IOS and NX-OS are
    supported - arp_parser.py/vrf_parser.py detect the format
    per-line, so this function doesn't need to know or care which
    platform it's talking to.

    open_session_fn(ip_candidates, username, password, platform_hint)
    -> (session, used_ip), where session exposes .run(command) and
    .close(). Defaults to the real open_session() (live Netmiko).
    Tests pass a fake with canned command->output responses.

    If arp_seed.arp_override_ip is set (e.g. a shared HSRP/VRRP VIP
    fronting a pair of devices, where the VIP's own ARP table is more
    complete/authoritative than either individual device's), it's
    tried FIRST - before the device's own normal ranked IPs, which
    remain as the fallback if the override is unreachable.
    """
    if open_session_fn is None:
        def open_session_fn(ip_candidates, username, password, platform_hint=None):
            return open_session(
                ip_candidates, username, password, platform_hint=platform_hint, session_log_dir=session_log_dir,
            )
    username, password = _get_tacacs_credentials(creds)
    octet = site_row["site_octet"]

    with db.get_conn() as conn:
        arp_seed = db.get_arp_seed_device_for_site(conn, site_row["id"])
    if arp_seed is None:
        print(f"  Skipping site {site_row['site_octet']} - no ARP seed (or CDP seed) available.")
        _report_progress(progress_cb, "status", octet, slot, "skipped", "Skipped - no ARP seed device available")
        return

    ip_candidates = []
    if arp_seed["arp_override_ip"]:
        ip_candidates.append(arp_seed["arp_override_ip"])
    with db.get_conn() as conn:
        ip_candidates.extend(db.get_ips_for_device(conn, arp_seed["id"]))

    if not ip_candidates:
        print(f"  No known IP for ARP seed {arp_seed['hostname']} - skipping.")
        _report_progress(
            progress_cb, "status", octet, slot, "skipped",
            f"Skipped - no known IP for ARP seed {arp_seed['hostname']}",
        )
        return

    print(f"  Connecting to ARP seed {arp_seed['hostname']}...", flush=True)
    _report_progress(progress_cb, "status", octet, slot, "arp", f"Connecting to ARP seed {arp_seed['hostname']}...")
    try:
        session, used_ip = open_session_fn(ip_candidates, username, password, arp_seed["platform"])
    except Exception as e:
        print(f"    Could not connect to {arp_seed['hostname']} (tried {ip_candidates}): {e}")
        _report_progress(
            progress_cb, "status", octet, slot, "arp", f"Could not connect to ARP seed {arp_seed['hostname']}: {e}",
        )
        return

    # Collected in memory (no read-after-write dependency between
    # entries, or between the global and per-VRF tables) and written
    # out as ONE batch after the device session closes, rather than
    # one round trip per entry - the biggest win of this whole
    # redesign, since a single site can produce 1000+ combined
    # global+VRF entries.
    total_entries = 0
    arp_ops = []
    try:
        vrf_raw = session.run("show vrf")
        vrf_names = vrf_parser.parse_vrf_names(vrf_raw)
        if vrf_names:
            print(f"    Found {len(vrf_names)} VRF(s): {vrf_names}", flush=True)
        else:
            print("    No VRFs configured.", flush=True)

        global_raw = session.run("show ip arp")
        global_entries = arp_parser.parse_arp_table(global_raw)
        for e in global_entries:
            arp_ops.append({
                "action": "upsert_arp_entry",
                "kwargs": {
                    "site_id": site_row["id"], "ip": e["ip"], "mac": e["mac"], "vrf": "",
                    "device_id": arp_seed["id"], "source": "arp", "raw_source_data": e["raw_line"],
                },
            })
        total_entries += len(global_entries)
        print(f"    Global table: {len(global_entries)} entry(ies)", flush=True)
        _report_progress(progress_cb, "status", octet, slot, "arp", f"Global ARP table: {len(global_entries)} entry(ies)")

        for vrf_name in vrf_names:
            vrf_arp_raw = session.run(f"show ip arp vrf {vrf_name}")
            vrf_entries = arp_parser.parse_arp_table(vrf_arp_raw)
            for e in vrf_entries:
                arp_ops.append({
                    "action": "upsert_arp_entry",
                    "kwargs": {
                        "site_id": site_row["id"], "ip": e["ip"], "mac": e["mac"], "vrf": vrf_name,
                        "device_id": arp_seed["id"], "source": "arp", "raw_source_data": e["raw_line"],
                    },
                })
            total_entries += len(vrf_entries)
            print(f"    VRF '{vrf_name}': {len(vrf_entries)} entry(ies)", flush=True)
            _report_progress(progress_cb, "status", octet, slot, "arp", f"VRF '{vrf_name}': {len(vrf_entries)} entry(ies)")
    finally:
        session.close()

    # mark_site_arp_run rides along as the last op in the SAME batch,
    # so a site with genuinely zero ARP entries (empty arp_ops) still
    # gets marked without a wasted extra round trip, and a site with
    # 1000+ entries gets exactly one.
    arp_ops.append({"action": "mark_site_arp_run", "kwargs": {"site_id": site_row["id"]}})
    write_queue.queue_batch_and_wait(arp_ops)
    print(f"  Site {site_row['site_octet']}: recorded {total_entries} ARP entry(ies) total (via {used_ip}).")
    _report_progress(progress_cb, "status", octet, slot, "arp", f"ARP collection complete: {total_entries} entry(ies) total")


def collect_tunnels(site_row, creds: dict, open_session_fn=None, session_log_dir: str = None, progress_cb=None,
                     slot=None) -> None:
    """Connect to a site's CDP seed device ONLY (not every device the
    CDP walk reaches - tunnels terminate on a site's edge/WAN router,
    not on every switch in the site), enumerate its tunnel interfaces
    via 'show interfaces description', pull 'show interfaces <name>'
    for each one, and write the parsed result into tunnel_interfaces.
    Finishes by re-running match_tunnels() - see that function's own
    docstring for why the correlation pass is global rather than
    scoped to this one site's data alone.

    Deliberately its own independent connection/action, structured
    just like collect_arp() (not piggybacked onto discover_site()'s
    CDP walk the way collect_mac_tables is) - it only ever needs ONE
    device's session, so there's no BFS walk here for it to ride along
    with. This also means, like collect_arp(), it doesn't require
    'cdp' to be part of THIS run's actions - only that a CDP seed is
    already flagged for this site from some earlier run.

    open_session_fn(ip_candidates, username, password, platform_hint)
    -> (session, used_ip), same contract as collect_arp() - defaults
    to the real open_session() (live Netmiko); tests pass a fake.

    A device whose 'show interfaces description' has no "Tu..." rows
    at all (no tunnels configured) is a normal, silent no-op here, not
    an error or a warning - most sites won't have any.
    """
    if open_session_fn is None:
        def open_session_fn(ip_candidates, username, password, platform_hint=None):
            return open_session(
                ip_candidates, username, password, platform_hint=platform_hint, session_log_dir=session_log_dir,
            )
    username, password = _get_tacacs_credentials(creds)
    octet = site_row["site_octet"]

    with db.get_conn() as conn:
        seed = db.get_seed_device_for_site(conn, site_row["id"])
    if seed is None:
        print(f"  Skipping site {site_row['site_octet']} - no CDP seed device flagged.")
        _report_progress(progress_cb, "status", octet, slot, "skipped", "Skipped - no CDP seed device flagged")
        return

    with db.get_conn() as conn:
        ip_candidates = db.get_ips_for_device(conn, seed["id"])
    if not ip_candidates:
        print(f"  No known IP for seed {seed['hostname']} - skipping tunnel collection.")
        _report_progress(
            progress_cb, "status", octet, slot, "skipped",
            f"Skipped - no known IP for seed {seed['hostname']}",
        )
        return

    print(f"  Connecting to {seed['hostname']} for tunnel collection...", flush=True)
    _report_progress(progress_cb, "status", octet, slot, "tunnels", f"Connecting to {seed['hostname']}...")
    try:
        session, used_ip = open_session_fn(ip_candidates, username, password, seed["platform"])
    except Exception as e:
        print(f"    Could not connect to {seed['hostname']} (tried {ip_candidates}): {e}")
        _report_progress(
            progress_cb, "status", octet, slot, "tunnels", f"Could not connect to {seed['hostname']}: {e}",
        )
        return

    # Same reasoning as collect_arp()/discover_site()'s batching: no
    # read-after-write dependency between any of these, so they
    # collect in memory and go out as one batch after the session
    # closes rather than one round trip per tunnel interface.
    tunnel_ops = []
    tunnel_names = []
    try:
        desc_raw = session.run("show interfaces description")
        tunnel_names = tunnel_parser.parse_tunnel_interface_names(desc_raw)
        if tunnel_names:
            print(f"    Found {len(tunnel_names)} tunnel interface(s): {tunnel_names}", flush=True)
        else:
            print("    No tunnel interfaces found.", flush=True)
        _report_progress(
            progress_cb, "status", octet, slot, "tunnels",
            f"Found {len(tunnel_names)} tunnel interface(s)" if tunnel_names else "No tunnel interfaces found",
        )

        for name in tunnel_names:
            detail_raw = session.run(f"show interfaces {name}")
            for entry in tunnel_parser.parse_tunnel_interfaces(detail_raw):
                tunnel_ops.append({
                    "action": "upsert_tunnel_interface",
                    "kwargs": {
                        "site_id": site_row["id"], "device_id": seed["id"], "interface": entry["interface"],
                        "admin_status": entry["admin_status"], "line_protocol": entry["line_protocol"],
                        "description": entry["description"], "internet_address": entry["internet_address"],
                        "source_ip": entry["source_ip"], "source_interface": entry["source_interface"],
                        "destination_ip": entry["destination_ip"], "destination_interface": entry["destination_interface"],
                        "raw_source_data": entry["raw_line"],
                    },
                })
    finally:
        session.close()

    tunnel_ops.append({"action": "mark_site_tunnel_run", "kwargs": {"site_id": site_row["id"]}})
    write_queue.queue_batch_and_wait(tunnel_ops)

    # Global, not site-scoped - see match_tunnels()'s own docstring.
    # Re-run after every site's tunnel collection rather than only
    # once at the very end of a multi-site run: cheap (a full fleet's
    # worth of tunnel rows is nowhere near arp_entries-scale), always
    # idempotent, and means a run against just one site still leaves
    # every OTHER site's already-collected tunnels correctly
    # re-matched against this site's fresh data too.
    result = write_queue.queue_and_wait("match_tunnels")
    print(f"  Site {site_row['site_octet']}: recorded {len(tunnel_names)} tunnel interface(s) via {used_ip}; "
          f"global match: {result['matched']} matched, {result['one_sided']} one-sided, {result['ambiguous']} ambiguous.")
    _report_progress(
        progress_cb, "status", octet, slot, "tunnels",
        f"Tunnel collection complete: {len(tunnel_names)} interface(s); "
        f"{result['matched']} matched / {result['one_sided']} one-sided / {result['ambiguous']} ambiguous fleet-wide",
    )


def collect_configs(site_row, creds: dict, open_session_fn=None, session_log_dir: str = None, progress_cb=None,
                    slot=None, include_stale: bool = False, only_device_ids=None) -> None:
    """Pull `show running-config` from every live device already in the
    DB for this site - no CDP walk, no seed device needed. Devices are
    done one after another within the site (sites themselves run in
    parallel via run_for_sites()). Each device gets its own session,
    trying its ranked IPs in order.

    Output is cleaned by config_parser.clean_config() (volatile header
    lines stripped, last-change time/user parsed out); a pull that is
    empty, rejected or cut off is recorded as a failure and NEVER
    stored. A config identical to the newest stored snapshot only
    refreshes the device's pull status, so the (large) text is queued
    for writing only when it actually changed.

    Aged-stale and manually-stale devices are skipped unless
    include_stale. only_device_ids (optional set) limits the pull to
    those devices - for a future single-device "pull now" button.
    """
    if open_session_fn is None:
        def open_session_fn(ip_candidates, username, password, platform_hint=None):
            return open_session(
                ip_candidates, username, password, platform_hint=platform_hint, session_log_dir=session_log_dir,
            )
    username, password = _get_tacacs_credentials(creds)
    octet = site_row["site_octet"]

    skipped = []
    with db.get_conn() as conn:
        targets = db.get_config_targets(conn, site_row["id"], include_stale=include_stale, skipped=skipped)
    if only_device_ids is not None:
        targets = [t for t in targets if t["id"] in only_device_ids]
    if skipped:
        print(f"  Site {octet}: skipped {len(skipped)} stale device(s): "
              + "; ".join(f"{h} ({r})" for h, r in skipped)
              + ". Tick 'Include stale devices' (GUI) or use --include-stale to pull them anyway.")
        _report_progress(progress_cb, "status", octet, slot, "configs", f"Skipping {len(skipped)} stale device(s)")
    if not targets:
        print(f"  Site {octet}: no devices to pull configs from.")
        _report_progress(progress_cb, "status", octet, slot, "skipped", "Skipped - no devices to pull configs from")
        return

    stored = unchanged = failed = 0
    for n, t in enumerate(targets, 1):
        host = t["hostname"]
        _report_progress(progress_cb, "status", octet, slot, "configs", f"Config {n}/{len(targets)}: {host}")
        try:
            if not t["ips"]:
                raise ConnectionError("no known IP for this device")
            session, used_ip = open_session_fn(t["ips"], username, password, t["platform"])
            try:
                raw = session.run("show running-config", read_timeout=CONFIG_READ_TIMEOUT)
            finally:
                session.close()
            cleaned = config_parser.clean_config(raw)
            if cleaned["problem"]:
                raise ValueError(cleaned["problem"])
            meta = {"changed_at": cleaned["changed_at"], "changed_by": cleaned["changed_by"],
                    "nvram_updated": cleaned["nvram_updated"]}
            if db.hash_config_text(cleaned["text"]) == t["latest_hash"]:
                write_queue.queue_and_wait("record_config_pull_result", device_id=t["id"], ok=True, **meta)
                unchanged += 1
            else:
                write_queue.queue_and_wait(
                    "record_config_snapshot", device_id=t["id"], config_text=cleaned["text"], **meta,
                )
                stored += 1
                print(f"    {host}: config changed - snapshot stored (via {used_ip})", flush=True)
        except Exception as e:
            failed += 1
            print(f"    {host}: config pull failed: {e}", flush=True)
            try:
                write_queue.queue_and_wait("record_config_pull_result", device_id=t["id"], ok=False, error=str(e))
            except Exception as e2:
                print(f"    {host}: could not record the failure: {e2}", flush=True)

    print(f"  Site {octet}: configs - {stored} new snapshot(s), {unchanged} unchanged, {failed} failed "
          f"of {len(targets)} device(s)" + (f" ({len(skipped)} stale skipped)." if skipped else "."))
    _report_progress(
        progress_cb, "status", octet, slot, "configs",
        f"Configs complete: {stored} changed / {unchanged} unchanged / {failed} failed"
        + (f" / {len(skipped)} stale skipped" if skipped else ""),
    )


def _run_site_actions(site, actions: list, creds: dict, session_log_dir: str = None,
                       collect_mac_tables: bool = False, collect_tunnels_flag: bool = False,
                       progress_cb=None, worker_slots=None, config_include_stale: bool = False) -> None:
    """One site's worth of work, pulled out into its own function so it
    can be handed to a thread-pool worker as-is. A site's own actions
    always run in the same strict order (CDP walk, then MAC
    correlation, then ARP, then tunnels) - only which SITES run
    concurrently with each other is parallelized, not the order of
    work within one site.

    This is the function that actually executes ON a pool worker
    thread, so it's the right (and only) place to ask "which worker
    slot am I" - worker_slots.assign_site() does that lazily, the first
    time this particular thread runs, and the resulting slot number is
    threaded through to every progress_cb call this site's work makes
    from here on, so a GUI can key its display off a stable per-worker
    identity rather than per-site.

    collect_tunnels_flag runs independently of which of 'cdp'/'arp' is
    in `actions` - like collect_arp() itself, collect_tunnels() only
    needs a CDP seed already flagged for this site from some earlier
    run, not a CDP walk happening THIS run. It runs last, after
    whatever else this call is doing, since ordering against the
    others doesn't matter (it neither depends on nor is depended on by
    the CDP/MAC/ARP data).
    """
    octet = site["site_octet"]
    slot = worker_slots.assign_site(octet) if worker_slots is not None else None
    print(f"\n=== Site {octet} ({site['site_name'] or 'unnamed'}) [worker {slot}] ===")
    if "cdp" in actions:
        print("--- CDP discovery ---")
        discover_site(site, creds, session_log_dir=session_log_dir, collect_mac_tables=collect_mac_tables,
                      progress_cb=progress_cb, slot=slot)
        if collect_mac_tables:
            print("--- MAC address table correlation ---")
            correlate_mac_tables(site, progress_cb=progress_cb, slot=slot)
    if "arp" in actions:
        print("--- ARP collection ---")
        collect_arp(site, creds, session_log_dir=session_log_dir, progress_cb=progress_cb, slot=slot)
    if collect_tunnels_flag:
        print("--- Tunnel collection ---")
        collect_tunnels(site, creds, session_log_dir=session_log_dir, progress_cb=progress_cb, slot=slot)
    if "configs" in actions:
        print("--- Config collection ---")
        collect_configs(site, creds, session_log_dir=session_log_dir, progress_cb=progress_cb, slot=slot,
                        include_stale=config_include_stale)


def run_for_sites(sites: list, actions: list, creds: dict, session_log_dir: str = None,
                   collect_mac_tables: bool = False, collect_tunnels_flag: bool = False,
                   max_workers: int = DISCOVERY_MAX_WORKERS, progress_cb=None,
                   config_include_stale: bool = False) -> None:
    """Run the given actions (any of 'cdp'/'arp'/'configs') against each site,
    up to max_workers sites at a time. Shared by both the CLI and
    interactive-menu entry points so there's exactly one place that
    drives "for each site, do each action".

    No `conn` parameter: sites run concurrently, each in its own worker
    thread, so there's no single shared connection to hand around -
    every read/write below (in discover_site()/collect_arp()/
    correlate_mac_tables()) manages its own, short-lived or queued. The
    only resource shared across worker threads is the write queue
    itself, which is explicitly designed for many concurrent writers
    (see write_queue.py's module docstring) - no scan ever holds a
    connection open long enough to lock another GUI or scan out.

    A per-site failure (a device unreachable, a parsing error, etc.)
    is caught here and printed rather than aborting the whole run, the
    same way discover_site()/collect_arp() already catch their own
    per-device connection failures internally and move on - one bad
    site shouldn't cost every other site its results.

    collect_mac_tables (default False - opt-in): only meaningful
    alongside 'cdp' - see discover_site()'s own docstring for what
    this actually does during the walk. correlate_mac_tables() runs
    right after that SAME site's own CDP walk finishes (not interleaved
    with any other site's walk), since it needs that site's links table
    to be complete first - safe under concurrency because each site's
    links only ever come from that site's own walk.

    collect_tunnels_flag (default False - opt-in): independent of
    which of 'cdp'/'arp' is in `actions` - see collect_tunnels()'s own
    docstring for why. Runs last for each site, via _run_site_actions().

    progress_cb: optional (event, site_octet, slot, phase, message)
    callback - see _report_progress()'s docstring for the full contract.
    Passed straight through to every site's discover_site()/
    collect_arp()/correlate_mac_tables()/collect_tunnels() calls for
    "status" updates, PLUS this function emits its own "done"/"error"
    event once each site's _run_site_actions() call finishes - one
    event per site, marking that site as complete (successfully or
    not) regardless of which action(s) it ran. Safe to call
    concurrently from every site's worker thread at once.
    """
    action_label = "+".join(actions)
    mac_note = " (+MAC tables)" if collect_mac_tables and "cdp" in actions else ""
    tunnel_note = " (+tunnels)" if collect_tunnels_flag else ""
    site_list = (
        ", ".join(s["site_octet"] for s in sites) if len(sites) <= 10 else f"{len(sites)} sites"
    )
    # Independent, immediately-committed write - logged BEFORE the
    # actual (multi-step, error-prone, now-concurrent) discovery work
    # below, not after it succeeds, so the record that this run was
    # genuinely attempted survives even if every single site's work
    # later fails. db.log_activity() opens its own short-lived
    # connection when conn=None (its default) - nothing here needs to
    # be queued, since this is a single, one-shot write with no BFS
    # read-after-write dependency on it.
    db.log_activity("discovery_run", f"{action_label}{mac_note}{tunnel_note} against site(s): {site_list}")

    if not sites:
        return

    # Fresh per-run registry (see _WorkerSlotRegistry's docstring) -
    # every run_for_sites() call gets its own, so worker slot numbers
    # always restart at 1 rather than accumulating across however many
    # discovery runs happen in one long-lived GUI session.
    worker_slots = _WorkerSlotRegistry()

    with ThreadPoolExecutor(max_workers=min(max_workers, len(sites))) as pool:
        futures = {
            pool.submit(
                _run_site_actions, site, actions, creds,
                session_log_dir=session_log_dir, collect_mac_tables=collect_mac_tables,
                collect_tunnels_flag=collect_tunnels_flag,
                progress_cb=progress_cb, worker_slots=worker_slots,
                config_include_stale=config_include_stale,
            ): site
            for site in sites
        }
        for future in as_completed(futures):
            site = futures[future]
            octet = site["site_octet"]
            # Back on the main thread here (as_completed() blocks the
            # caller, not the worker) - the slot that actually worked
            # this site was recorded by _run_site_actions() when it
            # started, so it's looked up rather than reasoned about
            # from whatever thread happens to be running this loop.
            slot = worker_slots.slot_for_site(octet)
            try:
                future.result()
            except Exception as e:
                print(f"\n  ERROR: site {octet} failed: {e}")
                _report_progress(progress_cb, "error", octet, slot, "error", str(e))
            else:
                _report_progress(progress_cb, "done", octet, slot, "done", "")


def _load_creds_or_exit() -> dict:
    creds = credential_loader.prompt_and_load()
    try:
        _get_tacacs_credentials(creds)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    return creds


# ---------------------------------------------------------------------
# Command runner - plugin discovery and execution. SAD's first write-
# capable feature - everything above this point only ever reads from
# devices. See utilities/plugins/ip_helper_replace.py for the plugin
# authoring contract this section expects.
# ---------------------------------------------------------------------
PLUGINS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "utilities", "plugins")
LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

# Command-runner concurrency defaults (the GUI reads settings.json
# "command_runner" and passes its values in; these are the fallbacks).
PLUGIN_MAX_WORKERS = 24
PLUGIN_PER_SITE_LIMIT = 5


def list_plugins() -> dict:
    """Scans utilities/plugins/ for command-runner plugins and returns
    {plugin_id: module} for every valid one found. A valid plugin
    exposes NAME, DESCRIPTION, PARAMS, and EXACTLY ONE of:

      - plan(conn, device_row, params) - a per-device plugin. The
        harness resolves SAD's own device list from the chosen scope,
        connects to each one, and calls plan() once per device. See
        ip_helper_replace.py.

      - run(log, params, credentials, commit) - a standalone plugin.
        Used when the task's device list isn't SAD-tracked data at all
        (e.g. a fixed set of appliances SAD never discovers) or has
        its own connection topology a per-device loop can't express
        (e.g. an HA pair where you must check both nodes before
        knowing which one to act on). The plugin owns its ENTIRE
        execution flow, including honoring commit=False itself - see
        bind_smtp_dataset.py and the plugins README for the safety
        implications of that.

    A file missing NAME/DESCRIPTION/PARAMS, missing both plan and run,
    or defining BOTH, is silently skipped (treated as not a valid
    plugin) rather than crashing discovery over one malformed or
    unrelated file in that folder.
    """
    plugins = {}
    if not os.path.isdir(PLUGINS_DIR):
        return plugins
    if PLUGINS_DIR not in sys.path:
        sys.path.insert(0, PLUGINS_DIR)
    importlib.invalidate_caches()  # so plugin files added since the last scan are found
    for fname in sorted(os.listdir(PLUGINS_DIR)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        mod_name = fname[:-3]
        try:
            # Re-read from disk on every scan: import_module() alone
            # returns the cached module, so edits to a plugin would
            # otherwise never show up until the app was relaunched.
            if mod_name in sys.modules:
                module = importlib.reload(sys.modules[mod_name])
            else:
                module = importlib.import_module(mod_name)
            has_core = all(hasattr(module, attr) for attr in ("NAME", "DESCRIPTION", "PARAMS"))
            has_plan = hasattr(module, "plan")
            has_run = hasattr(module, "run")
            if has_core and (has_plan != has_run):  # exactly one of the two shapes, never both/neither
                plugins[mod_name] = module
        except Exception as e:
            print(f"Warning: could not load plugin '{fname}': {e}")
    return plugins


def is_standalone_plugin(module) -> bool:
    return hasattr(module, "run")


def _site_groups_in_scope(conn, site_ids) -> list:
    """[(site_row, [device rows])] for the chosen scope, in site order.

    site_ids may be None (every site), a single site id, or a list/tuple/
    set of site ids (the GUI's "Selected sites"). Duplicates are dropped
    and unknown ids are ignored rather than raising, so a site deleted
    between a preview and a commit simply falls out of scope.
    """
    if site_ids is None:
        sites = db.get_all_sites(conn)
    else:
        if isinstance(site_ids, (list, tuple, set, frozenset)):
            wanted = list(dict.fromkeys(site_ids))
        else:
            wanted = [site_ids]
        sites = []
        for sid in wanted:
            site = db.get_site_by_id(conn, sid)
            if site:
                sites.append(site)
    return [(site, list(db.get_devices_for_site(conn, site["id"]))) for site in sites]


def _devices_in_scope(conn, site_ids):
    """Every device to run a plugin against, flattened. Reuses SAD's own
    device records directly (hostname, platform, ranked IPs) rather than
    needing a separately-maintained device list the way the original
    standalone script's CSV input did.
    """
    devices = []
    for _site, site_devices in _site_groups_in_scope(conn, site_ids):
        devices.extend(site_devices)
    return devices


def _save_device_config(conn, device_type) -> None:
    if device_type and device_type.startswith("cisco_nxos"):
        conn.save_config(cmd="copy running-config startup-config")
    else:
        conn.save_config()


def _interleave_by_site(jobs_by_site: list) -> list:
    """Round-robin across sites: device 1 of every site, then device 2 of
    every site, and so on. Jobs submitted site-by-site would let workers
    pile onto a site that is already at its per-site limit and sit
    blocked on its semaphore, wasting pool slots; interleaving makes that
    almost never happen.
    """
    ordered = []
    depth = max((len(j) for j in jobs_by_site), default=0)
    for i in range(depth):
        for site_jobs in jobs_by_site:
            if i < len(site_jobs):
                ordered.append(site_jobs[i])
    return ordered


def run_plugin(conn, plugin_module, params: dict, site_id, username: str, password: str,
               secret: str = None, commit: bool = False, save: bool = False,
               connect_fn=None, max_workers: int = PLUGIN_MAX_WORKERS,
               per_site_limit: int = PLUGIN_PER_SITE_LIMIT,
               progress_cb=None, stop_event=None) -> list:
    """Runs a command-runner plugin against every device in scope, with
    devices worked in parallel.

    site_id: None = every site, an int = one site, a list of ints = those
    sites. (Parameter name kept for older callers.)

    Threading: one pool of max_workers threads over devices, with at most
    per_site_limit devices of any one site in flight at once. A plugin can
    narrow this with optional module attributes: PARALLEL = False runs one
    device at a time, MAX_WORKERS = N caps the pool for that plugin.

    ALWAYS calls plugin_module.plan() first, regardless of commit -
    plan() is read-only by contract, so this is exactly as safe to
    call in dry-run as in commit mode. Commit mode additionally
    applies whatever plan() returned, then optionally saves.

    Per-device errors (connection failure, a command the device
    rejects, etc.) are caught and logged, never aborting the rest of
    the run - one bad device in scope shouldn't block every other
    device. Every device's plan, and the outcome of applying it, is
    written to a persistent, timestamped audit log file under logs/,
    in addition to being returned for the caller (the GUI) to display.
    Each device's lines are buffered and written as one block when that
    device finishes, so concurrent devices never interleave in the log.

    progress_cb(done_devices, total_devices, done_sites, total_sites) is
    called from worker threads after each device finishes (a queue.put
    is a safe callback). stop_event (a threading.Event): once set, devices
    not yet started are skipped; devices already running finish normally.

    Results are returned in site/device order, not completion order.

    connect_fn defaults to the real _connect() (live Netmiko); tests
    pass a fake with the same (host, username, password, platform_hint,
    secret) -> connection-like object signature, matching every other
    connect_fn override already used elsewhere in this file.
    """
    groups = _site_groups_in_scope(conn, site_id)
    total_devices = sum(len(ds) for _s, ds in groups)
    os.makedirs(LOGS_DIR, exist_ok=True)
    safe_name = re.sub(r"[^\w.-]", "_", plugin_module.NAME)
    log_path = os.path.join(
        LOGS_DIR, f"command_runner_{safe_name}_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
    )

    # Effective concurrency: the caller's numbers, narrowed by anything
    # the plugin itself declares.
    workers = max(1, int(max_workers))
    site_cap = max(1, int(per_site_limit))
    plugin_cap = getattr(plugin_module, "MAX_WORKERS", None)
    if isinstance(plugin_cap, int) and plugin_cap > 0:
        workers = min(workers, plugin_cap)
    if getattr(plugin_module, "PARALLEL", True) is False:
        workers = 1
    workers = max(1, min(workers, total_devices or 1))

    # Independent connection, not the caller's - same reasoning as
    # discovery_run above: this fires before the actual per-device
    # work, which is exactly the situation where sharing a connection
    # risks losing the "this was attempted" record if something later
    # raises before the caller's own transaction ever commits.
    db.log_activity(
        "command_runner_run",
        f"{plugin_module.NAME} - {'COMMIT' if commit else 'DRY-RUN'} - {total_devices} device(s) in "
        f"{len(groups)} site(s), {workers} worker(s), {site_cap} per site",
        detail_ref=log_path,
    )

    # All DB reads happen here on the calling thread - the sqlite
    # connection is not shared with workers.
    jobs_by_site = []
    results = [None] * total_devices
    index = 0
    for site, site_devices in groups:
        site_jobs = []
        for device in site_devices:
            site_jobs.append({
                "index": index, "site_id": site["id"],
                "site_label": str(site["site_name"] or site["site_octet"]),
                "device": device,
                "ips": list(db.get_ips_for_device(conn, device["id"])),
            })
            index += 1
        if site_jobs:
            jobs_by_site.append(site_jobs)
    jobs = _interleave_by_site(jobs_by_site)

    sites_total = len(jobs_by_site)
    remaining_in_site = {sj[0]["site_id"]: len(sj) for sj in jobs_by_site}
    site_slots = {sid: threading.BoundedSemaphore(site_cap) for sid in remaining_in_site}
    state = {"done_devices": 0, "done_sites": 0}
    lock = threading.Lock()
    connector = connect_fn or _connect

    with open(log_path, "w", encoding="utf-8") as logf:
        def emit(lines: list) -> None:
            block = "\n".join(lines)
            print(block)
            logf.write(block + "\n")
            logf.flush()

        def stamp(line: str = "") -> str:
            return f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {line}" if line else ""

        with lock:
            emit([
                stamp(f"=== {plugin_module.NAME} - {'COMMIT' if commit else 'DRY-RUN'} - "
                      f"{total_devices} device(s) in {sites_total} site(s) ==="),
                stamp(f"Parameters: {params}"),
                stamp(f"Concurrency: {workers} worker(s), at most {site_cap} per site"),
                "",
            ])

        def finish(job, result, lines):
            lines.append("")
            with lock:
                emit(lines)
                results[job["index"]] = result
                state["done_devices"] += 1
                remaining_in_site[job["site_id"]] -= 1
                if remaining_in_site[job["site_id"]] == 0:
                    state["done_sites"] += 1
                snapshot = (state["done_devices"], total_devices, state["done_sites"], sites_total)
            if progress_cb is not None:
                try:
                    progress_cb(*snapshot)
                except Exception:
                    pass

        def work(job):
            device = job["device"]
            hostname = device["hostname"]
            result = {"hostname": hostname, "site_id": job["site_id"], "changes": [],
                      "error": None, "applied": False, "skipped": False}
            lines = [stamp(f"--- {job['site_label']} / {hostname} ---")]

            def log(line: str = "") -> None:
                lines.append(stamp(line))

            try:
                if stop_event is not None and stop_event.is_set():
                    result["error"] = "Skipped (stopped before this device started)"
                    result["skipped"] = True
                    log(f"  SKIPPED: {result['error']}")
                    return finish(job, result, lines)

                with site_slots[job["site_id"]]:
                    if stop_event is not None and stop_event.is_set():
                        result["error"] = "Skipped (stopped before this device started)"
                        result["skipped"] = True
                        log(f"  SKIPPED: {result['error']}")
                        return finish(job, result, lines)

                    if not job["ips"]:
                        result["error"] = "No known IP on file for this device"
                        log(f"  SKIPPED: {result['error']}")
                        return finish(job, result, lines)

                    netmiko_conn = None
                    try:
                        last_exc = None
                        for ip in job["ips"]:
                            try:
                                netmiko_conn = connector(ip, username, password,
                                                         platform_hint=device["platform"], secret=secret)
                                break
                            except Exception as e:
                                last_exc = e
                                netmiko_conn = None
                        if netmiko_conn is None:
                            raise last_exc or ConnectionError("No usable IP for this device")

                        changes = plugin_module.plan(netmiko_conn, device, params)
                        result["changes"] = changes

                        if not changes:
                            log("  No changes needed.")
                        else:
                            prefix = "" if commit else "[DRY-RUN] "
                            for change in changes:
                                log(f"  {prefix}{change['description']}")
                                for cmd in change["commands"]:
                                    log(f"    > {cmd}")

                            if commit:
                                for change in changes:
                                    netmiko_conn.send_config_set(change["commands"])
                                result["applied"] = True
                                log(f"  Applied {len(changes)} change(s).")
                                if save:
                                    _save_device_config(netmiko_conn, _guess_device_type(device["platform"]))
                                    log("  Config saved.")
                    except Exception as e:
                        result["error"] = str(e)
                        log(f"  ERROR: {result['error']}")
                    finally:
                        if netmiko_conn is not None:
                            try:
                                netmiko_conn.disconnect()
                            except Exception:
                                pass
                return finish(job, result, lines)
            except Exception as e:  # never let a worker raise out of the pool
                result["error"] = str(e)
                lines.append(stamp(f"  ERROR: {e}"))
                return finish(job, result, lines)

        if jobs:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for future in [pool.submit(work, job) for job in jobs]:
                    future.result()

        done = [r for r in results if r is not None]
        with_changes = sum(1 for r in done if r["changes"])
        applied = sum(1 for r in done if r["applied"])
        errors = sum(1 for r in done if r["error"] and not r["skipped"])
        skipped = sum(1 for r in done if r["skipped"])
        with lock:
            emit([stamp(
                f"=== Finished: {len(done)} device(s), {with_changes} with changes"
                f"{f', {applied} applied' if commit else ''}, {errors} error(s), {skipped} skipped ==="
            )])

    print(f"Audit log written to {log_path}")
    return [r for r in results if r is not None]


def run_standalone_plugin(plugin_module, params: dict, username: str, password: str,
                           secret: str = None, commit: bool = False) -> None:
    """Runs a standalone plugin - one that owns its entire device list
    and connection flow itself (see list_plugins()'s docstring for
    when a plugin should be standalone rather than per-device).

    Unlike run_plugin(), there is no per-device loop or per-device
    error isolation at the harness level here - the plugin's own
    internal error handling is all there is, since the harness has no
    visibility into what devices it's even touching. Still writes the
    same kind of persistent, timestamped audit log as run_plugin(),
    and the plugin receives the same log() callable to write into it.

    IMPORTANT: unlike a per-device plugin's plan()/apply split (which
    the harness itself enforces - plan() is contractually read-only,
    and only the harness ever calls send_config_set()), a standalone
    plugin's run() function does EVERYTHING, including deciding
    whether to actually apply anything. The harness cannot structurally
    guarantee dry-run safety here - it depends entirely on the plugin
    correctly honoring commit=False itself. See the plugins README.
    """
    os.makedirs(LOGS_DIR, exist_ok=True)
    safe_name = re.sub(r"[^\w.-]", "_", plugin_module.NAME)
    log_path = os.path.join(
        LOGS_DIR, f"command_runner_{safe_name}_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
    )
    db.log_activity(
        "command_runner_run",
        f"{plugin_module.NAME} - {'COMMIT' if commit else 'DRY-RUN'} - standalone",
        detail_ref=log_path,
    )
    credentials = {"username": username, "password": password, "secret": secret}

    with open(log_path, "w", encoding="utf-8") as logf:
        def log(line: str = "") -> None:
            stamped = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {line}" if line else ""
            print(stamped)
            logf.write(stamped + "\n")
            logf.flush()

        try:
            plugin_module.run(log, params, credentials, commit)
        except Exception as e:
            log(f"ERROR: {e}")

    print(f"Audit log written to {log_path}")


def run_cli(argv: list) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--site", metavar="KEY", help="Run against one site (matches octet, name, or code)")
    group.add_argument("--all", action="store_true", help="Run against every site in the database")
    parser.add_argument(
        "--action", choices=["cdp", "arp", "all", "configs"], required=True,
        help="Which action to run: cdp discovery, arp collection, all (cdp + arp), or configs (pull running-configs "
             "from devices already in the database; no CDP walk). 'all' does not include configs.",
    )
    parser.add_argument(
        "--include-stale", action="store_true",
        help="With --action configs: also pull from aged-stale / manually-stale devices (skipped by default, "
             "since they are the most likely to time out).",
    )
    parser.add_argument(
        "--session-log", action="store_true",
        help="Troubleshooting only - write Netmiko's raw session log (exact bytes sent/received) for every "
             "connection this run makes, to timestamped files under ./session_logs/. Off by default since it "
             "isn't needed for routine runs; turn on only when actively debugging a connection issue.",
    )
    parser.add_argument(
        "--collect-tunnels", action="store_true",
        help="Also collect and match GRE tunnel interfaces (see collect_tunnels()). Independent of --action - "
             "only needs a CDP seed already flagged for each site, not a CDP walk this run.",
    )
    args = parser.parse_args(argv)

    actions = ["cdp", "arp"] if args.action == "all" else [args.action]
    session_log_dir = "session_logs" if args.session_log else None
    creds = _load_creds_or_exit()

    with db.get_conn() as conn:
        if args.all:
            # Excludes the reserved "Unassigned" holding site - it
            # never has a seed device, so scanning it is pure overhead
            # (picked up, immediately reports "no seed device
            # flagged", moves on) rather than a real site to discover.
            # (A config pull needs no seed device, so for --action configs
            # the Unassigned site IS included - its devices are real.)
            sites = db.get_all_sites(conn, include_unassigned=(args.action == "configs"))
        else:
            site = db.find_site_by_any_key(conn, args.site)
            if site is None:
                print(f"No site found matching '{args.site}'.", file=sys.stderr)
                sys.exit(1)
            sites = [site]

    if args.all and not sites:
        print("No sites found in the database.")
        return

    run_for_sites(sites, actions, creds, session_log_dir=session_log_dir, collect_tunnels_flag=args.collect_tunnels,
                  config_include_stale=args.include_stale)


def run_menu() -> None:
    print("--- Site Awareness Dashboard - Orchestrator ---\n")
    print("(1) Run CDP discovery")
    print("(2) Run ARP collection")
    print("(3) Run both (CDP then ARP)")
    print("(4) Collect running-configs (devices already in the database)")
    choice = input("Select action: ").strip()
    action_map = {"1": ["cdp"], "2": ["arp"], "3": ["cdp", "arp"], "4": ["configs"]}
    actions = action_map.get(choice)
    if actions is None:
        print("Invalid choice.")
        return

    print("\n(1) Run against one specific site")
    print("(2) Run against all sites")
    scope_choice = input("Select scope: ").strip()

    session_log_choice = input(
        "\nCapture Netmiko session logs for troubleshooting? (raw bytes sent/received, "
        "written to ./session_logs/) [y/N]: "
    ).strip().lower()
    session_log_dir = "session_logs" if session_log_choice == "y" else None

    creds = _load_creds_or_exit()

    with db.get_conn() as conn:
        if scope_choice == "2":
            sites = db.get_all_sites(conn, include_unassigned=("configs" in actions))
        elif scope_choice == "1":
            key = input("Enter site octet, name, or code: ").strip()
            site = db.find_site_by_any_key(conn, key)
            if site is None:
                print(f"No site found matching '{key}'.")
                return
            sites = [site]
        else:
            print("Invalid choice.")
            return

    if scope_choice == "2" and not sites:
        print("No sites found in the database.")
        return

    run_for_sites(sites, actions, creds, session_log_dir=session_log_dir)


def main():
    if len(sys.argv) == 1:
        run_menu()
    else:
        run_cli(sys.argv[1:])


if __name__ == "__main__":
    main()