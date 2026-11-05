"""
db.py - SQLite database layer for the Site Awareness Dashboard (SAD).

This module owns the schema and provides small, dependency-free helper
functions for reading and writing discovery data. Nothing outside this
file should be writing raw SQL against sad.db - everything goes through
these functions so the schema can evolve without hunting through the
whole codebase.

Design notes (decided during planning, not obvious from the code alone):
- Every discovery-derived table carries `source` and `last_seen` so we
  always know *where* a row came from and *how fresh* it is.
- `raw_source_data` stores the original parsed line/record as text so
  we can reprocess history later if parsing logic changes, without a
  full network re-scan.
- Sources in use: 'cdp' (CDP walk discovery) and 'inventory_sync'
  (bulk import from whatever inventory tool is current - Prime,
  Catalyst Center, etc; deliberately not tool-specific since the tool
  itself is expected to change over time). 'manual' is reserved for
  a person explicitly overriding a value by hand.
- devices.mgmt_ip is a CACHED "best known IP" value, derived from
  device_ips (see below) - nothing should write to it directly other
  than _refresh_cached_mgmt_ip(). It exists as a fast/simple column
  for anything that just wants "the IP to use right now" without
  caring about ranking logic.
- device_ips holds every IP ever observed for a device, tagged with
  its own source, and is never destructively overwritten - only
  added to. This exists because CDP-reported "management addresses"
  are sometimes wrong (e.g. a router advertising an unroutable
  interface-local IP instead of its real mgmt IP), so blindly trusting
  the most recent report isn't safe. inventory_sync data
  (the org's actual system of record) always outranks cdp data when
  picking the current best IP; among same-source candidates, an IP
  whose first two octets match another known-good IP at the same site
  is preferred as a tie-breaker. See record_device_ip() and
  get_best_ip_for_device().
"""

import re
import sqlite3
import ipaddress
import hashlib
import zlib
import mac_parser
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = "sad.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    site_octet         TEXT NOT NULL UNIQUE,
    site_name          TEXT UNIQUE,
    site_code          TEXT,
    seed_device        TEXT,
    arp_seed_device    TEXT,  -- only set when it differs from seed_device - see get_arp_seed_device_for_site()
    last_run           TEXT,  -- legacy, frozen - see last_cdp_discovery
    last_cdp_discovery TEXT,  -- set only by mark_site_run(); the trustworthy "was this site actually scanned" signal
    last_arp_collection TEXT,  -- set only by mark_site_arp_run(); same idea as last_cdp_discovery, for ARP collection
    last_mac_table_collection TEXT,  -- set only by mark_site_mac_table_run(); same idea again, for MAC-table/client collection specifically. NOT the same as last_cdp_discovery, which advances on every CDP walk regardless of whether MAC-table collection was actually requested that run - client staleness needs its own timestamp to avoid every client looking newly stale after a plain CDP-only re-scan
    last_tunnel_collection TEXT  -- set only by mark_site_tunnel_run(); same idea again, for tunnel collection specifically - see mark_site_tunnel_run()'s docstring for how this differs from tunnel_links.last_confirmed
);

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         INTEGER NOT NULL REFERENCES sites(id),
    hostname        TEXT NOT NULL,
    mgmt_ip         TEXT,
    platform        TEXT,
    serial_number   TEXT,
    is_seed         INTEGER NOT NULL DEFAULT 0,
    is_arp_seed     INTEGER NOT NULL DEFAULT 0,
    arp_override_ip TEXT,  -- tried first for ARP collection only (e.g. a shared VIP); falls through to the device's normal ranked IPs if unreachable
    marked_stale_at TEXT,  -- set only by set_device_marked_stale(); a manual "I've confirmed this is gone" flag, independent of and complementary to the automatic age-based staleness check
    source          TEXT NOT NULL DEFAULT 'cdp',
    last_seen       TEXT,
    raw_source_data TEXT,
    UNIQUE(site_id, hostname)
);

CREATE TABLE IF NOT EXISTS links (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         INTEGER NOT NULL REFERENCES sites(id),
    device_a_id     INTEGER NOT NULL REFERENCES devices(id),
    device_b_id     INTEGER NOT NULL REFERENCES devices(id),
    local_intf      TEXT,
    remote_intf     TEXT,
    source          TEXT NOT NULL DEFAULT 'cdp',
    last_seen       TEXT,
    raw_source_data TEXT,
    UNIQUE(site_id, device_a_id, device_b_id, local_intf, remote_intf)
);

CREATE TABLE IF NOT EXISTS arp_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         INTEGER NOT NULL REFERENCES sites(id),
    device_id       INTEGER REFERENCES devices(id),
    vrf             TEXT NOT NULL DEFAULT '',
    ip              TEXT NOT NULL,
    mac             TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'cdp',
    last_seen       TEXT,
    raw_source_data TEXT,
    UNIQUE(site_id, vrf, ip, mac)
);

-- One row per MAC per site - the switch/port it was last confirmed
-- plugged into (a real edge port, not an inter-switch uplink; see
-- mac_parser.py and the correlation pass that decides that before
-- ever calling upsert_client()). IP isn't stored here - it's
-- correlated against arp_entries.mac at display time instead of
-- duplicated, so the two facts can't drift out of sync with each
-- other. The UNIQUE constraint is a plain-string backstop; the real
-- duplicate-prevention happens in upsert_client() itself via
-- mac_parser.normalize_mac(), since the SAME physical MAC can be
-- reported in different separator styles/case across platforms and
-- commands - a raw string UNIQUE constraint alone wouldn't catch that.
CREATE TABLE IF NOT EXISTS clients (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         INTEGER NOT NULL REFERENCES sites(id),
    mac             TEXT NOT NULL,
    device_id       INTEGER REFERENCES devices(id),
    interface       TEXT,
    vlan            TEXT,
    device_type     TEXT,
    source          TEXT NOT NULL DEFAULT 'mac-table',
    last_seen       TEXT,
    raw_source_data TEXT,
    UNIQUE(site_id, mac)
);

-- Raw "show mac address-table" output, staged per device during a CDP
-- walk (see discover_site()'s collect_mac_tables option), NOT yet
-- correlated into clients. Deciding which entries are real edge/
-- client ports versus inter-switch uplinks requires the site's full
-- links table to be complete, which it isn't yet mid-walk - that
-- correlation is a separate pass, run only after the walk finishes.
-- One row per device (not accumulating history) - a later collection
-- for the same device REPLACES its previous staged output, matching
-- the same "last processed wins" philosophy used throughout.
CREATE TABLE IF NOT EXISTS mac_table_raw (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id      INTEGER NOT NULL REFERENCES sites(id),
    device_id    INTEGER NOT NULL REFERENCES devices(id),
    raw_output   TEXT NOT NULL,
    collected_at TEXT,
    UNIQUE(device_id)
);

-- CUCM/RIS enrichment for phone/VTC clients (see clients.device_type
-- 'cisco_phone'/'vtc'). Keyed by MAC alone, no site_id - stays valid
-- even if a phone physically moves between sites, since it's joined
-- against whichever site clients.mac currently belongs to, not tied
-- to one. mac is stored NORMALIZED (lowercase, no separators) here
-- specifically - unlike clients.mac/arp_entries.mac, which preserve
-- whatever a network device reported verbatim, this table's mac is
-- SAD's own generated join key (built to construct the SEPxxxx CUCM
-- lookup name), not text captured from an external source.
--
-- Two genuinely different refresh rhythms live on this one row:
-- ris_ip/ris_status come from RIS's cheap bulk query and are meant to
-- be refreshed on EVERY enrichment script run (ris_status in
-- particular can genuinely flip between Registered/Unregistered over
-- time) - no skip logic for those two fields at all. model/
-- serial_number come from a slow, per-device HTTP/xAPI call instead,
-- and are governed by last_attempted/last_enriched: last_attempted is
-- stamped on every attempt regardless of outcome (so a permanently-
-- unreachable legacy device is only ever tried once, not retried
-- forever), while last_enriched is stamped only when the pull
-- actually returned something real.
-- Activity log: SAD's operational record of who did what and when.
-- Every part of the app that logs anything does so through
-- db.log_activity() ONLY - nothing writes to this table directly.
-- That centralization is deliberate: it's what will let a future
-- syslog-forwarding feature be a small addition inside that one
-- function later, rather than needing to touch every call site again.
-- NOT tamper-proof (a local sqlite table like any other, editable by
-- anyone with file access to sad.db) - a genuinely useful operational
-- record, not a true audit trail, unless/until forwarded elsewhere.
-- credential_store is nullable - only set for actions that actually
-- involved unlocking one; detail_ref is nullable - a pointer to a
-- fuller file (e.g. one of Command Runner's own per-run logs) when
-- one exists for this entry.
CREATE TABLE IF NOT EXISTS activity_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT NOT NULL,
    username         TEXT,
    credential_store TEXT,
    action           TEXT NOT NULL,
    detail           TEXT,
    detail_ref       TEXT
);

CREATE TABLE IF NOT EXISTS phone_enrichment (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    mac            TEXT NOT NULL UNIQUE,
    device_name    TEXT,
    ris_ip         TEXT,
    ris_status     TEXT,
    phone_number   TEXT,  -- from RIS's DirNumber field (same bulk call as ris_ip/ris_status - refreshed every run, no skip logic, same reasoning as ris_status since an extension can genuinely be reassigned over time)
    model          TEXT,
    serial_number  TEXT,
    last_attempted TEXT,
    last_enriched  TEXT
);

CREATE TABLE IF NOT EXISTS subnet_overrides (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr     TEXT NOT NULL UNIQUE,
    site_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_ips (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER NOT NULL REFERENCES devices(id),
    ip              TEXT NOT NULL,
    source          TEXT NOT NULL,
    last_seen       TEXT,
    raw_source_data TEXT,
    UNIQUE(device_id, ip)
);

-- Raw per-device tunnel interface data, collected via 'show
-- interfaces tunnel <N>' (see tunnel_parser.py), starting from each
-- site's CDP seed outward like everything else - NOT limited to
-- devices already known from a CDP neighbor relationship, since a
-- tunnel's far end reaches sites CDP can never see across (an
-- internet-routed GRE tunnel, invisible to CDP by design; confirmed
-- CDP does not run on these interfaces at all in this environment).
-- One row per device per tunnel interface; a later collection for the
-- same device/interface REPLACES the previous row - same "last
-- processed wins" pattern as device_ips/arp_entries.
--
-- source_ip/destination_ip are the fields match_tunnels() actually
-- joins on to build tunnel_links. description/internet_address are
-- captured for reference/display only (the per-site Tunnels panel) -
-- neither is used for matching. Any of the parsed fields can be NULL
-- (an interface whose source/destination line didn't parse, or that
-- has no description/address configured) - see tunnel_parser.py,
-- which deliberately still returns a row in that case rather than
-- dropping it, so it can show up here too instead of vanishing.
CREATE TABLE IF NOT EXISTS tunnel_interfaces (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id                INTEGER NOT NULL REFERENCES sites(id),
    device_id              INTEGER NOT NULL REFERENCES devices(id),
    interface              TEXT NOT NULL,
    admin_status           TEXT,
    line_protocol          TEXT,
    description            TEXT,
    internet_address       TEXT,
    source_ip              TEXT,
    source_interface       TEXT,
    destination_ip         TEXT,
    destination_interface  TEXT,
    last_seen              TEXT,
    raw_source_data        TEXT,
    UNIQUE(device_id, interface)
);

-- Resolved tunnel pairings, built by match_tunnels(). One row per
-- LOCAL tunnel interface (device_a), NOT one row per pair - a
-- genuinely matched pair therefore shows up as TWO rows, one from
-- each device's own perspective (device_a's row points at device_b,
-- and device_b's own separate row independently points back at
-- device_a), which mirrors how the two devices were independently
-- scanned in the first place and lets a per-site Tunnels panel just
-- query "WHERE device_a_id IN (this site's devices)" without caring
-- which side "owns" the pairing.
--
-- device_b_id/device_b_interface are NULL whenever no matching
-- reverse row exists yet (the far site hasn't been scanned yet, or
-- the tunnel really has been removed on that end) - deliberately
-- surfaced as a one-sided row rather than hidden, since that's itself
-- useful signal (possible config drift: configured on one end,
-- deleted on the other).
--
-- last_confirmed is its own staleness signal, separate from either
-- endpoint device's last_seen - a tunnel (especially a backup one)
-- can flap independently of the device itself staying reachable.
CREATE TABLE IF NOT EXISTS tunnel_links (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    device_a_id            INTEGER NOT NULL REFERENCES devices(id),
    device_a_interface     TEXT NOT NULL,
    device_b_id            INTEGER REFERENCES devices(id),
    device_b_interface     TEXT,
    source_ip              TEXT NOT NULL,
    destination_ip         TEXT NOT NULL,
    last_confirmed         TEXT,
    UNIQUE(device_a_id, device_a_interface)
);

-- Remembers the OTHER name of a device that was merged away (see
-- merge_devices()). Devices are keyed by exact (site_id, hostname), so
-- after merging a CDP-discovered "SW-01.corp.example" into an
-- inventory-known "sw-01", the very next CDP walk would report
-- "SW-01.corp.example" again and silently create the duplicate all
-- over again. An alias row says "this name at this site is really that
-- device" - upsert_device()/get_device_*_by_hostname() consult it only
-- when no real device has the exact name. COLLATE NOCASE because
-- case-only differences are one of the most common ways these
-- duplicates arise in the first place.
CREATE TABLE IF NOT EXISTS device_aliases (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id    INTEGER NOT NULL REFERENCES sites(id),
    device_id  INTEGER NOT NULL REFERENCES devices(id),
    hostname   TEXT NOT NULL COLLATE NOCASE,
    created_at TEXT,
    UNIQUE(site_id, hostname)
);

-- Running-config history. One row per DISTINCT config seen on a device
-- (a pull identical to the newest stored snapshot adds nothing). The
-- config text is zlib-compressed after the volatile header/timestamp
-- lines are stripped (see config_parser.py), so content_hash only moves
-- when the real config does. changed_at/changed_by/nvram_updated are the
-- device's own "last configuration change" metadata parsed out of the
-- header, stored for display only. is_baseline marks the very first
-- snapshot ever stored for a device; pruning never deletes it.
CREATE TABLE IF NOT EXISTS config_snapshots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER NOT NULL REFERENCES devices(id),
    collected_at  TEXT NOT NULL,
    content_hash  TEXT NOT NULL,
    config_z      BLOB NOT NULL,
    size_bytes    INTEGER,
    line_count    INTEGER,
    changed_at    TEXT,
    changed_by    TEXT,
    nvram_updated TEXT,
    is_baseline   INTEGER NOT NULL DEFAULT 0
);

-- One row per device: when a config pull was last tried / last worked,
-- the last error, and what the device itself last reported as its
-- latest change (even when the config text was unchanged).
CREATE TABLE IF NOT EXISTS config_pull_status (
    device_id            INTEGER PRIMARY KEY REFERENCES devices(id),
    last_attempt_at      TEXT,
    last_success_at      TEXT,
    last_error           TEXT,
    device_changed_at    TEXT,
    device_changed_by    TEXT,
    device_nvram_updated TEXT
);

CREATE INDEX IF NOT EXISTS idx_config_snapshots_device ON config_snapshots(device_id, id);

-- GEM One KG (TACLANE) devices, imported from the file gemone_full_pull.py
-- writes. Kept apart from `devices` on purpose: CDP runs, stale marking and
-- the config collector never touch these. Health is NOT stored: it is worked
-- out from these fields and the thresholds in settings.json when displayed.
CREATE TABLE IF NOT EXISTS kg_devices (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_number       TEXT NOT NULL UNIQUE,
    site_id             INTEGER REFERENCES sites(id),
    system_name         TEXT,
    device_type         TEXT,
    state               TEXT,
    software_version    TEXT,
    pt_ip               TEXT,
    ct_ip               TEXT,
    pt_mac              TEXT,
    ct_mac              TEXT,
    pt_status           TEXT,
    ct_status           TEXT,
    ffvs_exp_date       TEXT,   -- KEYMAT expiry, YYYY-MM-DD
    battery_change_date TEXT,   -- when the battery was last changed, YYYY-MM-DD
    data_collected_at   TEXT,   -- the import file's collected_at for this row's data
    first_seen          TEXT,
    last_seen           TEXT,   -- the last import this serial was present in
    missing_since       TEXT,   -- set when a newer file no longer lists it; cleared when it returns
    last_error          TEXT,   -- the script could not read this device on its last run
    last_error_at       TEXT,
    deleted_at          TEXT,
    source              TEXT NOT NULL DEFAULT 'gemone'   -- 'gemone' (from a GEM One file) or 'manual' (entered by hand)
);

CREATE TABLE IF NOT EXISTS kg_security_associations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kg_id           INTEGER NOT NULL REFERENCES kg_devices(id),
    remote_ct       TEXT,
    remote_pt       TEXT,
    method          TEXT,
    pair_reachable  INTEGER   -- 1 yes, 0 no, NULL unknown
);

-- Which site a KG belongs to, by serial number (set by hand or from a CSV; the
-- GEM One data carries no site). A serial with no row here lands in Unassigned.
CREATE TABLE IF NOT EXISTS kg_site_map (
    serial_number TEXT PRIMARY KEY,
    site_id       INTEGER NOT NULL REFERENCES sites(id)
);

CREATE TABLE IF NOT EXISTS kg_imports (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    imported_at        TEXT NOT NULL,
    file_collected_at  TEXT,
    source             TEXT,
    device_count       INTEGER,
    added              INTEGER,
    updated            INTEGER,
    errors             INTEGER,
    missing            INTEGER
);

CREATE TABLE IF NOT EXISTS kg_state_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kg_id      INTEGER NOT NULL REFERENCES kg_devices(id),
    at         TEXT NOT NULL,
    old_state  TEXT,
    new_state  TEXT
);

CREATE INDEX IF NOT EXISTS idx_kg_devices_site ON kg_devices(site_id);
CREATE INDEX IF NOT EXISTS idx_kg_assoc_kg ON kg_security_associations(kg_id);
CREATE INDEX IF NOT EXISTS idx_devices_site   ON devices(site_id);
CREATE INDEX IF NOT EXISTS idx_devices_serial ON devices(serial_number);
CREATE INDEX IF NOT EXISTS idx_links_site     ON links(site_id);
CREATE INDEX IF NOT EXISTS idx_arp_site       ON arp_entries(site_id);
CREATE INDEX IF NOT EXISTS idx_device_ips_device ON device_ips(device_id);
CREATE INDEX IF NOT EXISTS idx_device_aliases_device ON device_aliases(device_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_interfaces_site   ON tunnel_interfaces(site_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_interfaces_device ON tunnel_interfaces(device_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_links_device_a    ON tunnel_links(device_a_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_links_device_b    ON tunnel_links(device_b_id);
"""


def _now() -> str:
    """UTC ISO-8601 timestamp used for every last_seen/last_run write."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------
# Activity logging
# ---------------------------------------------------------------------
# Set once by the login gate at launch (see gui.py) after a successful
# unlock - not recomputed per log call, since os.getlogin() can raise
# in some execution contexts (no controlling terminal, run as a
# service) and the login flow is a known-good moment to capture it
# safely. CURRENT_CREDENTIAL_STORE is which credential store file got
# unlocked; both stay None until login happens, and log_activity()
# logs whatever they currently are, blank or not - it has no opinion
# about whether login has happened yet, that's the login gate's job.
CURRENT_USER = None
CURRENT_CREDENTIAL_STORE = None


def log_activity(action: str, detail: str = "", detail_ref: str = None, conn=None) -> None:
    """THE single write path for SAD's activity log - every part of
    the app that wants to record something calls this, and ONLY this;
    nothing should ever INSERT INTO activity_log directly. This
    centralization is deliberate: it's what lets a future syslog-
    forwarding feature be a small addition inside this one function
    later, rather than needing to touch every call site across the
    app again.

    conn: an already-open connection to reuse, if the caller has one
    (e.g. db.py's own write functions, called from within a caller's
    still-open, uncommitted transaction). This matters for a concrete
    reason, not just convenience: opening a SEPARATE connection while
    another one is mid-transaction on the same SQLite file can hit
    "database is locked" - confirmed directly, not theoretical. Reusing
    the caller's connection avoids that entirely, since it's the same
    connection/transaction, not two competing ones. If no conn is
    given (e.g. the login dialog, which has no open transaction to
    reuse), falls back to opening its own independent one.

    Strictly best-effort either way: catches and swallows its own
    failures (a locked db, a full disk, whatever) rather than ever
    raising - logging must never be able to block or break the action
    it's attached to. A failure here prints a quiet warning and
    otherwise does nothing further.
    """
    try:
        if conn is not None:
            conn.execute(
                """
                INSERT INTO activity_log (timestamp, username, credential_store, action, detail, detail_ref)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (_now(), CURRENT_USER, CURRENT_CREDENTIAL_STORE, action, detail, detail_ref),
            )
        else:
            with get_conn() as own_conn:
                own_conn.execute(
                    """
                    INSERT INTO activity_log (timestamp, username, credential_store, action, detail, detail_ref)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (_now(), CURRENT_USER, CURRENT_CREDENTIAL_STORE, action, detail, detail_ref),
                )
    except Exception as e:
        print(f"Warning: could not write activity log entry: {e}")


@contextmanager
def get_conn(db_path: str = DB_PATH):
    """Context-managed connection with foreign keys enforced."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _ensure_column(conn, table: str, column: str, coltype: str) -> None:
    """Adds `column` to `table` if it isn't already there. Necessary
    because CREATE TABLE IF NOT EXISTS (used by init_db() below) is a
    complete no-op on a table that already exists - a new column
    added to SCHEMA's CREATE TABLE text does NOT retroactively apply
    to a database that was created before that column was added
    (verified directly: SQLite skips the whole statement once the
    table is present, new column or not). Every column added to an
    already-existing table needs an entry here, or it silently never
    reaches anyone's real, pre-existing database - it would only ever
    appear on a brand new one, and any code touching the missing
    column would hit a hard "no such column" SQL error there instead.
    """
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def init_db(db_path: str = DB_PATH) -> None:
    """Create all tables/indexes if they don't already exist, and
    migrate an existing database forward to match the current schema
    (see _ensure_column()'s docstring for why this step is needed at
    all - a plain CREATE TABLE IF NOT EXISTS cannot add new columns to
    a table that's already there).
    """
    with get_conn(db_path) as conn:
        conn.executescript(SCHEMA)
        _ensure_column(conn, "sites", "last_mac_table_collection", "TEXT")
        _ensure_column(conn, "phone_enrichment", "phone_number", "TEXT")
        # Soft-delete support: NULL = active, a real timestamp = hidden
        # from every listing/lookup below but still physically present
        # (reversible by design - see soft_delete_site()/
        # soft_delete_device()). No equivalent flag on links/arp_
        # entries/clients - their hiding is entirely derived from
        # whichever devices make it through the filtered queries below.
        _ensure_column(conn, "sites", "deleted_at", "TEXT")
        _ensure_column(conn, "devices", "deleted_at", "TEXT")
        # Retroactive coverage for a column added to an already-
        # existing table in an earlier session - included here in
        # case any real database predates it and was never recreated
        # from scratch since (this call is a safe no-op otherwise).
        _ensure_column(conn, "devices", "marked_stale_at", "TEXT")
        _ensure_column(conn, "sites", "last_tunnel_collection", "TEXT")
        # KG units entered by hand (not reachable by GEM One) vs imported ones.
        _ensure_column(conn, "kg_devices", "source", "TEXT NOT NULL DEFAULT 'gemone'")


# ---------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------

def upsert_site(conn, site_octet: str) -> int:
    """Insert a site by octet if new. Returns site_id.

    Does NOT touch last_run or last_cdp_discovery - those are
    exclusively set by mark_site_run() when a CDP discovery run
    actually completes for a site. Earlier versions of this function
    also stamped last_run here, which meant every inventory import
    call (not just real discovery runs) bumped it - making it
    impossible to tell which sites had genuinely been CDP-scanned.
    See last_cdp_discovery for the trustworthy signal going forward;
    last_run is left alone as a frozen legacy field, not actively used.

    site_name and site_code are NOT set here - discovery/import only
    ever knows the octet. Use set_site_identity() to assign the
    human-friendly name and org code afterward.
    """
    conn.execute(
        "INSERT INTO sites (site_octet) VALUES (?) ON CONFLICT(site_octet) DO NOTHING",
        (site_octet,),
    )
    row = conn.execute("SELECT id FROM sites WHERE site_octet = ?", (site_octet,)).fetchone()
    return row["id"]


def set_site_identity(conn, site_id: int, site_name: str = None, site_code: str = None) -> None:
    """Manually assign the human-friendly name and/or org code for a site.

    Pass only the field(s) you want to change - the other stays as-is.
    """
    if site_name is not None:
        conn.execute("UPDATE sites SET site_name = ? WHERE id = ?", (site_name, site_id))
    if site_code is not None:
        conn.execute("UPDATE sites SET site_code = ? WHERE id = ?", (site_code, site_id))


def add_site_manual(conn, site_octet: str, site_name: str = None, site_code: str = None) -> int:
    """User-initiated "Add Site" (Site Manager GUI). Thin wrapper around
    upsert_site() + set_site_identity() that additionally logs the
    action - deliberately NOT folded into upsert_site() itself, since
    upsert_site() is also called on every ordinary CDP/inventory
    discovery pass, where logging every call would flood the activity
    log with routine machinery instead of the one thing an operator
    actually cares about seeing: "a person added this site by hand".
    If the octet already exists, this reuses that row rather than
    erroring - upsert_site()'s normal behavior. If that existing row
    was soft-deleted, re-adding it by the same octet is treated as an
    intentional revival: deleted_at is cleared here so the site comes
    back to life, rather than the user's "Add Site" silently doing
    nothing because a same-named row already exists but is hidden.
    """
    site_id = upsert_site(conn, site_octet)
    conn.execute("UPDATE sites SET deleted_at = NULL WHERE id = ?", (site_id,))
    set_site_identity(conn, site_id, site_name=site_name, site_code=site_code)
    label = site_name or site_octet
    log_activity("add_site", f"Site {site_octet} ({label}) added", conn=conn)
    return site_id


def get_all_sites(conn, include_unassigned: bool = True):
    # site_octet is stored as TEXT (it isn't always a literal octet -
    # subnet-override keys like "170a" or "unassigned" live there too),
    # so a plain ORDER BY site_octet sorts alphabetically ("100" before
    # "20"), not numerically. CAST(...AS INTEGER) fixes the numeric
    # case; non-numeric octets all CAST to 0 in SQLite, so they group
    # together at the front, sorted alphabetically among themselves via
    # the site_octet/site_name tiebreakers - which is also the only
    # place site_name ever actually breaks a tie, since site_octet
    # itself is UNIQUE.
    #
    # include_unassigned=False (opt-in) excludes the reserved
    # "Unassigned" holding site (see get_or_create_unassigned_site()) -
    # it never has a seed device (nothing ever flags one for it), so a
    # discovery/ARP run against it is pure overhead: it's picked up,
    # immediately reports "no seed device flagged", and moves on. Every
    # caller that means "every real, scannable site" should pass this;
    # callers that manage or report on Unassigned's actual (just
    # misattributed, not fake) devices - Site Manager, Command Runner's
    # device scope, CSV export - keep the default and still see it.
    where = "WHERE deleted_at IS NULL"
    params = ()
    if not include_unassigned:
        where += " AND site_octet != ?"
        params = (UNASSIGNED_SITE_OCTET,)
    return conn.execute(
        f"SELECT * FROM sites {where} ORDER BY CAST(site_octet AS INTEGER), site_octet, site_name",
        params,
    ).fetchall()


def find_site_by_any_key(conn, key: str):
    """Look up a site by site_octet, site_name, or site_code - checked
    in that strict priority order, not all at once. site_octet is
    guaranteed unique, so an exact octet match is always authoritative
    and returned immediately; only falls through to name, then code,
    if no octet matches. This matters because site_code is
    intentionally NOT unique (real sites can share one) - a single
    combined OR query with no priority could return a coincidental
    name/code match instead of the real octet match, silently
    resolving to the wrong site. Case-insensitive on name/code since
    those are typed by hand more often than octet. Returns the site
    row, or None if nothing matches any of the three.
    """
    row = conn.execute("SELECT * FROM sites WHERE site_octet = ? AND deleted_at IS NULL", (key,)).fetchone()
    if row is not None:
        return row
    row = conn.execute(
        "SELECT * FROM sites WHERE LOWER(site_name) = LOWER(?) AND deleted_at IS NULL", (key,)
    ).fetchone()
    if row is not None:
        return row
    return conn.execute(
        "SELECT * FROM sites WHERE LOWER(site_code) = LOWER(?) AND deleted_at IS NULL LIMIT 1", (key,)
    ).fetchone()


def get_site_by_id(conn, site_id: int):
    """Pure lookup by primary key - unambiguous by definition, unlike
    any string-based lookup. Used where a caller already has a
    specific site's id in hand (e.g. from a GUI selection) and wants
    to re-fetch it without any risk of a name/code/octet collision.
    Returns None for a soft-deleted site, same as if it didn't exist -
    a caller that genuinely needs to see a deleted site (e.g. a future
    restore tool) should query sites directly rather than through this.
    """
    return conn.execute("SELECT * FROM sites WHERE id = ? AND deleted_at IS NULL", (site_id,)).fetchone()


def get_site_by_octet(conn, site_octet: str):
    """Pure lookup by exact site_octet - a plain SELECT with no side
    effects. Unlike upsert_site(), this never creates a row and never
    touches last_run. Use this when you need to check whether a site
    already exists without implying "a run just happened" (e.g.
    resolving which site a CDP neighbor actually belongs to, where the
    site itself wasn't what was being scanned). Returns None if no
    site has that octet.
    """
    return conn.execute(
        "SELECT * FROM sites WHERE site_octet = ?", (site_octet,)
    ).fetchone()


def find_devices_by_hostname_anywhere(conn, hostname: str):
    """All devices with this exact hostname across every site (should
    normally be 0 or 1, given hostnames are expected to be unique org-
    wide - but this doesn't enforce that, so more than one is possible
    and callers should treat that as ambiguous rather than picking
    one). Each row includes the owning site's site_octet as
    owning_site_octet, for convenience in messages/logging.
    """
    return conn.execute(
        """
        SELECT d.*, s.site_octet AS owning_site_octet
        FROM devices d
        JOIN sites s ON d.site_id = s.id
        WHERE d.hostname = ?
        """,
        (hostname,),
    ).fetchall()


UNASSIGNED_SITE_OCTET = "unassigned"


def get_or_create_unassigned_site(conn) -> int:
    """Returns the id of the reserved 'Unassigned' site, creating it
    (with a human-readable name) the first time it's needed.

    This is where a CDP-discovered neighbor lands when it can't be
    confidently attributed to any real site: its address's octet
    doesn't match the site being scanned (e.g. it's a WAN-facing
    address, which doesn't follow the normal per-site addressing
    scheme at all), AND its hostname doesn't match any device already
    known elsewhere. Rather than guess wrong, the device/link still
    get recorded - nothing is silently dropped - just parked here
    pending a person reviewing site_manager.py and reassigning it once
    its real site is known.
    """
    existing = get_site_by_octet(conn, UNASSIGNED_SITE_OCTET)
    if existing is not None:
        return existing["id"]
    site_id = upsert_site(conn, UNASSIGNED_SITE_OCTET)
    set_site_identity(conn, site_id, site_name="Unassigned - Needs Review")
    return site_id


# ---------------------------------------------------------------------
# Subnet overrides (for sites that share a second octet but are split
# by a non-/24 subnet boundary)
# ---------------------------------------------------------------------

def upsert_subnet_override(conn, cidr: str, site_key: str) -> None:
    """Add or update an exception mapping a specific CIDR range to a site key.

    site_key is just whatever unique string you want that site to be
    known by internally (it becomes that site's site_octet value) -
    it doesn't have to literally be an octet, e.g. '170a'/'170-guest'.
    """
    conn.execute(
        """
        INSERT INTO subnet_overrides (cidr, site_key)
        VALUES (?, ?)
        ON CONFLICT(cidr) DO UPDATE SET site_key = excluded.site_key
        """,
        (cidr, site_key),
    )


def get_all_subnet_overrides(conn):
    return conn.execute("SELECT * FROM subnet_overrides ORDER BY cidr").fetchall()


def resolve_site_key_for_ip(conn, ip_str: str) -> str:
    """Return the site key to use for a device's IP.

    Checks subnet_overrides first - if the IP falls in more than one
    override range (shouldn't normally happen, but be defensive), the
    most specific (longest prefix) match wins. Falls back to the plain
    second-octet rule if no override matches.
    """
    ip = ipaddress.ip_address(ip_str)

    overrides = conn.execute("SELECT cidr, site_key FROM subnet_overrides").fetchall()
    matches = []
    for row in overrides:
        network = ipaddress.ip_network(row["cidr"], strict=False)
        if ip in network:
            matches.append((network.prefixlen, row["site_key"]))

    if matches:
        matches.sort(key=lambda m: m[0], reverse=True)  # longest prefix first
        return matches[0][1]

    return str(ip).split(".")[1]


def mark_site_run(conn, site_id: int) -> None:
    """Stamp a site's last_cdp_discovery to now (call at the end of a
    successful discover_site() run) - the only thing that writes to
    this column, so it's a trustworthy "was this site genuinely
    CDP-scanned" signal. sites.last_run is a separate, legacy column
    that upsert_site() still bumps on every unrelated call (inventory
    imports, site creation, etc.) - it doesn't mean the same thing as
    last_cdp_discovery and shouldn't be used to judge scan freshness.
    """
    conn.execute("UPDATE sites SET last_cdp_discovery = ? WHERE id = ?", (_now(), site_id))


def mark_site_arp_run(conn, site_id: int) -> None:
    """Stamp a site's last_arp_collection to now (call at the end of a
    successful collect_arp() run) - same idea and same reasoning as
    mark_site_run()/last_cdp_discovery, just for ARP collection instead
    of CDP discovery. Nothing else should write to this column.
    """
    conn.execute("UPDATE sites SET last_arp_collection = ? WHERE id = ?", (_now(), site_id))


def mark_site_mac_table_run(conn, site_id: int) -> None:
    """Stamp a site's last_mac_table_collection to now (call at the
    end of a discover_site() run that had collect_mac_tables=True) -
    same idea as mark_site_run()/mark_site_arp_run(), but deliberately
    its own separate column rather than reusing last_cdp_discovery.
    last_cdp_discovery advances on EVERY CDP walk regardless of
    whether MAC-table collection was actually requested that run -
    comparing client staleness against it would make every client at
    a site look newly stale after a plain CDP-only re-scan, even
    though nothing about them was actually re-verified that time.
    """
    conn.execute("UPDATE sites SET last_mac_table_collection = ? WHERE id = ?", (_now(), site_id))


def mark_site_tunnel_run(conn, site_id: int) -> None:
    """Stamp a site's last_tunnel_collection to now (call at the end of
    a successful collect_tunnels() run) - same idea as mark_site_run()/
    mark_site_arp_run()/mark_site_mac_table_run(), its own separate
    column for the same reason last_mac_table_collection is separate
    from last_cdp_discovery: this only advances when tunnel collection
    itself actually ran, not on every unrelated CDP walk. This is
    site-level "was this site's tunnel data ever collected at all"
    staleness - a DIFFERENT, more granular signal than
    tunnel_links.last_confirmed, which tracks each individual tunnel
    pairing's own freshness (a backup tunnel can go stale on its own
    without the whole site's collection being stale).
    """
    conn.execute("UPDATE sites SET last_tunnel_collection = ? WHERE id = ?", (_now(), site_id))


# ---------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------

def _resolve_alias_hostname(conn, site_id: int, hostname: str):
    """If `hostname` is NOT the exact name of a real device at this
    site but IS a recorded alias (left behind by merge_devices()),
    return the canonical hostname of the device it points at. Returns
    None otherwise - including whenever a real device already has this
    exact name, which always wins over an alias.
    """
    if conn.execute(
        "SELECT 1 FROM devices WHERE site_id = ? AND hostname = ?", (site_id, hostname)
    ).fetchone():
        return None
    row = conn.execute(
        """
        SELECT d.hostname FROM device_aliases a
        JOIN devices d ON d.id = a.device_id
        WHERE a.site_id = ? AND a.hostname = ?
        """,
        (site_id, hostname),
    ).fetchone()
    return row["hostname"] if row else None


def upsert_device(
    conn,
    site_id: int,
    hostname: str,
    mgmt_ip: str = None,
    platform: str = None,
    serial_number: str = None,
    source: str = "cdp",
    raw_source_data: str = None,
) -> int:
    """Insert or refresh a device seen at a site. Returns device_id.

    serial_number is optional in V1 - plain CDP neighbor data doesn't
    carry it. It's here so a later enrichment pass (show inventory/SNMP)
    can populate it without a schema change, since it's the one field
    that survives a hostname rename or re-IP.

    Rank-aware like record_device_ip(): if this device already exists
    from a higher-priority source (e.g. inventory_sync) and this call
    is a lower-priority one (e.g. cdp re-discovering it), source/
    platform/serial_number are NOT downgraded - only last_seen
    refreshes. Without this, a CDP walk re-discovering an
    inventory-known device would silently overwrite trusted data with
    whatever CDP happens to report about it.
    """
    # A name left behind by a past merge resolves to the surviving
    # device instead of creating the duplicate again (see
    # device_aliases in SCHEMA).
    canonical = _resolve_alias_hostname(conn, site_id, hostname)
    if canonical is not None:
        hostname = canonical

    existing = conn.execute(
        "SELECT source FROM devices WHERE site_id = ? AND hostname = ?", (site_id, hostname)
    ).fetchone()

    if existing is not None and _source_rank(source) < _source_rank(existing["source"]):
        conn.execute(
            "UPDATE devices SET last_seen = ? WHERE site_id = ? AND hostname = ?",
            (_now(), site_id, hostname),
        )
    else:
        conn.execute(
            """
            INSERT INTO devices (site_id, hostname, mgmt_ip, platform, serial_number, source, last_seen, raw_source_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(site_id, hostname) DO UPDATE SET
                mgmt_ip         = excluded.mgmt_ip,
                platform        = excluded.platform,
                serial_number   = excluded.serial_number,
                source          = excluded.source,
                last_seen       = excluded.last_seen,
                raw_source_data = excluded.raw_source_data
            """,
            (site_id, hostname, mgmt_ip, platform, serial_number, source, _now(), raw_source_data),
        )

    row = conn.execute(
        "SELECT id FROM devices WHERE site_id = ? AND hostname = ?",
        (site_id, hostname),
    ).fetchone()
    return row["id"]


def touch_device_seen(conn, device_id: int) -> None:
    """Refresh a device's last_seen without touching anything else.

    A CDP walk logs into each device it visits, but the only
    last_seen refreshes it did were for NEIGHBORS (upsert_device on
    each CDP entry). A device nobody else lists as a neighbor - the
    only device at a one-device site, or one whose neighbors don't
    report it - was reached successfully every run and still aged out.
    The walk calls this for every device it actually connects to.
    """
    conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (_now(), device_id))


def get_devices_for_site(conn, site_id: int):
    return conn.execute(
        "SELECT * FROM devices WHERE site_id = ? AND deleted_at IS NULL ORDER BY hostname", (site_id,)
    ).fetchall()


def add_device_manual(
    conn, site_id: int, hostname: str, mgmt_ip: str = None, platform: str = None
) -> int:
    """User-initiated "Add Device" (Site Manager GUI). Thin wrapper
    around upsert_device() + logging, same reasoning as
    add_site_manual(): upsert_device() itself is called on every
    ordinary CDP/inventory pass and must stay silent, so the log entry
    lives here instead, on the one path that represents a person
    typing a device in by hand.

    source="manual" is fixed here (not a parameter) - manually-added
    devices sit at the bottom of upsert_device()'s source-priority
    ranking (see _source_rank()), so a later real CDP or inventory
    discovery of the same hostname correctly supersedes this row's
    platform/serial/source instead of a hand-typed placeholder
    permanently blocking real data from ever winning.

    If this device was previously soft-deleted, re-adding it by the
    same hostname at the same site revives it (deleted_at cleared),
    matching add_site_manual()'s revival behavior.
    """
    device_id = upsert_device(conn, site_id, hostname, mgmt_ip=mgmt_ip, platform=platform, source="manual")
    conn.execute("UPDATE devices SET deleted_at = NULL WHERE id = ?", (device_id,))
    log_activity(
        "add_device", f"{hostname} ({mgmt_ip or 'no IP'}) added to site id {site_id}", conn=conn
    )
    return device_id


def _soft_delete_device_no_log(conn, device_id: int):
    """Core soft-delete logic for ONE device, without its own logging
    call - shared by soft_delete_device() (a single-device delete,
    logs once) and soft_delete_site() (a whole-site delete that
    cascades to every device under it, but should still log ONCE for
    the site action, not once per device - matching the same "log the
    user's intent, not the underlying machinery" principle used
    everywhere else in the app). If this device is currently flagged
    as its site's CDP seed or ARP seed, that reference is cleared
    automatically (the site just reverts to "no seed set") rather than
    leaving a hidden device still referenced by a site that would
    otherwise try to use it for discovery. Returns the device's row as
    it was just before deletion, or None if it didn't exist / was
    already deleted.
    """
    row = conn.execute(
        "SELECT site_id, hostname, mgmt_ip, is_seed, is_arp_seed FROM devices WHERE id = ? AND deleted_at IS NULL",
        (device_id,),
    ).fetchone()
    if row is None:
        return None

    conn.execute("UPDATE devices SET deleted_at = ? WHERE id = ?", (_now(), device_id))
    if row["is_seed"]:
        conn.execute("UPDATE sites SET seed_device = NULL WHERE id = ?", (row["site_id"],))
    if row["is_arp_seed"]:
        conn.execute("UPDATE sites SET arp_seed_device = NULL WHERE id = ?", (row["site_id"],))
    return dict(row)


def soft_delete_device(conn, device_id: int) -> None:
    """Hides a device from every listing/lookup in the app without
    deleting its row or any history attached to it (links, ARP,
    clients, phone enrichment) - reversible by design, see the
    deleted_at columns' schema comment. A future helper script/
    function can restore or permanently purge soft-deleted rows; no
    such tool exists yet, on purpose - this is a one-way hide for now.
    """
    row = _soft_delete_device_no_log(conn, device_id)
    if row is None:
        return
    log_activity("delete_device", f"{row['hostname']} ({row['mgmt_ip'] or 'no IP'}) soft-deleted", conn=conn)


def get_device_delete_impact(conn, device_id: int) -> dict:
    """Counts of what references this device, for a delete
    confirmation - counts only, not full detail (the device itself is
    identified by name/IP in the confirmation UI; links/clients are
    just "how much is riding on this", not something worth listing
    individually).
    """
    links = conn.execute(
        "SELECT COUNT(*) AS c FROM links WHERE device_a_id = ? OR device_b_id = ?", (device_id, device_id)
    ).fetchone()["c"]
    clients = conn.execute(
        "SELECT COUNT(*) AS c FROM clients WHERE device_id = ?", (device_id,)
    ).fetchone()["c"]
    return {"links": links, "clients": clients}


def get_site_delete_impact(conn, site_id: int) -> dict:
    """Device list (hostname + mgmt_ip) plus aggregate link/client
    counts for a site-delete confirmation - devices are listed
    individually since their identity matters, links/clients are just
    counted since only the scale of what's affected matters there.
    """
    devices = conn.execute(
        "SELECT id, hostname, mgmt_ip FROM devices WHERE site_id = ? AND deleted_at IS NULL ORDER BY hostname",
        (site_id,),
    ).fetchall()
    device_ids = [d["id"] for d in devices]
    if device_ids:
        placeholders = ",".join("?" * len(device_ids))
        links = conn.execute(
            f"SELECT COUNT(*) AS c FROM links WHERE device_a_id IN ({placeholders}) OR device_b_id IN ({placeholders})",
            device_ids + device_ids,
        ).fetchone()["c"]
        clients = conn.execute(
            f"SELECT COUNT(*) AS c FROM clients WHERE device_id IN ({placeholders})", device_ids,
        ).fetchone()["c"]
    else:
        links = 0
        clients = 0
    return {"devices": [dict(d) for d in devices], "links": links, "clients": clients}


def soft_delete_site(conn, site_id: int) -> None:
    """Hides a site AND every device under it - reversible by design,
    same as soft_delete_device(). Logs once for the whole action
    regardless of how many devices it cascades to.
    """
    site_row = conn.execute(
        "SELECT site_octet FROM sites WHERE id = ? AND deleted_at IS NULL", (site_id,)
    ).fetchone()
    if site_row is None:
        return

    device_ids = [
        r["id"] for r in conn.execute(
            "SELECT id FROM devices WHERE site_id = ? AND deleted_at IS NULL", (site_id,)
        ).fetchall()
    ]
    for device_id in device_ids:
        _soft_delete_device_no_log(conn, device_id)

    conn.execute("UPDATE sites SET deleted_at = ? WHERE id = ?", (_now(), site_id))

    log_activity(
        "delete_site", f"Site {site_row['site_octet']} and {len(device_ids)} device(s) soft-deleted", conn=conn,
    )


def get_device_id_by_hostname(conn, site_id: int, hostname: str):
    """Look up a device's id by hostname without touching its row - used
    when you already know a device exists (e.g. the seed, or a device
    discovered earlier in the same walk) and just need its id, without
    risking an upsert overwriting fields you don't have fresh data for.
    Returns None if not found.
    """
    canonical = _resolve_alias_hostname(conn, site_id, hostname)
    if canonical is not None:
        hostname = canonical
    row = conn.execute(
        "SELECT id FROM devices WHERE site_id = ? AND hostname = ?", (site_id, hostname)
    ).fetchone()
    return row["id"] if row else None


def get_device_by_hostname(conn, site_id: int, hostname: str):
    """Same lookup as get_device_id_by_hostname, but returns the full
    row instead of just the id - used when a caller needs more than
    the id (e.g. the orchestrator's platform-substring connection
    fast-path, which needs the device's known platform too).
    """
    canonical = _resolve_alias_hostname(conn, site_id, hostname)
    if canonical is not None:
        hostname = canonical
    return conn.execute(
        "SELECT * FROM devices WHERE site_id = ? AND hostname = ?", (site_id, hostname)
    ).fetchone()


def update_device_mgmt_ip(conn, device_id: int, mgmt_ip: str) -> None:
    """Narrow update: refresh just mgmt_ip and last_seen, without
    touching any other field. Used when the actually-reachable IP
    differs from what CDP originally reported for a device - e.g. a
    connection fallback to entry_ip succeeded after the reported
    mgmt_ip failed.
    """
    conn.execute("UPDATE devices SET mgmt_ip = ?, last_seen = ? WHERE id = ?", (mgmt_ip, _now(), device_id))


def set_device_platform(conn, device_id: int, platform: str, source: str = "manual") -> None:
    """Narrow update: set just platform (and source/last_seen), without
    touching mgmt_ip/serial_number/raw_source_data. Used for manually
    correcting known-bad platform data from an inventory tool (e.g.
    "Unsupported Cisco Device"). Defaults source to 'manual' - the
    highest rank in _SOURCE_RANK - so the correction is protected from
    being silently overwritten by a future same-or-lower-rank re-sync.
    """
    conn.execute("UPDATE devices SET platform = ?, source = ?, last_seen = ? WHERE id = ?", (platform, source, _now(), device_id))


def set_device_as_seed(conn, site_id: int, device_id: int) -> None:
    """Flag a device as the CDP discovery seed for its site.

    Clears any existing seed flag for the site first, so exactly one
    device per site is ever marked as seed. Also mirrors the hostname
    into sites.seed_device for convenience/readability.
    """
    conn.execute("UPDATE devices SET is_seed = 0 WHERE site_id = ?", (site_id,))
    conn.execute("UPDATE devices SET is_seed = 1 WHERE id = ? AND site_id = ?", (device_id, site_id))
    hostname_row = conn.execute("SELECT hostname FROM devices WHERE id = ?", (device_id,)).fetchone()
    if hostname_row:
        conn.execute("UPDATE sites SET seed_device = ? WHERE id = ?", (hostname_row["hostname"], site_id))

    hostname = hostname_row["hostname"] if hostname_row else f"device {device_id}"
    site_row = conn.execute("SELECT site_octet FROM sites WHERE id = ?", (site_id,)).fetchone()
    site_label = site_row["site_octet"] if site_row else f"site {site_id}"
    log_activity("set_cdp_seed", f"{hostname} set as CDP seed for site {site_label}", conn=conn)


def get_seed_device_for_site(conn, site_id: int):
    """Return the device row flagged as seed for a site, or None if unset."""
    return conn.execute(
        "SELECT * FROM devices WHERE site_id = ? AND is_seed = 1", (site_id,)
    ).fetchone()


def set_device_as_arp_seed(conn, site_id: int, device_id: int) -> None:
    """Flag a device as the ARP-collection seed for its site - only
    needed when it should differ from the regular CDP seed (e.g. the
    CDP seed isn't a router, or doesn't hold the ARP table you want).
    Most sites will never call this; get_arp_seed_device_for_site()
    falls back to the CDP seed automatically when no override is set.

    Clears any existing ARP-seed flag for the site first, so at most
    one device per site is ever marked. Also mirrors the hostname into
    sites.arp_seed_device for convenience/readability.
    """
    conn.execute("UPDATE devices SET is_arp_seed = 0 WHERE site_id = ?", (site_id,))
    conn.execute("UPDATE devices SET is_arp_seed = 1 WHERE id = ? AND site_id = ?", (device_id, site_id))
    hostname_row = conn.execute("SELECT hostname FROM devices WHERE id = ?", (device_id,)).fetchone()
    if hostname_row:
        conn.execute("UPDATE sites SET arp_seed_device = ? WHERE id = ?", (hostname_row["hostname"], site_id))

    hostname = hostname_row["hostname"] if hostname_row else f"device {device_id}"
    site_row = conn.execute("SELECT site_octet FROM sites WHERE id = ?", (site_id,)).fetchone()
    site_label = site_row["site_octet"] if site_row else f"site {site_id}"
    log_activity("set_arp_seed", f"{hostname} set as ARP seed for site {site_label}", conn=conn)


def clear_device_as_arp_seed(conn, site_id: int) -> None:
    """Remove any ARP-seed override for a site, reverting it to using
    the regular CDP seed by default.
    """
    conn.execute("UPDATE devices SET is_arp_seed = 0 WHERE site_id = ?", (site_id,))
    conn.execute("UPDATE sites SET arp_seed_device = NULL WHERE id = ?", (site_id,))

    site_row = conn.execute("SELECT site_octet FROM sites WHERE id = ?", (site_id,)).fetchone()
    site_label = site_row["site_octet"] if site_row else f"site {site_id}"
    log_activity("clear_arp_seed", f"ARP seed override cleared for site {site_label}", conn=conn)


def get_arp_seed_device_for_site(conn, site_id: int):
    """Return the device to poll for ARP data at a site: the explicit
    ARP-seed override if one is set, otherwise the regular CDP seed.
    Returns None only if neither is set.
    """
    override = conn.execute(
        "SELECT * FROM devices WHERE site_id = ? AND is_arp_seed = 1", (site_id,)
    ).fetchone()
    if override is not None:
        return override
    return get_seed_device_for_site(conn, site_id)


def set_device_arp_override_ip(conn, device_id: int, ip: str) -> None:
    """Set (or clear, if ip is None/empty) a device's arp_override_ip -
    an address tried first during ARP collection specifically, before
    falling through to the device's normal ranked IPs. For the shared-
    VIP case (e.g. an HSRP/VRRP pair): set this identically on BOTH
    real devices in the pair, not just whichever is currently flagged
    is_arp_seed - that way, if the seed flag ever moves to the other
    device (a refresh, a manual switch), the override is already in
    place and nothing has to be reconfigured.
    """
    conn.execute("UPDATE devices SET arp_override_ip = ? WHERE id = ?", (ip or None, device_id))

    hostname_row = conn.execute("SELECT hostname FROM devices WHERE id = ?", (device_id,)).fetchone()
    hostname = hostname_row["hostname"] if hostname_row else f"device {device_id}"
    detail = f"ARP override IP for {hostname} set to {ip}" if ip else f"ARP override IP cleared for {hostname}"
    log_activity("set_arp_override_ip", detail, conn=conn)


def set_device_marked_stale(conn, device_id: int, stale: bool) -> None:
    """Manually flag (or clear) a device as stale - independent of, and
    complementary to, the automatic age-based staleness check (a
    device's last_seen vs. its site's last_cdp_discovery - see
    dashboard_generate.py's _is_stale()). This exists for the gap the
    automatic rule can't cover on its own: a device can only look
    "missing from a later scan" once a later scan actually exists, so
    on a young deployment (or a site simply not rescanned in a while)
    the timer has nothing to compare against yet, even if you already
    know from direct knowledge that something is gone.

    Links get no flag of their own at all - a link's manual staleness
    is always derived (computed fresh, not stored) from whether either
    of its two endpoint devices is marked, so there's nothing to keep
    in sync if a device later gets un-marked.
    """
    conn.execute("UPDATE devices SET marked_stale_at = ? WHERE id = ?", (_now() if stale else None, device_id))

    hostname_row = conn.execute("SELECT hostname FROM devices WHERE id = ?", (device_id,)).fetchone()
    hostname = hostname_row["hostname"] if hostname_row else f"device {device_id}"
    detail = f"{hostname} manually marked stale" if stale else f"{hostname} stale flag cleared"
    log_activity("set_marked_stale", detail, conn=conn)


def auto_seed_singleton_sites(conn) -> list:
    """Flag the seed device for any site that has exactly one device and
    doesn't already have a seed set. No guessing involved - there's only
    one candidate, so this is safe to run automatically (unlike sites
    with multiple devices, where seed choice stays a manual call).

    Returns a list of (site_row, device_row) for everything it flagged,
    so callers can report what happened.
    """
    flagged = []
    for site in get_all_sites(conn):
        if get_seed_device_for_site(conn, site["id"]) is not None:
            continue  # already has a seed
        devices = get_devices_for_site(conn, site["id"])
        if len(devices) == 1:
            set_device_as_seed(conn, site["id"], devices[0]["id"])
            flagged.append((site, devices[0]))
    return flagged


# ---------------------------------------------------------------------
# Device IPs (ranked history - see module docstring for why this exists)
# ---------------------------------------------------------------------

# Higher wins. Sources not listed here (shouldn't normally happen) rank
# below everything, rather than erroring.
_SOURCE_RANK = {"manual": 3, "inventory_sync": 2, "cdp": 1}


def _source_rank(source: str) -> int:
    return _SOURCE_RANK.get(source, 0)


def _get_site_reference_ip(conn, site_id: int):
    """A real, representative IP for a site, used only to compare
    first-two-octet similarity when ranking a device's candidate IPs -
    NOT a site identifier itself (site_octet only stores the second
    octet, never the first, so it can't be used for this directly).
    Prefers the site's seed device's IP; falls back to any device's
    mgmt_ip at the site. Returns None if the site has no IPs at all yet.
    """
    seed = get_seed_device_for_site(conn, site_id)
    if seed and seed["mgmt_ip"]:
        return seed["mgmt_ip"]
    row = conn.execute(
        "SELECT mgmt_ip FROM devices WHERE site_id = ? AND mgmt_ip IS NOT NULL LIMIT 1",
        (site_id,),
    ).fetchone()
    return row["mgmt_ip"] if row else None


def get_best_ip_for_device(conn, device_id: int, reference_ip: str = None) -> str:
    """Return the best candidate IP for a device from its device_ips
    history: highest source rank first, then (as a tie-breaker) whether
    the IP's first two octets match reference_ip's. Returns None if the
    device has no recorded IPs at all.
    """
    rows = conn.execute(
        "SELECT ip, source FROM device_ips WHERE device_id = ?", (device_id,)
    ).fetchall()
    if not rows:
        return None

    ref_prefix = None
    if reference_ip:
        parts = reference_ip.split(".")
        if len(parts) >= 2:
            ref_prefix = f"{parts[0]}.{parts[1]}."

    def sort_key(row):
        octet_match = 1 if (ref_prefix and row["ip"].startswith(ref_prefix)) else 0
        return (_source_rank(row["source"]), octet_match)

    ranked = sorted(rows, key=sort_key, reverse=True)
    return ranked[0]["ip"]


def get_ips_for_device(conn, device_id: int):
    """All recorded IPs for a device, highest-ranked first (same
    ordering logic as get_best_ip_for_device, without collapsing to
    just one result) - useful for a connection step that wants to try
    every known IP in order rather than just the top pick.
    """
    reference_ip = None
    device = conn.execute("SELECT site_id FROM devices WHERE id = ?", (device_id,)).fetchone()
    if device:
        reference_ip = _get_site_reference_ip(conn, device["site_id"])

    rows = conn.execute(
        "SELECT ip, source FROM device_ips WHERE device_id = ?", (device_id,)
    ).fetchall()

    ref_prefix = None
    if reference_ip:
        parts = reference_ip.split(".")
        if len(parts) >= 2:
            ref_prefix = f"{parts[0]}.{parts[1]}."

    def sort_key(row):
        octet_match = 1 if (ref_prefix and row["ip"].startswith(ref_prefix)) else 0
        return (_source_rank(row["source"]), octet_match)

    return [row["ip"] for row in sorted(rows, key=sort_key, reverse=True)]


def _refresh_cached_mgmt_ip(conn, device_id: int) -> None:
    """Recompute devices.mgmt_ip from device_ips and write the cache.
    Internal - called automatically by record_device_ip(); nothing else
    should need to call this directly.
    """
    device = conn.execute("SELECT site_id FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device:
        return
    reference_ip = _get_site_reference_ip(conn, device["site_id"])
    best = get_best_ip_for_device(conn, device_id, reference_ip=reference_ip)
    if best:
        conn.execute("UPDATE devices SET mgmt_ip = ? WHERE id = ?", (best, device_id))


def record_device_ip(conn, device_id: int, ip: str, source: str, raw_source_data: str = None) -> None:
    """Record an observed IP for a device. Never destructively
    overwrites - if this exact IP is already known for this device,
    its source is only upgraded (never downgraded) to whatever ranks
    higher, and last_seen always refreshes either way. Automatically
    recomputes and updates the device's cached mgmt_ip afterward.

    This is the ONLY function that should feed device_ips - nothing
    else should INSERT/UPDATE that table directly.
    """
    if not ip:
        return

    existing = conn.execute(
        "SELECT source FROM device_ips WHERE device_id = ? AND ip = ?", (device_id, ip)
    ).fetchone()

    if existing is None:
        conn.execute(
            "INSERT INTO device_ips (device_id, ip, source, last_seen, raw_source_data) VALUES (?, ?, ?, ?, ?)",
            (device_id, ip, source, _now(), raw_source_data),
        )
    elif _source_rank(source) >= _source_rank(existing["source"]):
        conn.execute(
            "UPDATE device_ips SET source = ?, last_seen = ?, raw_source_data = ? WHERE device_id = ? AND ip = ?",
            (source, _now(), raw_source_data, device_id, ip),
        )
    else:
        # A lower-priority source re-reported an IP we already trust
        # more from elsewhere - keep the existing source tag, but it
        # was still just seen again, so refresh last_seen.
        conn.execute(
            "UPDATE device_ips SET last_seen = ? WHERE device_id = ? AND ip = ?",
            (_now(), device_id, ip),
        )

    _refresh_cached_mgmt_ip(conn, device_id)


# ---------------------------------------------------------------------
# Links (CDP adjacencies)
# ---------------------------------------------------------------------

def upsert_link(
    conn,
    site_id: int,
    device_a_id: int,
    device_b_id: int,
    local_intf: str = None,
    remote_intf: str = None,
    source: str = "cdp",
    raw_source_data: str = None,
) -> int:
    """Insert or refresh a CDP link between two devices. Returns link_id.

    Same-site CDP walks discover most links from BOTH ends (device A
    reports seeing B; device B separately reports seeing A) - which
    would otherwise create two rows for what's really one physical
    cable: (A, B, local=X, remote=Y) and (B, A, local=Y, remote=X).
    Before inserting, check whether the MIRROR of this link (device_a/
    device_b swapped, AND local_intf/remote_intf swapped to match)
    already exists - if so, this is the same cable seen from the other
    end, so just refresh that existing row instead of creating a
    second one. A genuine second physical cable between the same two
    devices always uses a different port on at least one end, so it's
    never mistaken for this case.
    """
    mirror = conn.execute(
        """
        SELECT id FROM links
        WHERE site_id = ? AND device_a_id = ? AND device_b_id = ?
          AND IFNULL(local_intf, '') = IFNULL(?, '')
          AND IFNULL(remote_intf, '') = IFNULL(?, '')
        """,
        (site_id, device_b_id, device_a_id, remote_intf, local_intf),
    ).fetchone()
    if mirror is not None:
        conn.execute(
            "UPDATE links SET source = ?, last_seen = ?, raw_source_data = ? WHERE id = ?",
            (source, _now(), raw_source_data, mirror["id"]),
        )
        return mirror["id"]

    conn.execute(
        """
        INSERT INTO links (site_id, device_a_id, device_b_id, local_intf, remote_intf, source, last_seen, raw_source_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(site_id, device_a_id, device_b_id, local_intf, remote_intf) DO UPDATE SET
            source          = excluded.source,
            last_seen       = excluded.last_seen,
            raw_source_data = excluded.raw_source_data
        """,
        (site_id, device_a_id, device_b_id, local_intf, remote_intf, source, _now(), raw_source_data),
    )
    row = conn.execute(
        """
        SELECT id FROM links
        WHERE site_id = ? AND device_a_id = ? AND device_b_id = ?
          AND IFNULL(local_intf, '') = IFNULL(?, '')
          AND IFNULL(remote_intf, '') = IFNULL(?, '')
        """,
        (site_id, device_a_id, device_b_id, local_intf, remote_intf),
    ).fetchone()
    return row["id"]


def get_links_for_site(conn, site_id: int):
    return conn.execute(
        """
        SELECT l.*, da.hostname AS device_a_hostname, db.hostname AS device_b_hostname
        FROM links l
        JOIN devices da ON l.device_a_id = da.id
        JOIN devices db ON l.device_b_id = db.id
        WHERE l.site_id = ? AND da.deleted_at IS NULL AND db.deleted_at IS NULL
        """,
        (site_id,),
    ).fetchall()


# ---------------------------------------------------------------------
# ARP entries
# ---------------------------------------------------------------------

def upsert_arp_entry(
    conn,
    site_id: int,
    ip: str,
    mac: str,
    vrf: str = "",
    device_id: int = None,
    source: str = "cdp",
    raw_source_data: str = None,
) -> int:
    """Insert or refresh an ARP entry for a site. Returns arp entry id.

    vrf defaults to '' (empty string), meaning the global/default
    routing table - deliberately NOT NULL, since SQL treats every NULL
    as distinct from every other NULL for uniqueness purposes, which
    would silently break deduplication for every global-table entry.
    Pass the real VRF name for anything pulled from a specific VRF's
    ARP table.
    """
    conn.execute(
        """
        INSERT INTO arp_entries (site_id, device_id, vrf, ip, mac, source, last_seen, raw_source_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(site_id, vrf, ip, mac) DO UPDATE SET
            device_id       = excluded.device_id,
            source          = excluded.source,
            last_seen       = excluded.last_seen,
            raw_source_data = excluded.raw_source_data
        """,
        (site_id, device_id, vrf, ip, mac, source, _now(), raw_source_data),
    )
    row = conn.execute(
        "SELECT id FROM arp_entries WHERE site_id = ? AND vrf = ? AND ip = ? AND mac = ?",
        (site_id, vrf, ip, mac),
    ).fetchone()
    return row["id"]


def upsert_client(
    conn,
    site_id: int,
    mac: str,
    device_id: int = None,
    interface: str = None,
    vlan: str = None,
    device_type: str = None,
    source: str = "mac-table",
    raw_source_data: str = None,
) -> int:
    """Insert or refresh a client (a MAC seen as a genuine edge/end-
    device port, not an inter-switch link - that decision is made by
    the correlation pass that calls this, not here). One row per MAC
    per site; a MAC already known at this site has its location
    REFRESHED (device/interface/vlan/last_seen/mac's own stored
    formatting all overwritten with the latest values) rather than
    creating a second row - "last processed wins" is the deliberate,
    accepted behavior here, matching how a real L2 network's own MAC
    tables self-correct as old entries age out, rather than something
    this needs to resolve itself.

    Compares MACs via mac_parser.normalize_mac() rather than a plain
    string match, since the same physical MAC can be reported in
    different separator styles/case across platforms and even
    different commands on the same platform - a raw string comparison
    would otherwise silently treat one real device as two separate
    client rows. This is why the actual matching happens here in
    Python rather than via the schema's UNIQUE(site_id, mac) alone,
    which only catches an exact raw-string repeat.

    device_type (e.g. "cisco_phone", set via a separate CDP-based
    correlation step, not from the MAC table itself) is preserved
    across a later refresh that doesn't provide one - a plain MAC-
    table sighting with no type info shouldn't erase a type already
    learned from CDP.
    """
    normalized_new = mac_parser.normalize_mac(mac)

    existing = conn.execute(
        "SELECT id, mac FROM clients WHERE site_id = ?", (site_id,)
    ).fetchall()
    match_id = None
    for row in existing:
        if mac_parser.normalize_mac(row["mac"]) == normalized_new:
            match_id = row["id"]
            break

    if match_id is not None:
        conn.execute(
            """
            UPDATE clients
            SET mac = ?, device_id = ?, interface = ?, vlan = ?,
                device_type = COALESCE(?, device_type),
                source = ?, last_seen = ?, raw_source_data = ?
            WHERE id = ?
            """,
            (mac, device_id, interface, vlan, device_type, source, _now(), raw_source_data, match_id),
        )
        return match_id

    cur = conn.execute(
        """
        INSERT INTO clients (site_id, mac, device_id, interface, vlan, device_type, source, last_seen, raw_source_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (site_id, mac, device_id, interface, vlan, device_type, source, _now(), raw_source_data),
    )
    return cur.lastrowid


def get_clients_for_site(conn, site_id: int):
    return conn.execute(
        """
        SELECT clients.* FROM clients
        LEFT JOIN devices ON clients.device_id = devices.id
        WHERE clients.site_id = ? AND (devices.deleted_at IS NULL OR clients.device_id IS NULL)
        ORDER BY clients.mac
        """,
        (site_id,),
    ).fetchall()


def get_all_clients(conn):
    """Every client across every site, unfiltered beyond hiding
    anything attached to a soft-deleted device - callers filter by
    device_type or anything else as needed (e.g. the CUCM/VTC
    enrichment script only cares about 'cisco_phone'/'vtc' rows, but
    this stays a plain, general-purpose accessor rather than baking
    that specific filter in here).
    """
    return conn.execute(
        """
        SELECT clients.* FROM clients
        LEFT JOIN devices ON clients.device_id = devices.id
        WHERE devices.deleted_at IS NULL OR clients.device_id IS NULL
        ORDER BY clients.mac
        """
    ).fetchall()


def stage_mac_table_raw(conn, site_id: int, device_id: int, raw_output: str) -> None:
    """Stages a device's raw 'show mac address-table' output for a
    later correlation pass (see mac_table_raw's own schema comment for
    why this can't be decided mid-walk). One row per device - a later
    collection for the same device REPLACES its previous staged
    output, not accumulated as history.
    """
    conn.execute(
        """
        INSERT INTO mac_table_raw (site_id, device_id, raw_output, collected_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            site_id      = excluded.site_id,
            raw_output   = excluded.raw_output,
            collected_at = excluded.collected_at
        """,
        (site_id, device_id, raw_output, _now()),
    )


def get_staged_mac_tables_for_site(conn, site_id: int):
    return conn.execute(
        "SELECT * FROM mac_table_raw WHERE site_id = ?", (site_id,)
    ).fetchall()


def upsert_phone_enrichment_status(conn, mac: str, device_name: str, ris_ip: str, ris_status: str,
                                    phone_number: str = None) -> None:
    """Refreshes the FAST, always-current fields from RIS's bulk query
    (IP + registration status + directory number) - meant to be called
    for every tracked phone/VTC on every enrichment script run,
    regardless of whether model/serial are already known for that MAC.
    Deliberately has no skip logic at all: ris_status can genuinely
    flip over time (a device going from Registered to Unregistered and
    back), and phone_number can too (an extension gets reassigned), so
    both need to stay current every run, unlike the slower per-device
    pull below. Creates the row if this MAC has never been enriched
    before.
    """
    mac = mac_parser.normalize_mac(mac)
    conn.execute(
        """
        INSERT INTO phone_enrichment (mac, device_name, ris_ip, ris_status, phone_number)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            device_name  = excluded.device_name,
            ris_ip       = excluded.ris_ip,
            ris_status   = excluded.ris_status,
            phone_number = excluded.phone_number
        """,
        (mac, device_name, ris_ip, ris_status, phone_number),
    )


def record_phone_serial_pull(conn, mac: str, model: str = None, serial_number: str = None) -> None:
    """Records the outcome of a per-device model/serial pull attempt
    against a phone_enrichment row that already exists (created first
    by upsert_phone_enrichment_status(), which always runs before this
    for every tracked device). Always stamps last_attempted, whether
    or not the pull actually returned anything - that's what lets a
    permanently-unreachable legacy device get tried exactly once
    rather than retried on every future run. last_enriched is only
    stamped when the pull genuinely returned a model and/or serial,
    distinguishing "we tried and got nothing" from "we tried and got
    something real." A None model/serial here leaves any existing
    value in place (COALESCE) rather than blanking out a previously-
    known value with nothing.
    """
    mac = mac_parser.normalize_mac(mac)
    now = _now()
    got_something = bool(model or serial_number)
    conn.execute(
        """
        UPDATE phone_enrichment
        SET model          = COALESCE(?, model),
            serial_number  = COALESCE(?, serial_number),
            last_attempted = ?,
            last_enriched  = CASE WHEN ? THEN ? ELSE last_enriched END
        WHERE mac = ?
        """,
        (model, serial_number, now, got_something, now, mac),
    )


def get_phone_enrichment(conn, mac: str):
    mac = mac_parser.normalize_mac(mac)
    return conn.execute("SELECT * FROM phone_enrichment WHERE mac = ?", (mac,)).fetchone()


def get_all_phone_enrichment(conn):
    return conn.execute("SELECT * FROM phone_enrichment").fetchall()


def get_arp_for_site(conn, site_id: int):
    return conn.execute(
        """
        SELECT arp_entries.* FROM arp_entries
        LEFT JOIN devices ON arp_entries.device_id = devices.id
        WHERE arp_entries.site_id = ? AND (devices.deleted_at IS NULL OR arp_entries.device_id IS NULL)
        ORDER BY arp_entries.vrf, arp_entries.ip
        """,
        (site_id,),
    ).fetchall()



# ---------------------------------------------------------------------
# Device merge support (used by merge_duplicate_devices.py)
# ---------------------------------------------------------------------
# These exist for the one specific case where two device rows turn out
# to be the same physical device (e.g. a real inventory-known device
# and a CDP-discovered duplicate that got filed under the wrong site).
# Merging is: migrate history, repoint references,
# then delete the now-childless duplicate row. Foreign keys are
# enforced, so a duplicate can't be deleted while device_ips/links/
# arp_entries still reference it - these functions exist to clear
# those references first.

def get_device_ip_rows(conn, device_id: int):
    """Raw device_ips rows (ip, source, raw_source_data) for a device -
    used to replay a duplicate's IP history into the real device via
    record_device_ip(), so source-priority ranking is respected rather
    than just copied blindly.
    """
    return conn.execute(
        "SELECT ip, source, raw_source_data FROM device_ips WHERE device_id = ?", (device_id,)
    ).fetchall()


def delete_device_ip_rows(conn, device_id: int) -> None:
    conn.execute("DELETE FROM device_ips WHERE device_id = ?", (device_id,))


def get_links_referencing_device(conn, device_id: int):
    """Every link row where this device appears as either side."""
    return conn.execute(
        "SELECT * FROM links WHERE device_a_id = ? OR device_b_id = ?", (device_id, device_id)
    ).fetchall()


def delete_link(conn, link_id: int) -> None:
    conn.execute("DELETE FROM links WHERE id = ?", (link_id,))


def reassign_arp_entries_device(conn, old_device_id: int, new_device_id: int) -> None:
    """Repoint arp_entries.device_id from old to new. No conflict risk -
    device_id isn't part of arp_entries' uniqueness key (site_id, ip,
    mac), so this is a plain reassignment, not an upsert.
    """
    conn.execute("UPDATE arp_entries SET device_id = ? WHERE device_id = ?", (new_device_id, old_device_id))


def delete_device(conn, device_id: int) -> None:
    """Delete a device row outright. Caller must have already migrated
    or removed any device_ips/links/arp_entries referencing it first -
    foreign keys are enforced, so this raises if child rows remain.
    """
    conn.execute("DELETE FROM device_aliases WHERE device_id = ?", (device_id,))
    # Config history belongs to the device row; a merged-away duplicate's
    # snapshots are dropped with it (the survivor pulls its own).
    conn.execute("DELETE FROM config_snapshots WHERE device_id = ?", (device_id,))
    conn.execute("DELETE FROM config_pull_status WHERE device_id = ?", (device_id,))
    conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))


# ---------------------------------------------------------------------
# Running-config snapshots
# ---------------------------------------------------------------------

# Newest snapshots kept per device (the baseline is kept on top of this).
CONFIG_SNAPSHOTS_KEEP = 30
# Mirrors dashboard_generate's STALE_THRESHOLD_DAYS (kept here so the
# collector does not have to import the dashboard generator).
CONFIG_SKIP_STALE_DAYS = 60


def hash_config_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _config_stale_reason(device, site_last_cdp):
    """Why a config pull would skip this device as stale, or None. Stale =
    marked stale by hand (note: being reached by CDP does NOT clear that
    mark), or last seen CONFIG_SKIP_STALE_DAYS or more before the site's
    last CDP discovery."""
    if device["marked_stale_at"]:
        return "manually marked stale"
    if not device["last_seen"] or not site_last_cdp:
        return None
    try:
        seen = datetime.fromisoformat(device["last_seen"])
        scan = datetime.fromisoformat(site_last_cdp)
        days = (scan - seen).days
    except (ValueError, TypeError):
        return None
    return f"last seen {days} days before the site's last CDP scan" if days >= CONFIG_SKIP_STALE_DAYS else None


def get_config_targets(conn, site_id: int, include_stale: bool = False, skipped: list = None) -> list:
    """Live devices at a site to pull a config from, as plain dicts:
    id, hostname, platform, ips (ranked, best first) and latest_hash
    (hash of the newest stored snapshot, or None). Aged/manually-stale
    devices are skipped unless include_stale; if a list is passed as
    `skipped`, a (hostname, reason) pair is appended for each one."""
    site = get_site_by_id(conn, site_id)
    site_last_cdp = site["last_cdp_discovery"] if site else None
    targets = []
    for d in get_devices_for_site(conn, site_id):
        reason = _config_stale_reason(d, site_last_cdp)
        if reason and not include_stale:
            if skipped is not None:
                skipped.append((d["hostname"], reason))
            continue
        row = conn.execute(
            "SELECT content_hash FROM config_snapshots WHERE device_id = ? ORDER BY id DESC LIMIT 1", (d["id"],)
        ).fetchone()
        targets.append({
            "id": d["id"], "hostname": d["hostname"], "platform": d["platform"],
            "ips": get_ips_for_device(conn, d["id"]),
            "latest_hash": row["content_hash"] if row else None,
        })
    return targets


def record_config_pull_result(conn, device_id: int, ok: bool, error: str = None,
                              changed_at: str = None, changed_by: str = None, nvram_updated: str = None) -> None:
    """Note the outcome of one config pull. On success the device's own
    reported last-change metadata is refreshed and any old error cleared;
    on failure only the attempt time and error change."""
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        return  # device was purged since this was queued
    now = _now()
    conn.execute("INSERT INTO config_pull_status (device_id) VALUES (?) ON CONFLICT(device_id) DO NOTHING", (device_id,))
    if ok:
        conn.execute(
            """UPDATE config_pull_status SET last_attempt_at = ?, last_success_at = ?, last_error = NULL,
                   device_changed_at = ?, device_changed_by = ?, device_nvram_updated = ?
               WHERE device_id = ?""",
            (now, now, changed_at, changed_by, nvram_updated, device_id),
        )
    else:
        conn.execute(
            "UPDATE config_pull_status SET last_attempt_at = ?, last_error = ? WHERE device_id = ?",
            (now, (error or "unknown error")[:500], device_id),
        )


def record_config_snapshot(conn, device_id: int, config_text: str, changed_at: str = None,
                           changed_by: str = None, nvram_updated: str = None,
                           keep: int = CONFIG_SNAPSHOTS_KEEP) -> dict:
    """Store a cleaned running-config as a new snapshot unless it is
    identical to the device's newest one. The first snapshot ever stored
    for a device is flagged is_baseline and never pruned; beyond that
    only the newest `keep` snapshots are retained. Also records a
    successful pull. Returns {"stored", "snapshot_id", "pruned"}."""
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        return {"stored": False, "snapshot_id": None, "pruned": 0}
    content_hash = hash_config_text(config_text)
    latest = conn.execute(
        "SELECT id, content_hash FROM config_snapshots WHERE device_id = ? ORDER BY id DESC LIMIT 1", (device_id,)
    ).fetchone()
    record_config_pull_result(conn, device_id, True, changed_at=changed_at, changed_by=changed_by,
                              nvram_updated=nvram_updated)
    if latest is not None and latest["content_hash"] == content_hash:
        return {"stored": False, "snapshot_id": latest["id"], "pruned": 0}

    raw = config_text.encode("utf-8")
    cur = conn.execute(
        """INSERT INTO config_snapshots
               (device_id, collected_at, content_hash, config_z, size_bytes, line_count,
                changed_at, changed_by, nvram_updated, is_baseline)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (device_id, _now(), content_hash, zlib.compress(raw, 9), len(raw), config_text.count("\n"),
         changed_at, changed_by, nvram_updated, 1 if latest is None else 0),
    )
    pruned = conn.execute(
        """DELETE FROM config_snapshots
           WHERE device_id = ? AND is_baseline = 0
             AND id NOT IN (SELECT id FROM config_snapshots WHERE device_id = ? ORDER BY id DESC LIMIT ?)""",
        (device_id, device_id, keep),
    ).rowcount
    return {"stored": True, "snapshot_id": cur.lastrowid, "pruned": pruned}


def get_config_snapshots(conn, device_id: int):
    """Snapshot metadata (no config text), newest first."""
    return conn.execute(
        """SELECT id, collected_at, content_hash, size_bytes, line_count, changed_at, changed_by,
                  nvram_updated, is_baseline
           FROM config_snapshots WHERE device_id = ? ORDER BY id DESC""",
        (device_id,),
    ).fetchall()


def get_config_snapshot_text(conn, snapshot_id: int):
    row = conn.execute("SELECT config_z FROM config_snapshots WHERE id = ?", (snapshot_id,)).fetchone()
    return zlib.decompress(row["config_z"]).decode("utf-8") if row else None


# ---------------------------------------------------------------------
# GEM One KG (TACLANE) devices - see the kg_* tables in SCHEMA
# ---------------------------------------------------------------------

def _kg_clean(value):
    """Stripped text, or None when the value is missing or blank."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _kg_date(value, warnings: list, serial: str, field: str):
    """A YYYY-MM-DD string (a longer date/time is cut to its date), or None
    with a warning when the value is present but not a real date."""
    text = _kg_clean(value)
    if text is None:
        return None
    try:
        datetime.strptime(text[:10], "%Y-%m-%d")
        return text[:10]
    except ValueError:
        warnings.append(f"{serial}: {field} '{text[:30]}' is not a YYYY-MM-DD date, stored as empty")
        return None


def _kg_bool(value):
    """1 / 0 for a true or false value (a real boolean, or the text true/false),
    else None (unknown)."""
    if isinstance(value, bool):
        return 1 if value else 0
    text = _kg_clean(value)
    if text is None:
        return None
    text = text.lower()
    if text in ("true", "yes", "1"):
        return 1
    if text in ("false", "no", "0"):
        return 0
    return None


def _kg_timestamp(value):
    """A timestamp as normalized UTC ISO text, or None if it cannot be read."""
    text = _kg_clean(value)
    if text is None:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


_KG_FIELDS = (
    ("system_name", "systemName"), ("device_type", "type"), ("state", "state"),
    ("software_version", "softwareVersion"), ("pt_ip", "ptIpAddress"), ("ct_ip", "ctIpAddress"),
    ("pt_mac", "ptMacAddress"), ("ct_mac", "ctMacAddress"),
    ("pt_status", "ptOperationalStatus"), ("ct_status", "ctOperationalStatus"),
)


def import_kg_snapshot(conn, data: dict, source: str = None, force: bool = False) -> dict:
    """Applies one gemone_full_pull.py output file (already parsed from JSON)
    to the kg_* tables. Matching is by serial number: new serials are added,
    known ones updated (their security associations replaced wholesale), and
    serials missing from the file are NOT deleted, only marked missing_since.
    A device listed under the file's "errors" keeps its old data and gets
    last_error set instead. Returns a summary dict.

    Refuses a file older than the last import, or one listing no devices at
    all (that would mark everything missing), unless force=True."""
    if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
        raise ValueError("GEM One data must be an object with a 'devices' list")
    now = _now()
    collected = _kg_timestamp(data.get("collected_at")) or now
    last = conn.execute("SELECT file_collected_at FROM kg_imports ORDER BY id DESC LIMIT 1").fetchone()
    if not force:
        if last is not None and last["file_collected_at"] and collected < last["file_collected_at"]:
            raise ValueError(
                f"This file was collected at {collected}, which is older than the last import "
                f"({last['file_collected_at']}). Use force to import it anyway.")
        if not data["devices"] and not (data.get("errors") or []):
            raise ValueError("The file lists no devices. Importing it would mark every KG as missing. "
                             "Use force to import it anyway.")

    summary = {"file_collected_at": collected, "added": 0, "updated": 0, "reactivated": 0, "skipped": 0,
               "errors": 0, "missing": 0, "associations": 0, "unmapped": [], "warnings": [],
               "took_over": [], "possible_matches": []}
    warnings = summary["warnings"]
    site_map = {r["serial_number"]: r["site_id"] for r in conn.execute("SELECT serial_number, site_id FROM kg_site_map")}
    known = get_site_by_octet(conn, UNASSIGNED_SITE_OCTET)
    unassigned = [known["id"] if known is not None else None]

    def unassigned_id():
        if unassigned[0] is None:
            unassigned[0] = get_or_create_unassigned_site(conn)
        return unassigned[0]

    seen = set()
    for raw in data["devices"]:
        serial = _kg_clean(raw.get("serialNumber")) if isinstance(raw, dict) else None
        if not serial:
            summary["skipped"] += 1
            warnings.append("a device entry with no serialNumber was skipped")
            continue
        if serial in seen:
            warnings.append(f"{serial}: listed more than once, the last entry was used")
        seen.add(serial)

        values = {col: _kg_clean(raw.get(key)) for col, key in _KG_FIELDS}
        values["ffvs_exp_date"] = _kg_date(raw.get("currFfvsExpDate"), warnings, serial, "currFfvsExpDate")
        values["battery_change_date"] = _kg_date(raw.get("neBatteryChangeDate"), warnings, serial, "neBatteryChangeDate")

        existing = conn.execute("SELECT * FROM kg_devices WHERE serial_number = ?", (serial,)).fetchone()
        site_id = site_map.get(serial) or (existing["site_id"] if existing is not None and existing["site_id"] else None)
        if site_id is None:
            site_id = unassigned_id()
        if site_id == unassigned[0]:
            summary["unmapped"].append(serial)
        values["site_id"] = site_id
        values["data_collected_at"] = collected
        values["last_seen"] = now

        if existing is None:
            cols = ["serial_number", "first_seen"] + list(values)
            cur = conn.execute(
                f"INSERT INTO kg_devices ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
                [serial, now] + [values[c] for c in values])
            kg_id = cur.lastrowid
            summary["added"] += 1
            # A new GEM One unit that shares an IP with a hand-entered one is
            # probably the same physical unit. Reported, never merged by itself
            # (IP addresses get reused).
            ips = [ip for ip in (values.get("pt_ip"), values.get("ct_ip")) if ip]
            if ips:
                marks = ", ".join("?" for _ in ips)
                for m in conn.execute(
                        f"SELECT serial_number FROM kg_devices WHERE source = 'manual' AND deleted_at IS NULL "
                        f"AND (pt_ip IN ({marks}) OR ct_ip IN ({marks}))", ips + ips).fetchall():
                    summary["possible_matches"].append((serial, m["serial_number"]))
            if values["state"]:
                conn.execute("INSERT INTO kg_state_log (kg_id, at, old_state, new_state) VALUES (?, ?, NULL, ?)",
                             (kg_id, now, values["state"]))
        else:
            kg_id = existing["id"]
            if existing["deleted_at"]:
                summary["reactivated"] += 1
            if existing["source"] == "manual":
                summary["took_over"].append(serial)   # GEM One data now owns this unit
            sets = ", ".join(f"{c} = ?" for c in values)
            conn.execute(
                f"UPDATE kg_devices SET {sets}, source = 'gemone', missing_since = NULL, last_error = NULL, "
                f"last_error_at = NULL, deleted_at = NULL WHERE id = ?", [values[c] for c in values] + [kg_id])
            summary["updated"] += 1
            if (existing["state"] or None) != values["state"]:
                conn.execute("INSERT INTO kg_state_log (kg_id, at, old_state, new_state) VALUES (?, ?, ?, ?)",
                             (kg_id, now, existing["state"], values["state"]))

        assoc = raw.get("securityAssociations")
        if assoc is not None and not isinstance(assoc, list):
            warnings.append(f"{serial}: securityAssociations is not a list, ignored")
            assoc = []
        conn.execute("DELETE FROM kg_security_associations WHERE kg_id = ?", (kg_id,))
        rows = []
        for a in assoc or []:
            if not isinstance(a, dict):
                continue
            rows.append((kg_id, _kg_clean(a.get("remoteCtAddress")), _kg_clean(a.get("remotePtAddress")),
                         _kg_clean(a.get("establishmentMethod")), _kg_bool(a.get("pairReachable"))))
        conn.executemany(
            "INSERT INTO kg_security_associations (kg_id, remote_ct, remote_pt, method, pair_reachable) "
            "VALUES (?, ?, ?, ?, ?)", rows)
        summary["associations"] += len(rows)

    error_serials = set()
    for e in data.get("errors") or []:
        serial = _kg_clean(e.get("serialNumber")) if isinstance(e, dict) else None
        if not serial:
            continue
        error_serials.add(serial)
        summary["errors"] += 1
        message = (_kg_clean(e.get("error")) or "lookup failed")[:300]
        conn.execute("UPDATE kg_devices SET last_error = ?, last_error_at = ?, missing_since = NULL "
                     "WHERE serial_number = ?", (message, now, serial))

    present = seen | error_serials
    # Hand-entered units are never in a GEM One file, so they are never "missing".
    for row in conn.execute(
            "SELECT id, serial_number FROM kg_devices WHERE deleted_at IS NULL AND source != 'manual'").fetchall():
        if row["serial_number"] not in present:
            conn.execute("UPDATE kg_devices SET missing_since = COALESCE(missing_since, ?) WHERE id = ?", (now, row["id"]))
            summary["missing"] += 1

    conn.execute(
        "INSERT INTO kg_imports (imported_at, file_collected_at, source, device_count, added, updated, errors, missing) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (now, collected, source, len(seen), summary["added"], summary["updated"], summary["errors"], summary["missing"]))
    log_activity("import_kg", f"GEM One file: {summary['added']} added, {summary['updated']} updated, "
                 f"{summary['errors']} errors, {summary['missing']} missing", conn=conn)
    return summary


def set_kg_site(conn, serial_number: str, site_id: int) -> None:
    """Assigns a KG to a site by serial number. The assignment is remembered
    in kg_site_map, so later imports keep it."""
    serial = _kg_clean(serial_number)
    if not serial:
        raise ValueError("A serial number is required")
    if conn.execute("SELECT 1 FROM sites WHERE id = ?", (site_id,)).fetchone() is None:
        raise ValueError(f"No site with id {site_id}")
    conn.execute("INSERT INTO kg_site_map (serial_number, site_id) VALUES (?, ?) "
                 "ON CONFLICT(serial_number) DO UPDATE SET site_id = excluded.site_id", (serial, site_id))
    conn.execute("UPDATE kg_devices SET site_id = ? WHERE serial_number = ?", (site_id, serial))
    log_activity("set_kg_site", f"KG {serial} assigned to site id {site_id}", conn=conn)


def import_kg_site_map(conn, rows: list) -> dict:
    """Bulk-loads serial-to-site assignments. rows: [{"serial": ..., "site": <site octet>}].
    A site value that matches no known site is reported, not applied."""
    summary = {"applied": 0, "unknown_site": [], "skipped": 0}
    for r in rows:
        serial = _kg_clean(r.get("serial")) if isinstance(r, dict) else None
        octet = _kg_clean(r.get("site")) if isinstance(r, dict) else None
        if not serial or not octet:
            summary["skipped"] += 1
            continue
        site = get_site_by_octet(conn, octet)
        if site is None:
            summary["unknown_site"].append((serial, octet))
            continue
        conn.execute("INSERT INTO kg_site_map (serial_number, site_id) VALUES (?, ?) "
                     "ON CONFLICT(serial_number) DO UPDATE SET site_id = excluded.site_id", (serial, site["id"]))
        conn.execute("UPDATE kg_devices SET site_id = ? WHERE serial_number = ?", (site["id"], serial))
        summary["applied"] += 1
    log_activity("import_kg_site_map", f"{summary['applied']} KG site assignment(s) loaded", conn=conn)
    return summary


def soft_delete_kg_device(conn, serial_number: str) -> None:
    """Hides a KG from the pages. It comes back by itself if a later file lists it again."""
    conn.execute("UPDATE kg_devices SET deleted_at = ? WHERE serial_number = ? AND deleted_at IS NULL",
                 (_now(), _kg_clean(serial_number)))
    log_activity("delete_kg", f"KG {serial_number} hidden", conn=conn)


# ---------------------------------------------------------------------
# KG units entered by hand (source = 'manual')
#
# For a TACLANE/ViaSat that is up and working but that GEM One cannot see.
# Only the type is required: the unit exists so the security-association
# tables can show a name for it instead of "not in SAD". The match is by
# PT/CT IP address, so those are worth filling in when known.
# ---------------------------------------------------------------------

def _kg_check_ip(value, label: str):
    text = _kg_clean(value)
    if text is None:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        raise ValueError(f"{label} '{text}' is not a valid IP address") from None
    return text


def _kg_check_date(value, label: str):
    text = _kg_clean(value)
    if text is None:
        return None
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"{label} must be a date written YYYY-MM-DD") from None
    return text


def _kg_ip_conflict(conn, ips, exclude_id=None) -> None:
    """Raises when another KG already uses one of these IPs (the SA peer
    lookup keeps only one unit per IP, so a shared IP would show the wrong name)."""
    ips = [ip for ip in ips if ip]
    if not ips:
        return
    marks = ", ".join("?" for _ in ips)
    rows = conn.execute(
        f"SELECT id, serial_number, system_name, pt_ip, ct_ip FROM kg_devices WHERE deleted_at IS NULL "
        f"AND (pt_ip IN ({marks}) OR ct_ip IN ({marks}))", ips + ips).fetchall()
    for r in rows:
        if exclude_id is not None and r["id"] == exclude_id:
            continue
        shared = sorted({ip for ip in ips if ip in (r["pt_ip"], r["ct_ip"])})
        raise ValueError(f"{', '.join(shared)} is already used by {r['system_name'] or r['serial_number']} "
                         f"({r['serial_number']}). Each IP can belong to only one KG.")


def _kg_next_serial(conn, device_type: str) -> str:
    """'<type>-<n>' with n one above the highest used for this type. Removed
    units count too, so a number is never handed out twice."""
    pattern = re.compile(r"^" + re.escape(device_type) + r"-(\d+)$", re.IGNORECASE)
    highest = 0
    for r in conn.execute("SELECT serial_number FROM kg_devices").fetchall():
        m = pattern.match(r["serial_number"])
        if m:
            highest = max(highest, int(m.group(1)))
    return f"{device_type}-{highest + 1}"


def _kg_manual_validate(conn, device_type, site_id, pt_ip, ct_ip, ffvs_exp_date, battery_change_date,
                        requested_serial, editing_serial=None):
    """Every check an add or edit has to pass, with no writes. Returns
    (existing_row_or_None, cleaned_values, final_serial_or_None); raises
    ValueError with a plain message. final_serial is None only for an add
    with no serial given (one is generated when the add is applied)."""
    row = None
    if editing_serial:
        serial = _kg_clean(editing_serial)
        row = conn.execute("SELECT * FROM kg_devices WHERE serial_number = ?", (serial,)).fetchone()
        if row is None:
            raise ValueError(f"No KG with serial {serial}")
        if row["source"] != "manual":
            raise ValueError(f"{serial} comes from GEM One and cannot be edited here")
    device_type = _kg_clean(device_type)
    if not device_type:
        raise ValueError("A type is required")
    values = {
        "device_type": device_type,
        "pt_ip": _kg_check_ip(pt_ip, "PT IP"),
        "ct_ip": _kg_check_ip(ct_ip, "CT IP"),
        "ffvs_exp_date": _kg_check_date(ffvs_exp_date, "KEYMAT expiry"),
        "battery_change_date": _kg_check_date(battery_change_date, "Battery change date"),
    }
    _kg_ip_conflict(conn, [values["pt_ip"], values["ct_ip"]], exclude_id=row["id"] if row is not None else None)
    requested = _kg_clean(requested_serial)
    if row is not None:
        final = requested or row["serial_number"]
        if final != row["serial_number"] and conn.execute(
                "SELECT 1 FROM kg_devices WHERE serial_number = ?", (final,)).fetchone():
            raise ValueError(f"A KG with serial {final} already exists")
    else:
        final = requested
        if final and conn.execute("SELECT 1 FROM kg_devices WHERE serial_number = ?", (final,)).fetchone():
            raise ValueError(f"A KG with serial {final} already exists (it may have been removed; "
                             f"a removed unit comes back when a GEM One file lists it).")
    if site_id is not None and conn.execute("SELECT 1 FROM sites WHERE id = ?", (site_id,)).fetchone() is None:
        raise ValueError(f"No site with id {site_id}")
    return row, values, final


def check_manual_kg(conn, device_type, site_id=None, pt_ip=None, ct_ip=None, ffvs_exp_date=None,
                    battery_change_date=None, serial_number=None, editing_serial=None):
    """The checks an add/edit would have to pass, without writing anything.
    Returns None if it would be accepted, else the problem as plain text.
    The GUI calls this before queueing the write, so a mistake in the form
    never reaches the write queue (a queued write that fails is kept there
    and retried on every drain)."""
    try:
        _kg_manual_validate(conn, device_type, site_id, pt_ip, ct_ip, ffvs_exp_date, battery_change_date,
                            serial_number, editing_serial)
    except ValueError as e:
        return str(e)
    return None


def add_manual_kg(conn, device_type: str, site_id: int = None, system_name: str = None, pt_ip: str = None,
                  ct_ip: str = None, serial_number: str = None, state: str = None, software_version: str = None,
                  ffvs_exp_date: str = None, battery_change_date: str = None) -> str:
    """Adds a hand-entered KG and returns its serial number. Only device_type
    is required; a blank serial_number is generated as '<type>-<n>'."""
    _row, v, serial = _kg_manual_validate(conn, device_type, site_id, pt_ip, ct_ip, ffvs_exp_date,
                                          battery_change_date, serial_number)
    if not serial:
        serial = _kg_next_serial(conn, v["device_type"])
    actual_site = site_id if site_id is not None else get_or_create_unassigned_site(conn)
    now = _now()
    state = _kg_clean(state)
    cur = conn.execute(
        "INSERT INTO kg_devices (serial_number, site_id, system_name, device_type, state, software_version, "
        "pt_ip, ct_ip, ffvs_exp_date, battery_change_date, first_seen, last_seen, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual')",
        (serial, actual_site, _kg_clean(system_name), v["device_type"], state, _kg_clean(software_version),
         v["pt_ip"], v["ct_ip"], v["ffvs_exp_date"], v["battery_change_date"], now, now))
    if site_id is not None:
        conn.execute("INSERT INTO kg_site_map (serial_number, site_id) VALUES (?, ?) "
                     "ON CONFLICT(serial_number) DO UPDATE SET site_id = excluded.site_id", (serial, site_id))
    if state:
        conn.execute("INSERT INTO kg_state_log (kg_id, at, old_state, new_state) VALUES (?, ?, NULL, ?)",
                     (cur.lastrowid, now, state))
    log_activity("add_manual_kg", f"KG {serial} ({v['device_type']}) added by hand", conn=conn)
    return serial


def update_manual_kg(conn, serial_number: str, device_type: str, site_id: int = None, system_name: str = None,
                     pt_ip: str = None, ct_ip: str = None, new_serial_number: str = None, state: str = None,
                     software_version: str = None, ffvs_exp_date: str = None,
                     battery_change_date: str = None) -> str:
    """Rewrites every editable field of a hand-entered KG (blank = empty) and
    returns its serial, which changes if new_serial_number is given. GEM One
    units cannot be edited here (their data belongs to the pull)."""
    row, v, final_serial = _kg_manual_validate(conn, device_type, site_id, pt_ip, ct_ip, ffvs_exp_date,
                                               battery_change_date, new_serial_number, editing_serial=serial_number)
    serial = row["serial_number"]
    actual_site = site_id if site_id is not None else get_or_create_unassigned_site(conn)
    state = _kg_clean(state)
    conn.execute(
        "UPDATE kg_devices SET serial_number = ?, site_id = ?, system_name = ?, device_type = ?, state = ?, "
        "software_version = ?, pt_ip = ?, ct_ip = ?, ffvs_exp_date = ?, battery_change_date = ?, last_seen = ? "
        "WHERE id = ?",
        (final_serial, actual_site, _kg_clean(system_name), v["device_type"], state, _kg_clean(software_version),
         v["pt_ip"], v["ct_ip"], v["ffvs_exp_date"], v["battery_change_date"], _now(), row["id"]))
    conn.execute("DELETE FROM kg_site_map WHERE serial_number = ?", (serial,))
    if site_id is not None:
        conn.execute("INSERT INTO kg_site_map (serial_number, site_id) VALUES (?, ?) "
                     "ON CONFLICT(serial_number) DO UPDATE SET site_id = excluded.site_id", (final_serial, site_id))
    if (row["state"] or None) != state:
        conn.execute("INSERT INTO kg_state_log (kg_id, at, old_state, new_state) VALUES (?, ?, ?, ?)",
                     (row["id"], _now(), row["state"], state))
    log_activity("edit_manual_kg", f"KG {serial} edited" + (f", serial now {final_serial}" if final_serial != serial else ""),
                 conn=conn)
    return final_serial


def get_kg_devices(conn, site_id: int = None, include_deleted: bool = False):
    """KG rows (with the site's octet/name and association counts), by name."""
    where, params = [], []
    if site_id is not None:
        where.append("k.site_id = ?")
        params.append(site_id)
    if not include_deleted:
        where.append("k.deleted_at IS NULL")
    sql = (
        "SELECT k.*, s.site_octet, s.site_name, "
        "  (SELECT COUNT(*) FROM kg_security_associations a WHERE a.kg_id = k.id) AS assoc_total, "
        "  (SELECT COUNT(*) FROM kg_security_associations a WHERE a.kg_id = k.id AND a.pair_reachable = 0) AS assoc_unreachable "
        "FROM kg_devices k LEFT JOIN sites s ON s.id = k.site_id "
        + ("WHERE " + " AND ".join(where) + " " if where else "")
        + "ORDER BY LOWER(COALESCE(k.system_name, k.serial_number)), k.serial_number"
    )
    return conn.execute(sql, params).fetchall()


def get_kg_associations(conn, kg_id: int):
    return conn.execute(
        "SELECT remote_ct, remote_pt, method, pair_reachable FROM kg_security_associations "
        "WHERE kg_id = ? ORDER BY pair_reachable IS NULL, pair_reachable, remote_ct", (kg_id,)).fetchall()


def get_kg_last_import(conn):
    """The most recent import's row (imported_at, file_collected_at, counts) or None."""
    return conn.execute("SELECT * FROM kg_imports ORDER BY id DESC LIMIT 1").fetchone()


# ---------------------------------------------------------------------
# Device merge
# ---------------------------------------------------------------------

def _newest(*timestamps):
    """Latest of several ISO-8601 timestamps (all produced by _now(), so
    plain string comparison orders them correctly), ignoring None."""
    present = [t for t in timestamps if t]
    return max(present) if present else None


def _merge_check(conn, duplicate_id: int, target_id: int):
    dup = conn.execute("SELECT * FROM devices WHERE id = ?", (duplicate_id,)).fetchone()
    tgt = conn.execute("SELECT * FROM devices WHERE id = ?", (target_id,)).fetchone()
    if dup is None or tgt is None:
        raise ValueError("One of the devices no longer exists - refresh and try again.")
    if duplicate_id == target_id:
        raise ValueError("Pick two different devices.")
    if dup["site_id"] != tgt["site_id"]:
        raise ValueError("Both devices must be at the same site.")
    if dup["deleted_at"] or tgt["deleted_at"]:
        raise ValueError("Can't merge a deleted device.")
    return dup, tgt


def merge_devices(conn, duplicate_id: int, target_id: int, keep_hostname: str = "target",
                  dry_run: bool = False) -> dict:
    """Merge a duplicate device INTO a target device (same site), then
    remove the duplicate. The target is the survivor: its row, id and
    seed/stale/etc. state stay; everything that pointed at the
    duplicate is moved onto it.

    What moves, table by table (every table that references
    devices(id) is covered - foreign keys are enforced, so a missed one
    would make the final delete fail and roll the whole merge back):
      - device_ips: re-parented with last_seen preserved; an IP both
        devices had keeps the higher-ranked source and newer last_seen.
        Cached mgmt_ip is recomputed afterward.
      - links: re-pointed onto the target. A link that becomes
        equivalent to one the target already has (checked in BOTH
        orientations, same as upsert_link()) is merged into it; a link
        between the duplicate and the target themselves is dropped (a
        device can't link to itself).
      - arp_entries, clients: re-pointed.
      - mac_table_raw (one row per device): the newer collection wins.
      - tunnel_interfaces: re-pointed; same interface on both keeps the
        newer. tunnel_links is DERIVED data, so rows owned by the
        duplicate are cleared and match_tunnels() rebuilds from the
        merged interfaces.
      - device_aliases: any pointing at the duplicate move to the target.
      - Target's own platform/serial_number/arp_override_ip are kept;
        only blanks are filled from the duplicate. last_seen becomes the
        newer of the two (which is what clears the "not seen" stale
        flag). The duplicate's manual stale mark is NOT carried over.
      - CDP/ARP seed flags transfer to the target if the duplicate held
        them (and the sites.seed_device/arp_seed_device hostname mirrors
        are kept in step with the final hostname).

    keep_hostname: "target" (default) keeps the target's name;
    "duplicate" renames the target to the duplicate's name. Either way
    the name that is NOT kept is recorded in device_aliases, so the next
    discovery/inventory run that reports it lands on the survivor
    instead of re-creating the duplicate.

    dry_run=True performs the exact same work and then ROLLS BACK the
    connection's open transaction, returning the same summary - so a
    preview can never disagree with the real thing. Use a dedicated
    connection for it (anything else uncommitted on the connection is
    rolled back too).

    Returns a plain-JSON summary dict (counts per table, final
    hostname, seed transfers, filled fields). Raises ValueError for a
    bad pairing; any other failure propagates and, under get_conn(),
    means nothing was committed.
    """
    if keep_hostname not in ("target", "duplicate"):
        raise ValueError("keep_hostname must be 'target' or 'duplicate'.")
    dup, tgt = _merge_check(conn, duplicate_id, target_id)
    site_id = tgt["site_id"]
    dup_name, tgt_name = dup["hostname"], tgt["hostname"]

    summary = {
        "duplicate_hostname": dup_name, "target_hostname": tgt_name,
        "final_hostname": tgt_name if keep_hostname == "target" else dup_name,
        "ips_moved": 0, "ips_merged": 0,
        "links_moved": 0, "links_merged": 0, "links_dropped": 0,
        "arp_moved": 0, "clients_moved": 0,
        "mac_tables_moved": 0, "mac_tables_merged": 0,
        "tunnel_interfaces_moved": 0, "tunnel_interfaces_merged": 0, "tunnel_links_cleared": 0,
        "fields_filled": [], "seed_transferred": False, "arp_seed_transferred": False,
        "dry_run": bool(dry_run),
    }

    # --- device_ips ---
    tgt_ips = {r["ip"]: r for r in conn.execute("SELECT * FROM device_ips WHERE device_id = ?", (target_id,))}
    for r in conn.execute("SELECT * FROM device_ips WHERE device_id = ?", (duplicate_id,)).fetchall():
        existing = tgt_ips.get(r["ip"])
        if existing is None:
            conn.execute("UPDATE device_ips SET device_id = ? WHERE id = ?", (target_id, r["id"]))
            summary["ips_moved"] += 1
            continue
        newest = _newest(existing["last_seen"], r["last_seen"])
        if _source_rank(r["source"]) > _source_rank(existing["source"]):
            conn.execute(
                "UPDATE device_ips SET source = ?, raw_source_data = ?, last_seen = ? WHERE id = ?",
                (r["source"], r["raw_source_data"], newest, existing["id"]),
            )
        else:
            conn.execute("UPDATE device_ips SET last_seen = ? WHERE id = ?", (newest, existing["id"]))
        conn.execute("DELETE FROM device_ips WHERE id = ?", (r["id"],))
        summary["ips_merged"] += 1
    _refresh_cached_mgmt_ip(conn, target_id)

    # --- links ---
    for link in conn.execute(
        "SELECT * FROM links WHERE device_a_id = ? OR device_b_id = ?", (duplicate_id, duplicate_id)
    ).fetchall():
        a = target_id if link["device_a_id"] == duplicate_id else link["device_a_id"]
        b = target_id if link["device_b_id"] == duplicate_id else link["device_b_id"]
        if a == b:
            conn.execute("DELETE FROM links WHERE id = ?", (link["id"],))
            summary["links_dropped"] += 1
            continue
        equivalent = conn.execute(
            """
            SELECT id, last_seen FROM links
            WHERE id != ? AND site_id = ? AND (
                (device_a_id = ? AND device_b_id = ?
                  AND IFNULL(local_intf, '') = IFNULL(?, '') AND IFNULL(remote_intf, '') = IFNULL(?, ''))
             OR (device_a_id = ? AND device_b_id = ?
                  AND IFNULL(local_intf, '') = IFNULL(?, '') AND IFNULL(remote_intf, '') = IFNULL(?, ''))
            )
            """,
            (link["id"], link["site_id"],
             a, b, link["local_intf"], link["remote_intf"],
             b, a, link["remote_intf"], link["local_intf"]),
        ).fetchone()
        if equivalent is not None:
            conn.execute(
                "UPDATE links SET last_seen = ? WHERE id = ?",
                (_newest(equivalent["last_seen"], link["last_seen"]), equivalent["id"]),
            )
            conn.execute("DELETE FROM links WHERE id = ?", (link["id"],))
            summary["links_merged"] += 1
        else:
            conn.execute("UPDATE links SET device_a_id = ?, device_b_id = ? WHERE id = ?", (a, b, link["id"]))
            summary["links_moved"] += 1

    # --- arp_entries / clients ---
    summary["arp_moved"] = conn.execute(
        "UPDATE arp_entries SET device_id = ? WHERE device_id = ?", (target_id, duplicate_id)
    ).rowcount
    summary["clients_moved"] = conn.execute(
        "UPDATE clients SET device_id = ? WHERE device_id = ?", (target_id, duplicate_id)
    ).rowcount

    # --- mac_table_raw (UNIQUE(device_id)) ---
    dup_mt = conn.execute("SELECT * FROM mac_table_raw WHERE device_id = ?", (duplicate_id,)).fetchone()
    if dup_mt is not None:
        tgt_mt = conn.execute("SELECT * FROM mac_table_raw WHERE device_id = ?", (target_id,)).fetchone()
        if tgt_mt is None:
            conn.execute("UPDATE mac_table_raw SET device_id = ? WHERE id = ?", (target_id, dup_mt["id"]))
            summary["mac_tables_moved"] = 1
        else:
            if (dup_mt["collected_at"] or "") > (tgt_mt["collected_at"] or ""):
                conn.execute("DELETE FROM mac_table_raw WHERE id = ?", (tgt_mt["id"],))
                conn.execute("UPDATE mac_table_raw SET device_id = ? WHERE id = ?", (target_id, dup_mt["id"]))
            else:
                conn.execute("DELETE FROM mac_table_raw WHERE id = ?", (dup_mt["id"],))
            summary["mac_tables_merged"] = 1

    # --- tunnel_interfaces (UNIQUE(device_id, interface)) + derived tunnel_links ---
    tgt_tunnels = {
        r["interface"]: r
        for r in conn.execute("SELECT * FROM tunnel_interfaces WHERE device_id = ?", (target_id,))
    }
    for r in conn.execute("SELECT * FROM tunnel_interfaces WHERE device_id = ?", (duplicate_id,)).fetchall():
        existing = tgt_tunnels.get(r["interface"])
        if existing is None:
            conn.execute("UPDATE tunnel_interfaces SET device_id = ? WHERE id = ?", (target_id, r["id"]))
            summary["tunnel_interfaces_moved"] += 1
        else:
            if (r["last_seen"] or "") > (existing["last_seen"] or ""):
                conn.execute("DELETE FROM tunnel_interfaces WHERE id = ?", (existing["id"],))
                conn.execute("UPDATE tunnel_interfaces SET device_id = ? WHERE id = ?", (target_id, r["id"]))
            else:
                conn.execute("DELETE FROM tunnel_interfaces WHERE id = ?", (r["id"],))
            summary["tunnel_interfaces_merged"] += 1
    summary["tunnel_links_cleared"] = conn.execute(
        "DELETE FROM tunnel_links WHERE device_a_id = ?", (duplicate_id,)
    ).rowcount
    conn.execute("UPDATE tunnel_links SET device_b_id = ? WHERE device_b_id = ?", (target_id, duplicate_id))
    conn.execute("DELETE FROM tunnel_links WHERE device_a_id = device_b_id")
    if summary["tunnel_interfaces_moved"] or summary["tunnel_interfaces_merged"] or summary["tunnel_links_cleared"]:
        match_tunnels(conn)

    # --- aliases that pointed at the duplicate now point at the target ---
    conn.execute("UPDATE device_aliases SET device_id = ? WHERE device_id = ?", (target_id, duplicate_id))

    # --- fill the target's blanks; take the newer last_seen ---
    updates = {}
    for col in ("platform", "serial_number", "arp_override_ip"):
        if not tgt[col] and dup[col]:
            updates[col] = dup[col]
            summary["fields_filled"].append(col)
    newest_seen = _newest(tgt["last_seen"], dup["last_seen"])
    if newest_seen != tgt["last_seen"]:
        updates["last_seen"] = newest_seen
    if updates:
        set_clause = ", ".join(f"{col} = ?" for col in updates)
        conn.execute(f"UPDATE devices SET {set_clause} WHERE id = ?", (*updates.values(), target_id))

    # --- the duplicate is now childless: remove it (frees its name) ---
    delete_device(conn, duplicate_id)

    # --- final hostname + alias for whichever name is NOT kept ---
    if keep_hostname == "duplicate":
        conn.execute("UPDATE devices SET hostname = ? WHERE id = ?", (dup_name, target_id))
        alias_name = tgt_name
    else:
        alias_name = dup_name
    final_name = summary["final_hostname"]
    conn.execute("DELETE FROM device_aliases WHERE site_id = ? AND hostname = ?", (site_id, final_name))
    conn.execute(
        """
        INSERT INTO device_aliases (site_id, device_id, hostname, created_at) VALUES (?, ?, ?, ?)
        ON CONFLICT(site_id, hostname) DO UPDATE SET device_id = excluded.device_id, created_at = excluded.created_at
        """,
        (site_id, target_id, alias_name, _now()),
    )

    # --- seed flags (and their hostname mirrors on sites) ---
    if dup["is_seed"] and not tgt["is_seed"]:
        set_device_as_seed(conn, site_id, target_id)
        summary["seed_transferred"] = True
    elif tgt["is_seed"] and final_name != tgt_name:
        conn.execute("UPDATE sites SET seed_device = ? WHERE id = ?", (final_name, site_id))
    if dup["is_arp_seed"] and not tgt["is_arp_seed"]:
        set_device_as_arp_seed(conn, site_id, target_id)
        summary["arp_seed_transferred"] = True
    elif tgt["is_arp_seed"] and final_name != tgt_name:
        conn.execute("UPDATE sites SET arp_seed_device = ? WHERE id = ?", (final_name, site_id))

    site_row = conn.execute("SELECT site_octet FROM sites WHERE id = ?", (site_id,)).fetchone()
    log_activity(
        "merge_devices",
        f"Merged '{dup_name}' into '{final_name}' (site {site_row['site_octet'] if site_row else site_id})"
        + (" [dry run]" if dry_run else ""),
        conn=conn,
    )

    if dry_run:
        conn.rollback()
    return summary


def _site_label(site_row) -> str:
    """'octet (name)' for messages and summaries."""
    if site_row is None:
        return "?"
    name = site_row["site_name"]
    return f"{site_row['site_octet']} ({name})" if name else str(site_row["site_octet"])


def move_device_to_site(conn, device_id: int, dest_site_id: int, new_mgmt_ip: str = None,
                        dry_run: bool = False) -> dict:
    """Reassign a device to a different site - mainly for fixing devices
    that discovery filed under Unassigned (often because they were first
    seen via a WAN-facing IP whose octet matched no site).

    What changes: devices.site_id; the device's name aliases follow it;
    its seed flags (and the matching sites.seed_device/arp_seed_device
    mirrors) are cleared at the OLD site, since a device can't seed a
    site it no longer belongs to; and, if new_mgmt_ip is given, that
    address is recorded as a MANUAL ip for the device (highest source
    rank, so it becomes the primary address). The IPs the device already
    had, e.g. the WAN address it was discovered with, are KEPT as lower-
    ranked fallbacks - nothing is removed from device_ips.

    What deliberately does NOT change: links, ARP entries, clients,
    staged MAC tables and tunnel interfaces. Their site_id records the
    site whose scan collected them (not where the device lives), and
    they all reference the device by id, so they stay valid. A later
    scan re-attributes anything that needs it.

    Refuses (ValueError) when the destination already has a LIVE device
    with this name (compared case-insensitively) or a merge alias of
    that name pointing at a live device: that is a duplicate to combine,
    not a device to move. A SOFT-DELETED device holding the name is not
    a blocker - it is renamed to "<name> (deleted #<id>)" so the name is
    free; the row and everything attached to it are kept.

    dry_run=True does all the work and then ROLLS BACK, exactly like
    merge_devices(), so a preview can't disagree with the real move.
    Needs a dedicated connection for the same reason.

    Returns a summary dict (see keys below).
    """
    dev = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if dev is None or dev["deleted_at"]:
        raise ValueError("That device no longer exists - refresh and try again.")
    src_site = conn.execute("SELECT * FROM sites WHERE id = ?", (dev["site_id"],)).fetchone()
    dest_site = get_site_by_id(conn, dest_site_id)
    if dest_site is None:
        raise ValueError("The destination site no longer exists - refresh and try again.")
    if dest_site["id"] == dev["site_id"]:
        raise ValueError("The device is already at that site.")

    hostname = dev["hostname"]
    dest_label = _site_label(dest_site)

    ip = (new_mgmt_ip or "").strip() or None
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ValueError(f"'{new_mgmt_ip.strip()}' is not a valid IP address.") from None

    # A LIVE device with this name at the destination means a real duplicate: refuse. A SOFT-DELETED one
    # (e.g. someone re-added the device by hand there, then deleted that copy) is just squatting on the
    # name - it is renamed out of the way below, not destroyed, so nothing attached to it is lost.
    deleted_clashes = []
    for clash in conn.execute(
        "SELECT id, hostname, deleted_at FROM devices WHERE site_id = ? AND lower(hostname) = lower(?)",
        (dest_site["id"], hostname),
    ).fetchall():
        if not clash["deleted_at"]:
            raise ValueError(
                f"Site {dest_label} already has a device named '{clash['hostname']}'. That looks like the same "
                f"device, so the move was stopped instead of creating a duplicate."
            )
        deleted_clashes.append(clash)
    alias_clash = conn.execute(
        """
        SELECT d.hostname FROM device_aliases a JOIN devices d ON d.id = a.device_id
        WHERE a.site_id = ? AND a.hostname = ? AND d.deleted_at IS NULL
        """,
        (dest_site["id"], hostname),
    ).fetchone()
    if alias_clash is not None:
        raise ValueError(
            f"'{hostname}' is already a known alternate name of '{alias_clash['hostname']}' at site {dest_label}. "
            f"That looks like the same device, so the move was stopped."
        )

    summary = {
        "hostname": hostname,
        "from_site": _site_label(src_site),
        "to_site": dest_label,
        "previous_ip": dev["mgmt_ip"],
        "ip_added": ip,
        "primary_ip": None,
        "ip_is_primary": None,
        "seeds_cleared": [],
        "deleted_renamed": [],
        "aliases_moved": 0,
        "links_left": 0,
        "clients_left": 0,
        "arp_left": 0,
        "dry_run": bool(dry_run),
    }

    # --- free the name: rename any soft-deleted device holding it at the destination ---
    for clash in deleted_clashes:
        new_name = f"{clash['hostname']} (deleted #{clash['id']})"
        conn.execute("UPDATE devices SET hostname = ? WHERE id = ?", (new_name, clash["id"]))
        conn.execute(
            "DELETE FROM device_aliases WHERE site_id = ? AND hostname = ? AND device_id = ?",
            (dest_site["id"], hostname, clash["id"]),
        )
        summary["deleted_renamed"].append(new_name)

    # --- seed flags at the old site ---
    if dev["is_seed"]:
        conn.execute(
            "UPDATE sites SET seed_device = NULL WHERE id = ? AND seed_device = ?", (dev["site_id"], hostname)
        )
        summary["seeds_cleared"].append("CDP seed")
    if dev["is_arp_seed"]:
        conn.execute(
            "UPDATE sites SET arp_seed_device = NULL WHERE id = ? AND arp_seed_device = ?", (dev["site_id"], hostname)
        )
        summary["seeds_cleared"].append("ARP seed")

    # --- the move itself ---
    conn.execute(
        "UPDATE devices SET site_id = ?, is_seed = 0, is_arp_seed = 0 WHERE id = ?",
        (dest_site["id"], device_id),
    )

    # --- aliases follow the device (drop any same-named alias already at the destination first) ---
    alias_rows = conn.execute("SELECT hostname FROM device_aliases WHERE device_id = ?", (device_id,)).fetchall()
    for a in alias_rows:
        conn.execute(
            "DELETE FROM device_aliases WHERE site_id = ? AND hostname = ? AND device_id != ?",
            (dest_site["id"], a["hostname"], device_id),
        )
    conn.execute("UPDATE device_aliases SET site_id = ? WHERE device_id = ?", (dest_site["id"], device_id))
    summary["aliases_moved"] = len(alias_rows)

    # --- management IP: add as manual (keeps every existing IP as a fallback) ---
    if ip:
        record_device_ip(
            conn, device_id, ip, "manual",
            raw_source_data=f"Set by hand when the device was moved to site {dest_label}",
        )
    else:
        # The cached mgmt_ip's tie-breaker depends on the site's reference IP, which just changed.
        _refresh_cached_mgmt_ip(conn, device_id)
    primary = conn.execute("SELECT mgmt_ip FROM devices WHERE id = ?", (device_id,)).fetchone()["mgmt_ip"]
    summary["primary_ip"] = primary
    summary["ip_is_primary"] = (primary == ip) if ip else None

    # --- what stays put (for the preview) ---
    summary["links_left"] = conn.execute(
        "SELECT COUNT(*) AS c FROM links WHERE device_a_id = ? OR device_b_id = ?", (device_id, device_id)
    ).fetchone()["c"]
    summary["clients_left"] = conn.execute(
        "SELECT COUNT(*) AS c FROM clients WHERE device_id = ?", (device_id,)
    ).fetchone()["c"]
    summary["arp_left"] = conn.execute(
        "SELECT COUNT(*) AS c FROM arp_entries WHERE device_id = ?", (device_id,)
    ).fetchone()["c"]

    log_activity(
        "move_device",
        f"Moved '{hostname}' from site {summary['from_site']} to site {dest_label}"
        + (f"; added management IP {ip}" if ip else "")
        + (" [dry run]" if dry_run else ""),
        conn=conn,
    )

    if dry_run:
        conn.rollback()
    return summary


# ---------------------------------------------------------------------
# Tunnel interfaces / tunnel links
# ---------------------------------------------------------------------

def upsert_tunnel_interface(
    conn,
    site_id: int,
    device_id: int,
    interface: str,
    admin_status: str = None,
    line_protocol: str = None,
    description: str = None,
    internet_address: str = None,
    source_ip: str = None,
    source_interface: str = None,
    destination_ip: str = None,
    destination_interface: str = None,
    raw_source_data: str = None,
) -> int:
    """Insert or refresh a device's tunnel interface row (see
    tunnel_parser.py for how these fields are extracted from 'show
    interfaces tunnel <N>' output). One row per device per interface;
    a later collection REPLACES the previous row - same "last
    processed wins" pattern as device_ips/arp_entries.

    source_ip/destination_ip are the fields match_tunnels() actually
    joins on; everything else here is for display/reference only.
    Either can legitimately be None (see tunnel_interfaces' own schema
    comment) - a row like that still gets stored, it just can never be
    matched until/unless it's corrected on a later collection.
    """
    conn.execute(
        """
        INSERT INTO tunnel_interfaces (
            site_id, device_id, interface, admin_status, line_protocol,
            description, internet_address, source_ip, source_interface,
            destination_ip, destination_interface, last_seen, raw_source_data
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id, interface) DO UPDATE SET
            site_id                = excluded.site_id,
            admin_status           = excluded.admin_status,
            line_protocol          = excluded.line_protocol,
            description            = excluded.description,
            internet_address       = excluded.internet_address,
            source_ip              = excluded.source_ip,
            source_interface       = excluded.source_interface,
            destination_ip         = excluded.destination_ip,
            destination_interface  = excluded.destination_interface,
            last_seen              = excluded.last_seen,
            raw_source_data        = excluded.raw_source_data
        """,
        (site_id, device_id, interface, admin_status, line_protocol,
         description, internet_address, source_ip, source_interface,
         destination_ip, destination_interface, _now(), raw_source_data),
    )
    row = conn.execute(
        "SELECT id FROM tunnel_interfaces WHERE device_id = ? AND interface = ?",
        (device_id, interface),
    ).fetchone()
    return row["id"]


def get_tunnel_interfaces_for_site(conn, site_id: int):
    """Every raw tunnel_interfaces row for this site's own devices -
    the source data for a per-site Tunnels panel, unfiltered by
    whether source_ip/destination_ip parsed or matched anything."""
    return conn.execute(
        """
        SELECT tunnel_interfaces.*, devices.hostname AS device_hostname
        FROM tunnel_interfaces
        JOIN devices ON tunnel_interfaces.device_id = devices.id
        WHERE tunnel_interfaces.site_id = ? AND devices.deleted_at IS NULL
        """,
        (site_id,),
    ).fetchall()


def get_all_tunnel_interfaces(conn):
    """Every tunnel_interfaces row that has BOTH source_ip and
    destination_ip - the only rows match_tunnels() can do anything
    with. A row missing one or both (its 'Tunnel source ...,
    destination ...' line didn't parse) is excluded here, not deleted
    - it still shows up in a site's raw tunnel list via
    get_tunnel_interfaces_for_site(), just never as a match candidate.
    """
    return conn.execute(
        "SELECT * FROM tunnel_interfaces WHERE source_ip IS NOT NULL AND destination_ip IS NOT NULL"
    ).fetchall()


def match_tunnels(conn) -> dict:
    """Global correlation pass: for every tunnel_interfaces row with a
    parsed source_ip/destination_ip, look for the mirror-image row
    from a DIFFERENT device (its source_ip/destination_ip swapped
    relative to this one) and record the pairing in tunnel_links.
    Deliberately global rather than per-site - a tunnel's far end is
    very often at a different site than the one just scanned, so this
    has to search the WHOLE tunnel_interfaces table, not just whatever
    site triggered the collection.

    Every eligible tunnel_interfaces row gets its own tunnel_links row
    (as device_a), whether or not a match was found - see
    tunnel_links' own schema comment for why a genuine pair ends up as
    two rows, one from each side, and why a one-sided tunnel is
    deliberately surfaced (device_b_id/device_b_interface left NULL)
    rather than hidden.

    Ambiguous cases (more than one row claims the exact same reverse
    source/destination pair - a real misconfiguration, not expected in
    normal operation) are left one-sided rather than guessed at, and
    counted separately so a caller can report them rather than the
    mismatch going unnoticed.

    Meant to be re-run after every tunnel collection (whether one site
    or the whole fleet) - existing tunnel_links rows are refreshed in
    place via upsert, not accumulated as history.

    Returns {"matched": N, "one_sided": N, "ambiguous": N} counts.
    """
    all_rows = get_all_tunnel_interfaces(conn)

    matched = 0
    one_sided = 0
    ambiguous = 0

    for row in all_rows:
        candidates = [
            other for other in all_rows
            if other["id"] != row["id"]
            and other["device_id"] != row["device_id"]
            and other["source_ip"] == row["destination_ip"]
            and other["destination_ip"] == row["source_ip"]
        ]

        if len(candidates) == 1:
            match = candidates[0]
            device_b_id = match["device_id"]
            device_b_interface = match["interface"]
            matched += 1
        else:
            device_b_id = None
            device_b_interface = None
            if len(candidates) == 0:
                one_sided += 1
            else:
                ambiguous += 1

        conn.execute(
            """
            INSERT INTO tunnel_links (
                device_a_id, device_a_interface, device_b_id, device_b_interface,
                source_ip, destination_ip, last_confirmed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_a_id, device_a_interface) DO UPDATE SET
                device_b_id        = excluded.device_b_id,
                device_b_interface = excluded.device_b_interface,
                source_ip          = excluded.source_ip,
                destination_ip     = excluded.destination_ip,
                last_confirmed     = excluded.last_confirmed
            """,
            (row["device_id"], row["interface"], device_b_id, device_b_interface,
             row["source_ip"], row["destination_ip"], _now()),
        )

    return {"matched": matched, "one_sided": one_sided, "ambiguous": ambiguous}


def get_tunnel_links_for_site(conn, site_id: int):
    """tunnel_links rows for this site's own devices (as device_a) -
    each row is one local tunnel interface and, if matched, who it
    pairs with. See tunnel_links' schema comment for why a genuine
    pair shows up as two independent rows rather than one shared row -
    this only returns this site's own half of any such pair; the far
    site's page shows its own row independently.
    """
    return conn.execute(
        """
        SELECT tunnel_links.*,
               da.hostname AS device_a_hostname,
               dbb.hostname AS device_b_hostname,
               dbb.site_id AS device_b_site_id,
               sb.site_name AS device_b_site_name,
               sb.site_octet AS device_b_site_octet
        FROM tunnel_links
        JOIN devices da ON tunnel_links.device_a_id = da.id
        LEFT JOIN devices dbb ON tunnel_links.device_b_id = dbb.id
        LEFT JOIN sites sb ON dbb.site_id = sb.id
        WHERE da.site_id = ? AND da.deleted_at IS NULL
        """,
        (site_id,),
    ).fetchall()


def get_all_tunnel_links(conn):
    """Every tunnel_links row with both sides' hostname/site resolved
    (device_b's side left NULL for one-sided rows) - the source data
    for the all-site tunnel diagram.
    """
    return conn.execute(
        """
        SELECT tunnel_links.*,
               da.hostname AS device_a_hostname, da.site_id AS device_a_site_id,
               sa.site_name AS device_a_site_name, sa.site_octet AS device_a_site_octet,
               dbb.hostname AS device_b_hostname, dbb.site_id AS device_b_site_id,
               sb.site_name AS device_b_site_name, sb.site_octet AS device_b_site_octet
        FROM tunnel_links
        JOIN devices da ON tunnel_links.device_a_id = da.id
        JOIN sites sa ON da.site_id = sa.id
        LEFT JOIN devices dbb ON tunnel_links.device_b_id = dbb.id
        LEFT JOIN sites sb ON dbb.site_id = sb.id
        WHERE da.deleted_at IS NULL
        """
    ).fetchall()


if __name__ == "__main__":
    # Running this file directly just (re)creates an empty sad.db in the
    # current directory - useful as a sanity check that the schema is valid.
    init_db()
    print(f"Initialized {DB_PATH}")