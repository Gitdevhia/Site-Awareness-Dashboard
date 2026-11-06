"""
dashboard_generate.py - Generates the static HTML dashboard (index page
+ one page per site) directly from sad.db. Reuses utilities/db.py for
every query and utilities/topology_layout.py + topology_svg.py for the
per-site topology diagram - no new query or layout logic lives here,,
this module is purely "fetch data, fill in HTML."

Usage:
    python3 dashboard_generate.py                  # regenerate everything
    python3 dashboard_generate.py --site <key>      # regenerate one site + the index

Run from the project root, same as orchestrator.py and gui.py.
"""

import sys
import os
import re
import json
import argparse
import datetime
import ipaddress

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "utilities"))

import db  # noqa: E402
import topology_layout  # noqa: E402
import topology_svg  # noqa: E402
import site_map_layout  # noqa: E402
import site_map_svg  # noqa: E402
import mac_parser  # noqa: E402
import banner  # noqa: E402
import kg_pages  # noqa: E402

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard")

CSS_TOKENS = """
:root{
  --bg: #0b0f14; --panel: #121821; --panel-2: #182130; --border: #24303f;
  --text: #dbe4ee; --text-dim: #7c8a9a; --accent: #e8a33d; --accent-dim: #7a5a26;
  --up: #3ddc84; --warn: #e85d5d; --radius: 10px;
  --mono: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;
  --sans: 'Segoe UI', Tahoma, Arial, sans-serif;
}
html[data-theme="light"]{
  --bg: #f2f4f7; --panel: #ffffff; --panel-2: #eef1f5; --border: #dbe1e8;
  --text: #1b2531; --text-dim: #6b7684; --accent: #c07a1e; --accent-dim: #f0d6ac;
  --up: #1f9d5c; --warn: #c0392b;
}
"""

THEME_TOGGLE_JS = """
const root = document.documentElement;
const toggleBtn = document.getElementById("theme-toggle");
const saved = localStorage.getItem("sad-theme");
if(saved){ root.setAttribute("data-theme", saved); toggleBtn.textContent = saved === "dark" ? "\\ud83c\\udf19" : "\\u2600\\ufe0f"; }
toggleBtn.addEventListener("click", () => {
  const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
  root.setAttribute("data-theme", next);
  localStorage.setItem("sad-theme", next);
  toggleBtn.textContent = next === "dark" ? "\\ud83c\\udf19" : "\\u2600\\ufe0f";
});
"""

# Plain viewBox manipulation rather than a CSS transform on the <svg>
# element itself - editing the viewBox keeps stroke widths/font sizes
# defined in the SVG's own coordinate space looking correct at any
# zoom level (a CSS transform would visually thicken/thin strokes as
# it scales, unless every stroked element also carried
# vector-effect="non-scaling-stroke", which is more to get right for
# no real benefit here). Only used on site-map.html - conditionally
# runs its setup only if a #map-viewport element is actually present,
# so this same shared script block can also be included harmlessly
# anywhere else THEME_TOGGLE_JS already is.
SITE_MAP_PAN_ZOOM_JS = """
(function(){
  const viewport = document.getElementById("map-viewport");
  if(!viewport) return;
  const svg = document.getElementById("site-map");
  const base = svg.viewBox.baseVal;
  let view = { x: base.x, y: base.y, w: base.width, h: base.height };
  const MIN_W = base.width * 0.15;
  const MAX_W = base.width * 3;

  function apply(){
    svg.setAttribute("viewBox", view.x + " " + view.y + " " + view.w + " " + view.h);
  }

  function clientToSvg(clientX, clientY){
    const rect = svg.getBoundingClientRect();
    return {
      x: view.x + ((clientX - rect.left) / rect.width) * view.w,
      y: view.y + ((clientY - rect.top) / rect.height) * view.h,
    };
  }

  function zoomAt(clientX, clientY, factor){
    const newW = Math.min(MAX_W, Math.max(MIN_W, view.w * factor));
    const newH = newW * (view.h / view.w);
    const anchor = clientToSvg(clientX, clientY);
    view.x = anchor.x - ((anchor.x - view.x) * (newW / view.w));
    view.y = anchor.y - ((anchor.y - view.y) * (newH / view.h));
    view.w = newW;
    view.h = newH;
    apply();
  }

  function zoomAtCenter(factor){
    const rect = svg.getBoundingClientRect();
    zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, factor);
  }

  viewport.addEventListener("wheel", (e) => {
    e.preventDefault();
    zoomAt(e.clientX, e.clientY, e.deltaY > 0 ? 1.15 : 1 / 1.15);
  }, { passive: false });

  // dragMoved distinguishes an actual pan from a plain click on a site
  // node (which should still navigate to that site's page) - a click
  // is only ever cancelled if the mouse genuinely moved past a small
  // threshold between mousedown and mouseup, not just because a drag
  // sequence technically started and ended on the same node.
  let dragging = false, dragMoved = false, lastX = 0, lastY = 0;
  viewport.addEventListener("mousedown", (e) => {
    dragging = true; dragMoved = false; lastX = e.clientX; lastY = e.clientY;
    viewport.classList.add("dragging");
  });
  window.addEventListener("mousemove", (e) => {
    if(!dragging) return;
    if(Math.abs(e.clientX - lastX) > 2 || Math.abs(e.clientY - lastY) > 2) dragMoved = true;
    const rect = svg.getBoundingClientRect();
    view.x -= (e.clientX - lastX) * (view.w / rect.width);
    view.y -= (e.clientY - lastY) * (view.h / rect.height);
    lastX = e.clientX; lastY = e.clientY;
    apply();
  });
  window.addEventListener("mouseup", () => {
    dragging = false;
    viewport.classList.remove("dragging");
  });
  svg.addEventListener("click", (e) => {
    if(dragMoved){ e.preventDefault(); e.stopPropagation(); }
  }, true);

  const zoomInBtn = document.getElementById("map-zoom-in");
  const zoomOutBtn = document.getElementById("map-zoom-out");
  const resetBtn = document.getElementById("map-zoom-reset");
  if(zoomInBtn) zoomInBtn.addEventListener("click", () => zoomAtCenter(1 / 1.4));
  if(zoomOutBtn) zoomOutBtn.addEventListener("click", () => zoomAtCenter(1.4));
  if(resetBtn) resetBtn.addEventListener("click", () => {
    view = { x: base.x, y: base.y, w: base.width, h: base.height };
    apply();
  });

  apply();
})();
"""


def _esc(s) -> str:
    return "" if s is None else str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _ip_sort_key(ip):
    """Sorts real IPs in genuine numeric order (a plain string sort
    would put 192.20.0.10 before 192.20.0.2, which is wrong) - devices
    with no known IP sort after every device that has one.
    """
    if not ip:
        return (1, 0)
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)


def _interface_sort_key(interface):
    """Natural sort for interface names - a plain string sort would
    put Gi1/0/10 before Gi1/0/2, which is wrong. Splits the name into
    alternating text/number chunks (e.g. "Gi1/0/2" -> ["Gi","1","/",
    "0","/","2"]) and zero-pads each numeric chunk to a fixed width
    before joining back into one string - comparing the padded
    strings then produces the same order true numeric comparison
    would, while keeping the whole key a single string throughout (no
    mixed str/int comparison to worry about, regardless of how a real
    device's interface naming happens to be shaped). Different
    prefixes just fall into plain alphabetical order (Fa before Gi
    before Te) without needing any hardcoded notion of interface
    speeds. An interface with no name at all sorts last, matching how
    an unresolved IP already sorts last elsewhere.
    """
    if not interface:
        return (1, "")
    chunks = re.findall(r"\d+|\D+", interface)
    padded = "".join(c.zfill(10) if c.isdigit() else c for c in chunks)
    return (0, padded)


def _fmt_ts(ts) -> str:
    if not ts:
        return "never"
    try:
        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return ts


def _is_recent(ts, hours=24) -> bool:
    if not ts:
        return False
    try:
        then = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return False
    now = datetime.datetime.now(datetime.timezone.utc)
    return (now - then) < datetime.timedelta(hours=hours)


# How long a device/link can go unseen on successive scans before it's
# flagged as stale in the dashboard - a tunable knob, easy to find and
# adjust here without hunting through the rest of the file.
STALE_THRESHOLD_DAYS = 60

# ARP entries churn far faster than physical devices or cabling -
# DHCP leases expire, laptops sleep and grab a new address, phones
# reboot - so they get their own, much shorter threshold rather than
# reusing STALE_THRESHOLD_DAYS. Starting point; tune once there's real
# data to look at, same as the device/link threshold above.
ARP_STALE_THRESHOLD_DAYS = 10

# Clients churn even faster than ARP entries in practice - a laptop
# gets unplugged, a loaner phone moves desks - so this gets the
# shortest threshold of any staleness dimension in the dashboard.
# Automatic timer only, no manual override (unlike devices, which
# needed one specifically because MAC-table collection was brand new
# with no scan history to judge against - that's no longer true here).
CLIENT_STALE_THRESHOLD_DAYS = 3


def _is_stale(last_seen, site_last_cdp_discovery, threshold_days: int = None) -> bool:
    """A device/link/ARP entry is "stale" if it wasn't seen on the
    site's most recent successful scan by at least threshold_days -
    NOT simply "older than N days" by today's date. Comparing against
    today would make every entry at a site look newly stale just
    because the site itself hasn't been rescanned in a while, which
    isn't new information about any specific entry - only a real gap
    between an entry's last_seen and the site's own last scan means
    "this specific thing was missing when we last actually looked."
    No signal at all (site never scanned, or this entry has no
    last_seen) means there's not enough information to judge - never
    flagged stale in that case, matching the same "don't guess" stance
    used for the site-level status dot.

    threshold_days defaults to STALE_THRESHOLD_DAYS (devices/links);
    callers with a different natural churn rate - ARP entries change
    far faster than physical devices or cabling - pass their own
    threshold (see ARP_STALE_THRESHOLD_DAYS) instead of reusing that
    default.
    """
    if threshold_days is None:
        threshold_days = STALE_THRESHOLD_DAYS
    if not last_seen or not site_last_cdp_discovery:
        return False
    try:
        seen_dt = datetime.datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        scan_dt = datetime.datetime.fromisoformat(site_last_cdp_discovery.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (scan_dt - seen_dt) >= datetime.timedelta(days=threshold_days)


def _device_is_stale(device_row, site_last_cdp_discovery) -> bool:
    """A device is stale if EITHER the automatic age-based rule fires
    (_is_stale() above) OR it's been manually flagged via
    marked_stale_at (Site Manager's "Mark Stale" button). The manual
    flag exists specifically for what the automatic rule can't yet
    judge - a deployment too young to have a later rescan to compare
    against (or a site that just hasn't been rescanned in a while)
    means the timer has nothing to detect a gap against yet, even when
    a human already knows from direct knowledge that something's gone.
    """
    return _is_stale(device_row["last_seen"], site_last_cdp_discovery) or device_row["marked_stale_at"] is not None


def device_stale_reason(device_row, site_last_cdp_discovery):
    """WHY a device counts as stale, using exactly the same two rules
    as _device_is_stale() (which this must always agree with - it is
    the single definition of "stale" for devices, shared with the Site
    Manager tab in gui.py so the two can't drift apart):
      None                 - not stale
      "marked"             - flagged by hand (Mark Stale button) only
      "not seen"           - age-based only (last_seen fell behind the
                             site's last CDP scan by the threshold)
      "marked + not seen"  - both
    """
    aged = _is_stale(device_row["last_seen"], site_last_cdp_discovery)
    marked = device_row["marked_stale_at"] is not None
    if aged and marked:
        return "marked + not seen"
    if aged:
        return "not seen"
    if marked:
        return "marked"
    return None


def _client_is_stale(client_row, site_last_mac_table_collection) -> bool:
    """A client is stale if it wasn't seen on the site's most recent
    MAC-table collection (last_mac_table_collection, NOT
    last_cdp_discovery - the latter advances on every CDP walk
    regardless of whether MAC-table collection was actually requested
    that run, which would make every client at a site look newly
    stale after a plain CDP-only re-scan even though nothing about
    them was actually re-verified). Automatic timer only, unlike
    devices - clients have no manual "marked stale" override.
    """
    return _is_stale(client_row["last_seen"], site_last_mac_table_collection, threshold_days=CLIENT_STALE_THRESHOLD_DAYS)


# ---------------------------------------------------------------------
# Topology data assembly
# ---------------------------------------------------------------------

def build_topology_data(conn, site_id: int, site_last_cdp_discovery=None):
    """Builds the (devices, links) shapes topology_layout.compute_layout()
    expects, straight from sad.db. Includes stub entries for any
    cross-site remote devices referenced by this site's links, since
    the layout/render code needs their hostname + owning site info to
    label the collapsed cross-site group correctly.

    site_last_cdp_discovery: this site's own last successful scan -
    passed through so each local device/link can be flagged "stale"
    against it (see _is_stale()/_device_is_stale()). Cross-site remote
    stub devices are never flagged stale here - they belong to a
    different site's own scan cycle, which this function has no
    visibility into.
    """
    devices = {}
    for d in db.get_devices_for_site(conn, site_id):
        devices[d["id"]] = {
            "id": d["id"], "hostname": d["hostname"], "mgmt_ip": d["mgmt_ip"],
            "arp_override_ip": d["arp_override_ip"], "site_id": d["site_id"],
            "stale": _device_is_stale(d, site_last_cdp_discovery),
        }

    links = [dict(l) for l in conn.execute(
        "SELECT * FROM links WHERE site_id = ?", (site_id,)
    ).fetchall()]

    referenced_ids = {l["device_a_id"] for l in links} | {l["device_b_id"] for l in links}
    missing_ids = referenced_ids - set(devices.keys())
    for device_id in missing_ids:
        row = conn.execute(
            "SELECT d.*, s.site_octet, s.site_name FROM devices d "
            "JOIN sites s ON d.site_id = s.id WHERE d.id = ?",
            (device_id,),
        ).fetchone()
        if row:
            devices[device_id] = {
                "id": row["id"], "hostname": row["hostname"], "mgmt_ip": row["mgmt_ip"],
                "arp_override_ip": row["arp_override_ip"], "site_id": row["site_id"],
                "site_octet": row["site_octet"], "site_name": row["site_name"],
                "stale": False,
            }

    # A link is stale if its own timing looks aged out, OR either
    # endpoint device is itself stale (whether by the automatic timer
    # or a manual "Mark Stale" flag) - computed here against the
    # already-resolved device dict (now that every referenced device,
    # local or cross-site stub, exists in it) rather than stored on
    # the link itself. Nothing to keep in sync: if a device's manual
    # flag is later cleared, every link touching it correctly stops
    # looking stale on the very next generation, with no extra step.
    for link in links:
        a_stale = devices.get(link["device_a_id"], {}).get("stale", False)
        b_stale = devices.get(link["device_b_id"], {}).get("stale", False)
        link["stale"] = _is_stale(link["last_seen"], site_last_cdp_discovery) or a_stale or b_stale

    return devices, links


# ---------------------------------------------------------------------
# Site page
# ---------------------------------------------------------------------

def render_device_list_html(devices_rows, site_last_cdp_discovery, config_device_ids=frozenset()) -> str:
    rows_html = []
    for d in devices_rows:
        roles = []
        if d["is_seed"]:
            roles.append('<span class="badge role">CDP seed</span>')
        if d["is_arp_seed"]:
            roles.append('<span class="badge role">ARP seed</span>')
        source_cls = "source-inventory" if d["source"] == "inventory_sync" else "source-cdp"
        source_label = "inventory" if d["source"] == "inventory_sync" else _esc(d["source"])
        stale_badge = ""
        if _device_is_stale(d, site_last_cdp_discovery):
            stale_badge = '<span class="badge stale">stale</span>'
        config_badge = ""
        if d["id"] in config_device_ids:
            config_badge = f'<a class="badge cfg" href="configs.html?d={d["id"]}" title="View this device\'s saved configs">config</a>'
        rows_html.append(f'''
    <div class="row">
      <div class="main">
        <div class="name">{_esc(d["hostname"])}</div>
        <div class="meta">{_esc(d["mgmt_ip"] or "-")} · {_esc(d["platform"] or "unknown platform")}</div>
      </div>
      <div class="badges">
        {"".join(roles)}
        {stale_badge}
        {config_badge}
        <span class="badge {source_cls}">{source_label}</span>
      </div>
    </div>''')
    return "".join(rows_html) if rows_html else '<div class="row"><div class="main"><div class="meta">No devices found.</div></div></div>'


def render_clients_html(client_rows, devices_by_id, arp_rows, site_last_mac_table_collection, enrichment_rows) -> str:
    """client_rows: db.get_clients_for_site() results. devices_by_id:
    {device_id: hostname} for this site. arp_rows: this site's ARP
    entries - each client's IP (if known) is correlated against these
    via mac_parser.normalize_mac(), not a raw SQL join, since
    clients.mac and arp_entries.mac are independently-reported and
    aren't guaranteed to share the same separator/case format.
    enrichment_rows: db.get_all_phone_enrichment() results (not site-
    scoped - phone_enrichment has no site_id at all, so this is the
    full table each time; simple and correct at the scale this data
    actually reaches, just looked up per-client by normalized MAC).

    Grouped by switch (device_id) rather than one flat list - a large
    site can easily have hundreds of clients, and a single unbroken
    list of that size is unwieldy to scroll even collapsed by default.
    Grouping by switch is a natural, already-meaningful dimension in
    the data (mirrors ARP's own per-VRF grouping, reusing the exact
    same .vrf-group markup/CSS - no new styling needed) and keeps each
    group's size naturally bounded by that switch's own port count.
    """
    if not client_rows:
        return (
            '<p style="padding:14px; font-family:var(--mono); font-size:12px; color:var(--text-dim);">'
            'No client data collected yet - run CDP discovery with "Also collect MAC address tables" enabled.</p>'
        )

    ip_by_mac = {}
    for arp in arp_rows:
        norm = mac_parser.normalize_mac(arp["mac"])
        ips = ip_by_mac.setdefault(norm, [])
        if arp["ip"] not in ips:
            ips.append(arp["ip"])

    enrichment_by_mac = {row["mac"]: row for row in enrichment_rows}

    def sort_key(c):
        ips = ip_by_mac.get(mac_parser.normalize_mac(c["mac"]), [])
        ip_key = _ip_sort_key(ips[0] if ips else None)
        return (_interface_sort_key(c["interface"]), ip_key)

    def render_row(c):
        ips = ip_by_mac.get(mac_parser.normalize_mac(c["mac"]), [])
        ip_label = ", ".join(ips) if ips else "-"
        vlan_label = c["vlan"] or "-"
        norm_mac = mac_parser.normalize_mac(c["mac"])
        enrichment = enrichment_by_mac.get(norm_mac)

        badges = []
        type_label = {"cisco_phone": "phone", "vtc": "VTC"}.get(c["device_type"])
        if type_label:
            if enrichment and enrichment["model"]:
                type_label = f"{type_label} \u00b7 {enrichment['model']}"
            badges.append(f'<span class="badge role">{_esc(type_label)}</span>')
        if _client_is_stale(c, site_last_mac_table_collection):
            badges.append('<span class="badge stale">stale</span>')

        has_expand = enrichment is not None and any(
            [enrichment["phone_number"], enrichment["serial_number"], enrichment["ris_status"], enrichment["ris_ip"]]
        )
        panel_id = f"client-{norm_mac}"
        row_attrs = f' onclick="toggleExpand(\'{panel_id}\')" style="cursor:pointer;"' if has_expand else ""

        row_html = f'''
    <div class="row"{row_attrs}>
      <div class="main client-row-main">
        <span class="name">{_esc(c["interface"] or "-")}</span>
        <span class="meta">VLAN {_esc(vlan_label)} \u00b7 {_esc(ip_label)} \u00b7 {_esc(c["mac"])}</span>
      </div>
      <div class="badges">
        {"".join(badges)}
      </div>
    </div>'''

        if has_expand:
            row_html += f'''
    <div id="{panel_id}" class="remote-list" hidden>
      <div class="remote-list-title">CUCM / RIS Details</div>
      <div class="enrich-row"><span>Phone number(s)</span><span>{_esc(enrichment["phone_number"] or "-")}</span></div>
      <div class="enrich-row"><span>Serial</span><span>{_esc(enrichment["serial_number"] or "-")}</span></div>
      <div class="enrich-row"><span>RIS status</span><span>{_esc(enrichment["ris_status"] or "-")}</span></div>
      <div class="enrich-row"><span>RIS IP</span><span>{_esc(enrichment["ris_ip"] or "-")}</span></div>
      <div class="enrich-row"><span>Last enriched</span><span>{_fmt_ts(enrichment["last_enriched"])}</span></div>
    </div>'''

        return row_html

    groups = {}
    for c in client_rows:
        groups.setdefault(c["device_id"], []).append(c)

    html_parts = []
    for device_id, entries in sorted(groups.items(), key=lambda kv: devices_by_id.get(kv[0], "")):
        switch_name = devices_by_id.get(device_id, "(unknown device)")
        rows_html = "".join(render_row(c) for c in sorted(entries, key=sort_key))
        open_attr = "" if len(entries) > ARP_GROUP_AUTO_COLLAPSE_THRESHOLD else "open"
        html_parts.append(f'''
  <details class="vrf-group" {open_attr}>
    <summary class="vrf-group-head"><span class="vrf-name"><span class="chevron">\u25b8</span>{_esc(switch_name)}</span><span>{len(entries)} clients</span></summary>
    {rows_html}
  </details>''')
    return f'<div class="vrf-groups">{"".join(html_parts)}</div>'


ARP_GROUP_AUTO_COLLAPSE_THRESHOLD = 15


def _render_vrf_groups_html(rows) -> str:
    """Groups ARP rows by VRF and renders each as its own collapsible
    panel (auto-collapsed past ARP_GROUP_AUTO_COLLAPSE_THRESHOLD
    entries, same as always). Shared by both the active and stale
    sections in render_arp_tables_html() below - the only difference
    between them is which subset of rows gets passed in and what wraps
    the result, not how a single VRF's own table gets built. Returns
    "" if rows is empty, so callers can decide what (if anything) to
    show in that case.
    """
    groups = {}
    for row in rows:
        groups.setdefault(row["vrf"], []).append(row)
    if not groups:
        return ""

    html_parts = []
    for vrf, entries in sorted(groups.items(), key=lambda kv: (kv[0] != "", kv[0])):
        vrf_label = "(global)" if vrf == "" else _esc(vrf)
        # Interface/age aren't stored as their own columns on arp_entries
        # (only ip/mac/vrf/source/raw are) - pull them back out of the
        # stored raw_source_data line for display instead of adding
        # columns that would need a schema change for a cosmetic need.
        rows_html = "".join(_render_arp_row(e) for e in entries)
        open_attr = "" if len(entries) > ARP_GROUP_AUTO_COLLAPSE_THRESHOLD else "open"
        html_parts.append(f'''
  <details class="vrf-group" {open_attr}>
    <summary class="vrf-group-head"><span class="vrf-name"><span class="chevron">\u25b8</span>{vrf_label}</span><span>{len(entries)} entries</span></summary>
    <table>
      <thead><tr><th>IP</th><th>MAC</th><th>Interface</th><th>Age</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </details>''')
    return "".join(html_parts)


def render_tunnels_html(interface_rows, link_rows, site_last_tunnel_collection) -> str:
    """interface_rows: db.get_tunnel_interfaces_for_site() - the raw,
    per-interface data (status, description, internet_address, source/
    destination IPs). link_rows: db.get_tunnel_links_for_site() - the
    resolved match state for each of this site's own tunnel interfaces
    (see tunnel_links' schema comment for why this site's panel only
    ever shows its OWN half of a pair - the far site's own page shows
    its own row independently).

    Joined here by (device_id, interface) rather than queried as one
    combined SQL statement, since the two tables serve different
    purposes (raw collected data vs. a derived global correlation) and
    keeping them as separate db.py accessors means match_tunnels()
    re-runs don't require re-deriving anything this function already
    has cached - it just re-reads both.

    Three distinct badge states, deliberately NOT all using the same
    "stale" styling (that word is reserved for "this data is old" -
    see _is_stale() elsewhere on this page):
      - matched: a real reverse row was found at collection time -
        green/up-styled, names the far end.
      - one-sided: no reverse row was found (far site not yet
        collected, or the tunnel really was removed on that end) -
        warn-styled, surfaced rather than hidden (see match_tunnels()'s
        own docstring for why this is deliberate, not a bug).
      - unparsed: this interface's 'Tunnel source ..., destination ...'
        line didn't parse at all, so match_tunnels() had nothing to
        even attempt a match with - dim/neutral styled, distinct from
        "one-sided" since there's no meaningful source/destination to
        report here at all, not just a missing far end.
    Interface up/down status gets its own separate badge, independent
    of match state - a matched tunnel can still be administratively
    down, and that's worth seeing at a glance too.
    """
    if not interface_rows:
        return (
            '<p style="padding:14px; font-family:var(--mono); font-size:12px; color:var(--text-dim);">'
            'No tunnel data collected yet - run discovery with "Also collect tunnel interfaces" enabled.</p>'
        )

    link_by_key = {(lr["device_a_id"], lr["device_a_interface"]): lr for lr in link_rows}

    def sort_key(row):
        return (row["device_hostname"] or "", _interface_sort_key(row["interface"]))

    rows_html = []
    for row in sorted(interface_rows, key=sort_key):
        link_row = link_by_key.get((row["device_id"], row["interface"]))

        badges = []
        if not (row["admin_status"] == "up" and row["line_protocol"] == "up"):
            status_label = f'{row["admin_status"] or "?"} / {row["line_protocol"] or "?"}'
            badges.append(f'<span class="badge tunnel-down">{_esc(status_label)}</span>')

        if link_row is None:
            badges.append('<span class="badge tunnel-unparsed">unparsed</span>')
        elif link_row["device_b_id"] is not None:
            far_label = link_row["device_b_hostname"]
            far_site = link_row["device_b_site_name"] or link_row["device_b_site_octet"] or "?"
            badges.append(f'<span class="badge tunnel-matched">matched → {_esc(far_label)} ({_esc(far_site)})</span>')
        else:
            badges.append('<span class="badge tunnel-one-sided">one-sided</span>')

        if _is_stale(row["last_seen"], site_last_tunnel_collection):
            badges.append('<span class="badge stale">stale</span>')

        meta_bits = []
        if row["description"]:
            meta_bits.append(row["description"])
        if row["internet_address"]:
            meta_bits.append(row["internet_address"])
        if row["source_ip"] and row["destination_ip"]:
            meta_bits.append(f'{row["source_ip"]} → {row["destination_ip"]}')
        elif row["source_ip"]:
            meta_bits.append(f'src {row["source_ip"]} (no destination parsed)')
        meta = " · ".join(_esc(b) for b in meta_bits) if meta_bits else "-"

        rows_html.append(f'''
    <div class="row">
      <div class="main">
        <div class="name">{_esc(row["device_hostname"])} · {_esc(row["interface"])}</div>
        <div class="meta">{meta}</div>
      </div>
      <div class="badges">
        {"".join(badges)}
      </div>
    </div>''')
    return "".join(rows_html)


def render_arp_tables_html(arp_rows, site_last_arp_collection) -> str:
    """Active and stale entries are split FIRST, then grouped by VRF
    independently within each - not nested the other way around - so
    a VRF with both active and stale entries shows up in both
    sections rather than making someone hunt through an otherwise-
    normal-looking VRF table for the stale rows mixed in among it.
    A VRF that has only active (or only stale) entries only appears
    in the relevant section, never as an empty entry in the other.
    """
    if not arp_rows:
        return '<p style="padding:14px; font-family:var(--mono); font-size:12px; color:var(--text-dim);">No ARP data collected yet.</p>'

    active_rows, stale_rows = [], []
    for row in arp_rows:
        if _is_stale(row["last_seen"], site_last_arp_collection, threshold_days=ARP_STALE_THRESHOLD_DAYS):
            stale_rows.append(row)
        else:
            active_rows.append(row)

    active_html = _render_vrf_groups_html(active_rows)
    if not active_html:
        active_html = '<p style="padding:0 14px 14px; font-family:var(--mono); font-size:12px; color:var(--text-dim);">No active entries.</p>'

    parts = [f'<div class="vrf-groups"><div class="arp-section-label">Active ARP Entries</div>{active_html}']

    if stale_rows:
        stale_html = _render_vrf_groups_html(stale_rows)
        parts.append(f'''
  <details class="arp-stale-section">
    <summary class="stale-section-head"><span class="chevron">\u25b8</span>Stale ARP Entries ({len(stale_rows)} entries)</summary>
    {stale_html}
  </details>''')

    parts.append('</div>')
    return "".join(parts)


def _render_arp_row(entry) -> str:
    """arp_entries doesn't have its own interface/age columns - both
    parsers already stash the full original line in raw_source_data,
    so pull them back out for display rather than changing the schema
    just for a cosmetic column.
    """
    interface, age = "", ""
    raw = entry["raw_source_data"] or ""
    parts = raw.split()
    if parts:
        # IOS: Internet <ip> <age> <mac> <type> <interface>
        # NX-OS: <ip> <age> <mac> <interface> [flags]
        if parts[0].upper() == "INTERNET" and len(parts) == 6:
            age, interface = parts[2], parts[5]
        elif len(parts) in (4, 5):
            age, interface = parts[1], parts[3]
    return (
        f'<tr><td title="{_esc(entry["ip"])}">{_esc(entry["ip"])}</td>'
        f'<td title="{_esc(entry["mac"])}">{_esc(entry["mac"])}</td>'
        f'<td title="{_esc(interface)}">{_esc(interface)}</td>'
        f'<td title="{_esc(age)}">{_esc(age)}</td></tr>'
    )


def render_site_page(conn, site_row) -> str:
    site_id = site_row["id"]
    devices_rows = sorted(db.get_devices_for_site(conn, site_id), key=lambda d: _ip_sort_key(d["mgmt_ip"]))
    try:
        config_device_ids = {r[0] for r in conn.execute(
            "SELECT DISTINCT cs.device_id FROM config_snapshots cs JOIN devices d ON d.id = cs.device_id WHERE d.site_id = ?",
            (site_id,))}
    except Exception:
        config_device_ids = set()
    try:
        kg_panel_html = kg_pages.render_site_panel(conn, site_id)
    except Exception as e:   # never let a KG problem stop a site page
        kg_panel_html = f'<div class="panel"><div class="panel-head"><span class="label">KG Devices</span></div><p style="padding:12px 14px;font-family:var(--mono);font-size:12px">KG panel could not be built: {_esc(e)}</p></div>'
    kg_css = kg_pages.CSS if kg_panel_html else ""
    kg_js = kg_pages.JS if kg_panel_html else ""
    arp_rows = db.get_arp_for_site(conn, site_id)
    client_rows = db.get_clients_for_site(conn, site_id)
    tunnel_interface_rows = db.get_tunnel_interfaces_for_site(conn, site_id)
    tunnel_link_rows = db.get_tunnel_links_for_site(conn, site_id)
    seed = db.get_seed_device_for_site(conn, site_id)
    arp_seed = db.get_arp_seed_device_for_site(conn, site_id)

    devices, links = build_topology_data(conn, site_id, site_row["last_cdp_discovery"])
    topology_html = '<p style="padding:14px; font-family:var(--mono); font-size:12px; color:var(--text-dim);">No seed device flagged - nothing to render.</p>'
    expand_panels_html = ""
    device_count_label = f"{len(devices_rows)} devices"
    if seed is not None and seed["id"] in devices:
        layout = topology_layout.compute_layout(seed["id"], devices, links, site_id)
        result = topology_svg.render_svg(layout, devices)
        topology_html = result["svg"]
        panels = []
        for p in result["expand_panels"]:
            items = "".join(
                f'<a class="remote-item" href="#">{_esc(it["label"])} <span class="site-tag">{_esc(it["sub"])}</span></a>'
                for it in p["items"]
            )
            panels.append(f'''
    <div id="{p["id"]}" class="remote-list" hidden>
      <div class="remote-list-title">{_esc(p["title"])}</div>
      {items}
    </div>''')
        expand_panels_html = "".join(panels)
        device_count_label = f"{len(devices_rows)} devices shown"

    site_label = site_row["site_name"] or f"octet {site_row['site_octet']}"
    code_label = f" — {_esc(site_row['site_code'])}" if site_row["site_code"] else ""
    seed_label = seed["hostname"] if seed else "(none flagged)"
    arp_seed_label = arp_seed["hostname"] if arp_seed else "(none flagged)"
    arp_override_note = ""
    if arp_seed and arp_seed["arp_override_ip"]:
        arp_override_note = f" (override \u2192 {_esc(arp_seed['arp_override_ip'])})"

    total_arp = len(arp_rows)
    vrf_count = len({row["vrf"] for row in arp_rows}) if arp_rows else 0

    return f'''<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(site_label)} ({_esc(site_row['site_octet'])}) — Site Awareness Dashboard</title>
<style>
{CSS_TOKENS}
*{{ box-sizing: border-box; }}
body{{ margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); -webkit-font-smoothing:antialiased; }}
.wrap{{ max-width:1200px; margin:0 auto; padding:24px 24px 60px; }}
.backlink{{ display:inline-block; font-family:var(--mono); font-size:12px; color:var(--text-dim); border:1px solid var(--border); border-radius:999px; padding:5px 12px; text-decoration:none; margin-bottom:14px; }}
.backlink:hover{{ color:var(--accent); border-color:var(--accent); }}
header{{ display:flex; justify-content:space-between; align-items:flex-end; border-bottom:2px solid var(--border); padding-bottom:16px; margin-bottom:20px; gap:16px; flex-wrap:wrap; }}
header h1{{ margin:0; font-size:22px; font-weight:700; }}
.subtitle{{ font-family:var(--mono); font-size:12px; color:var(--text-dim); margin-top:4px; }}
button, .btn{{ background:var(--panel-2); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--sans); font-size:13px; padding:8px 14px; cursor:pointer; transition:border-color .15s ease, transform .1s ease; text-decoration:none; display:inline-block; }}
button:hover, .btn:hover{{ border-color:var(--accent); }}
button:active, .btn:active{{ transform:scale(.97); }}
.header-actions{{ display:flex; gap:8px; align-items:center; }}
.icon-btn{{ width:38px; height:38px; padding:0; display:flex; align-items:center; justify-content:center; font-size:16px; }}
header.site-header{{ display:block; }}
.title-row{{ display:flex; justify-content:space-between; align-items:center; gap:16px; }}
.icon-btn-sm{{ width:30px; height:30px; font-size:13px; flex:none; }}
.panel{{ background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; margin-bottom:18px; }}
.panel-head{{ background:var(--panel-2); border-bottom:1px solid var(--border); padding:8px 14px; display:flex; justify-content:space-between; align-items:center; cursor:pointer; list-style:none; }}
.panel-head::-webkit-details-marker{{ display:none; }}
.panel-head .label{{ font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; display:flex; align-items:center; }}
.panel-head .count{{ font-family:var(--mono); font-size:11px; background:var(--bg); border:1px solid var(--border); border-radius:999px; padding:2px 9px; color:var(--text-dim); }}
.chevron{{ display:inline-block; margin-right:8px; color:var(--text-dim); font-size:10px; transition:transform .15s ease; transform:rotate(90deg); }}
details:not([open]) > .panel-head .chevron, details:not([open]) > .vrf-group-head .chevron, details:not([open]) > .stale-section-head .chevron{{ transform:rotate(0deg); }}
.grouped-node{{ cursor:pointer; }}
.grouped-node:hover .node-box.grouped, .grouped-node:hover .node-box{{ stroke:var(--accent); }}
.remote-list{{ margin:14px 16px 14px; border:1px solid var(--accent-dim); border-radius:8px; background:var(--panel-2); overflow:hidden; }}
.remote-list-title{{ font-family:var(--mono); font-size:10.5px; color:var(--text-dim); padding:8px 12px; border-bottom:1px solid var(--border); text-transform:uppercase; letter-spacing:.05em; }}
.remote-item{{ display:block; font-family:var(--mono); font-size:12px; color:var(--text); text-decoration:none; padding:7px 12px; border-bottom:1px solid var(--border); }}
.remote-item:last-child{{ border-bottom:none; }}
.remote-item:hover{{ background:var(--panel); color:var(--accent); }}
.remote-item .site-tag{{ color:var(--text-dim); }}
.enrich-row{{ display:flex; justify-content:space-between; gap:12px; font-family:var(--mono); font-size:12px; padding:7px 12px; border-bottom:1px solid var(--border); }}
.enrich-row:last-child{{ border-bottom:none; }}
.enrich-row span:first-child{{ color:var(--text-dim); }}
#topology{{ width:100%; height:auto; display:block; }}
.node-box{{ fill:var(--panel-2); stroke:var(--border); stroke-width:1; }}
.node-box.grouped{{ fill:var(--bg); stroke:var(--accent-dim); stroke-dasharray:3 3; }}
.node-box.stale{{ opacity:0.5; stroke-dasharray:2 2; }}
.node-label{{ font-family:var(--mono); font-size:11px; fill:var(--text); }}
.node-sub{{ font-family:var(--mono); font-size:9px; fill:var(--text-dim); }}
.link-line{{ stroke:var(--text-dim); stroke-width:1.3; transition:stroke .1s ease, stroke-width .1s ease; }}
.link-line.grouped{{ stroke:var(--accent-dim); stroke-width:1.3; stroke-dasharray:4 3; }}
.link-line.stale{{ opacity:0.45; stroke-dasharray:1 3; }}
.edge:hover .link-line{{ stroke:var(--accent); stroke-width:2.2; }}
.row{{ display:flex; align-items:center; gap:14px; padding:9px 14px; border-bottom:1px solid var(--border); }}
.row:last-child{{ border-bottom:none; }}
.row:hover{{ background:var(--panel-2); }}
.row .main{{ flex:1; min-width:0; }}
.row .name{{ font-size:14px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.row .meta{{ font-family:var(--mono); font-size:11.5px; color:var(--text-dim); margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.client-row-main{{ display:flex; align-items:baseline; gap:10px; }}
.client-row-main .meta{{ margin-top:0; }}
.badges{{ display:flex; gap:6px; flex:none; }}
.badge{{ font-family:var(--mono); font-size:10.5px; border-radius:999px; padding:2px 9px; white-space:nowrap; border:1px solid var(--border); }}
.badge.source-inventory{{ color:var(--up); border-color:color-mix(in srgb, var(--up) 40%, var(--border)); }}
.badge.source-cdp{{ color:var(--text-dim); }}
.badge.source-manual{{ color:var(--accent); border-color:var(--accent-dim); }}
.badge.role{{ color:var(--accent); border-color:var(--accent-dim); }}
.badge.stale{{ color:var(--text-dim); border-style:dashed; }}
.badge.cfg{{ color:var(--accent); border-color:var(--accent-dim); text-decoration:none; }}
.badge.cfg:hover{{ border-color:var(--accent); }}
.badge.tunnel-matched{{ color:var(--up); border-color:color-mix(in srgb, var(--up) 40%, var(--border)); }}
.badge.tunnel-one-sided{{ color:var(--warn); border-color:color-mix(in srgb, var(--warn) 40%, var(--border)); }}
.badge.tunnel-down{{ color:var(--warn); border-color:color-mix(in srgb, var(--warn) 40%, var(--border)); }}
.badge.tunnel-unparsed{{ color:var(--text-dim); border-style:dashed; }}
.vrf-groups{{ padding:14px; }}
.vrf-group{{ border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-bottom:14px; display:block; }}
.vrf-group-head{{ background:var(--panel-2); padding:9px 14px; font-family:var(--mono); font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; color:var(--text); display:flex; justify-content:space-between; cursor:pointer; list-style:none; }}
.vrf-group-head::-webkit-details-marker{{ display:none; }}
.vrf-group-head .vrf-name{{ display:flex; align-items:center; }}
.arp-section-label{{ font-family:var(--mono); font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; color:var(--text); padding:14px 14px 4px; }}
.arp-stale-section{{ margin:0 14px 14px; }}
.stale-section-head{{ font-family:var(--mono); font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; color:var(--text-dim); cursor:pointer; padding:8px 0; list-style:none; display:flex; align-items:center; }}
.stale-section-head::-webkit-details-marker{{ display:none; }}
.stale-section-head:hover{{ color:var(--accent); }}
table{{ width:100%; table-layout:fixed; border-collapse:collapse; font-family:var(--mono); font-size:12px; }}
th:nth-child(1), td:nth-child(1){{ width:26%; }}
th:nth-child(2), td:nth-child(2){{ width:30%; }}
th:nth-child(3), td:nth-child(3){{ width:30%; }}
th:nth-child(4), td:nth-child(4){{ width:14%; }}
th, td{{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
th{{ text-align:left; padding:6px 12px; color:var(--text-dim); font-weight:600; border-bottom:1px solid var(--border); font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; }}
td{{ padding:5px 12px; border-bottom:1px solid var(--border); }}
tr:last-child td{{ border-bottom:none; }}
tr:hover td{{ background:var(--panel-2); }}
footer{{ margin-top:20px; font-family:var(--mono); font-size:11px; color:var(--text-dim); text-align:center; }}
{kg_css}
{banner.CSS}
</style>
</head>
<body>
{banner.html()}
<div class="wrap">
  <a class="backlink" href="index.html">\u2190 All Sites</a>
  <header class="site-header">
    <div class="title-row">
      <h1>{_esc(site_label)}{code_label}</h1>
      <button class="icon-btn icon-btn-sm" id="theme-toggle" title="Toggle theme">\U0001F319</button>
    </div>
    <div class="subtitle">octet {_esc(site_row['site_octet'])} · CDP seed: {_esc(seed_label)} · ARP seed: {_esc(arp_seed_label)}{arp_override_note} · last CDP {_fmt_ts(site_row['last_cdp_discovery'])} · last ARP {_fmt_ts(site_row['last_arp_collection'])} · last tunnels {_fmt_ts(site_row['last_tunnel_collection'])}</div>
  </header>

  <details class="panel" open>
    <summary class="panel-head"><span class="label"><span class="chevron">\u25b8</span>Topology</span><span class="count">{device_count_label}</span></summary>
    {topology_html}
    {expand_panels_html}
  </details>

  <details class="panel">
    <summary class="panel-head"><span class="label"><span class="chevron">\u25b8</span>Devices</span><span class="count">{len(devices_rows)} total</span></summary>
    <div>{render_device_list_html(devices_rows, site_row["last_cdp_discovery"], config_device_ids)}</div>
  </details>

  <details class="panel">
    <summary class="panel-head"><span class="label"><span class="chevron">\u25b8</span>ARP Tables</span><span class="count">{vrf_count} tables · {total_arp} entries</span></summary>
    {render_arp_tables_html(arp_rows, site_row["last_arp_collection"])}
  </details>

  <details class="panel">
    <summary class="panel-head"><span class="label"><span class="chevron">\u25b8</span>Tunnels</span><span class="count">{len(tunnel_interface_rows)} total</span></summary>
    <div>{render_tunnels_html(tunnel_interface_rows, tunnel_link_rows, site_row["last_tunnel_collection"])}</div>
  </details>

  {kg_panel_html}

  <details class="panel">
    <summary class="panel-head"><span class="label"><span class="chevron">\u25b8</span>Clients</span><span class="count">{len(client_rows)} total</span></summary>
    <div>{render_clients_html(client_rows, {d["id"]: d["hostname"] for d in devices_rows}, arp_rows, site_row["last_mac_table_collection"], db.get_all_phone_enrichment(conn))}</div>
  </details>

  <footer>{_esc(site_label)} (octet {_esc(site_row['site_octet'])}) — generated from sad.db, read-only</footer>
</div>
<script>
function toggleExpand(id){{
  const el = document.getElementById(id);
  el.hidden = !el.hidden;
}}
{kg_js}
{THEME_TOGGLE_JS}
</script>
</body>
</html>
'''


# ---------------------------------------------------------------------
# Index page
# ---------------------------------------------------------------------

def render_index_page(conn) -> str:
    sites = db.get_all_sites(conn)
    # "Unassigned" is a real row in the sites table (so the generator
    # can produce a normal site-unassigned.html page for it) but isn't
    # a real site - it shouldn't be counted or listed alongside actual
    # sites. It gets its own dedicated header button/page instead (see
    # unassigned_count below).
    real_sites = [s for s in sites if s["site_octet"] != "unassigned"]
    unassigned_site = next((s for s in sites if s["site_octet"] == "unassigned"), None)

    total_devices = conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"]
    total_links = conn.execute("SELECT COUNT(*) AS c FROM links").fetchone()["c"]
    total_clients = conn.execute("SELECT COUNT(*) AS c FROM clients").fetchone()["c"]
    never_scanned = sum(1 for s in real_sites if not s["last_cdp_discovery"])
    kg_button_html, kg_tile_html = "", ""
    try:
        kgs = kg_pages.summary(conn)
        if kgs["total"]:
            kg_button_html = f'<a class="btn" href="kg.html">KG Devices ({kgs["total"]})</a>'
            kg_cls = "num warn" if kgs["critical"] else "num"
            kg_label = (f'{kgs["critical"]} critical' if kgs["critical"] else f'{kgs["warning"]} warning' if kgs["warning"] else "all healthy")
            kg_tile_html = (f'<a class="kpi kpi-link" href="kg.html" title="KG health"><center><div class="{kg_cls}">{kgs["total"]}</div>'
                            f'<div class="label">KG devices &middot; {kg_label}</div></center></a>')
    except Exception:
        pass

    unassigned_count = 0
    if unassigned_site is not None:
        unassigned_count = conn.execute(
            "SELECT COUNT(*) AS c FROM devices WHERE site_id = ?", (unassigned_site["id"],)
        ).fetchone()["c"]

    # The tile and the stale devices page share one definition
    # (collect_stale_devices) so the count here always equals the
    # number of rows on stale.html. Unassigned is never CDP-scanned, so
    # nothing there can be judged stale by this rule.
    stale_device_count = len(collect_stale_devices(conn, real_sites))

    rows_html = []
    for s in real_sites:
        device_count = conn.execute(
            "SELECT COUNT(*) AS c FROM devices WHERE site_id = ?", (s["id"],)
        ).fetchone()["c"]
        link_count = conn.execute(
            "SELECT COUNT(*) AS c FROM links WHERE site_id = ?", (s["id"],)
        ).fetchone()["c"]

        label = s["site_name"] or f"(unset — octet {s['site_octet']})"
        code_meta = f" · {_esc(s['site_code'])}" if s["site_code"] else ""

        if not s["last_cdp_discovery"]:
            dot_class = ""
        elif _is_recent(s["last_cdp_discovery"]):
            dot_class = "up"
        else:
            dot_class = "stale"

        href = f"site-{s['site_octet']}.html"

        rows_html.append(f'''
    <a class="row" href="{href}">
      <span class="status-dot {dot_class}"></span>
      <div class="main">
        <div class="name">{_esc(label)}</div>
        <div class="meta">octet {_esc(s['site_octet'])}{code_meta}</div>
      </div>
      <div class="counts">
        <span class="pill">{device_count} dev</span>
        <span class="pill">{link_count} links</span>
      </div>
      <div class="runinfo">cdp {_fmt_ts(s['last_cdp_discovery'])}<br>arp {_fmt_ts(s['last_arp_collection'])}</div>
    </a>''')

    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f'''<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Site Awareness Dashboard</title>
<style>
{CSS_TOKENS}
*{{ box-sizing: border-box; }}
body{{ margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); -webkit-font-smoothing:antialiased; }}
.wrap{{ max-width:1200px; margin:0 auto; padding:24px 24px 60px; }}
header{{ display:flex; justify-content:space-between; align-items:flex-end; border-bottom:2px solid var(--border); padding-bottom:16px; margin-bottom:20px; gap:16px; flex-wrap:wrap; }}
header h1{{ margin:0; font-size:22px; font-weight:700; }}
.subtitle{{ font-family:var(--mono); font-size:12px; color:var(--text-dim); margin-top:4px; }}
.header-actions{{ display:flex; gap:8px; align-items:center; }}
button, .btn{{ background:var(--panel-2); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--sans); font-size:13px; padding:8px 14px; cursor:pointer; transition:border-color .15s ease, transform .1s ease; text-decoration:none; display:inline-block; }}
button:hover, .btn:hover{{ border-color:var(--accent); }}
button:active, .btn:active{{ transform:scale(.97); }}
.icon-btn{{ width:38px; height:38px; padding:0; display:flex; align-items:center; justify-content:center; font-size:16px; }}
.kpi-grid{{ display:grid; grid-template-columns:repeat(auto-fit, minmax(120px,1fr)); gap:10px; margin-bottom:24px; }}
.kpi{{ background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); padding:12px 10px; }}
.kpi .num{{ font-family:var(--mono); font-size:24px; font-weight:700; }}
.kpi .num.warn{{ color:var(--warn); }}
.kpi .label{{ font-family:var(--mono); font-size:11px; text-transform:uppercase; letter-spacing:.07em; color:var(--text-dim); margin-top:4px; }}
.kpi-link{{ display:block; color:inherit; text-decoration:none; transition:border-color .15s ease; }}
.kpi-link:hover{{ border-color:var(--accent); }}
.search-row{{ margin-bottom:14px; }}
#search{{ width:100%; background:var(--panel); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--mono); font-size:13px; padding:10px 14px; }}
#search::placeholder{{ color:var(--text-dim); }}
#search:focus{{ outline:none; border-color:var(--accent); }}
.panel{{ background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; }}
.panel-head{{ background:var(--panel-2); border-bottom:1px solid var(--border); padding:8px 14px; display:flex; justify-content:space-between; align-items:center; }}
.panel-head .label{{ font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; }}
.panel-head .count{{ font-family:var(--mono); font-size:11px; background:var(--bg); border:1px solid var(--border); border-radius:999px; padding:2px 9px; color:var(--text-dim); }}
.row{{ display:flex; align-items:center; gap:14px; padding:10px 14px; border-bottom:1px solid var(--border); cursor:pointer; text-decoration:none; color:inherit; }}
.row:last-child{{ border-bottom:none; }}
.row:hover{{ background:var(--panel-2); }}
.status-dot{{ width:8px; height:8px; border-radius:50%; background:var(--text-dim); flex:none; transition:box-shadow .15s ease; }}
.status-dot.up{{ background:var(--up); box-shadow:0 0 0 4px color-mix(in srgb, var(--up) 20%, transparent); }}
.status-dot.stale{{ background:var(--warn); }}
.row .main{{ flex:1; min-width:0; }}
.row .name{{ font-size:14.5px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.row .meta{{ font-family:var(--mono); font-size:11.5px; color:var(--text-dim); margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.row .counts{{ display:flex; gap:6px; flex:none; }}
.pill{{ font-family:var(--mono); font-size:11px; border:1px solid var(--border); border-radius:999px; padding:2px 9px; color:var(--text-dim); white-space:nowrap; }}
.pill.needs-review{{ border-color:var(--warn); color:var(--warn); }}
.row .runinfo{{ font-family:var(--mono); font-size:11px; color:var(--text-dim); text-align:right; flex:none; width:150px; }}
footer{{ margin-top:20px; font-family:var(--mono); font-size:11px; color:var(--text-dim); text-align:center; }}
{banner.CSS}
</style>
</head>
<body>
{banner.html()}
<div class="wrap">
  <header>
    <div>
      <h1>Site Awareness Dashboard</h1>
      <div class="subtitle">{len(real_sites)} sites · {total_devices} devices tracked · generated {generated_at}</div>
    </div>
    <div class="header-actions">
      <a class="btn" href="site-map.html">Site Map</a>
      <a class="btn" href="clients.html">Search Clients</a>
      <a class="btn" href="exports.html">Exports</a>
      <a class="btn" href="configs.html">Configs</a>
      <a class="btn" href="aci.html">ACI</a>
      {kg_button_html}
      <a class="btn" href="site-unassigned.html">Unassigned ({unassigned_count})</a>
      <button class="icon-btn" id="theme-toggle" title="Toggle theme">\U0001F319</button>
    </div>
  </header>

  <div class="kpi-grid">
    <div class="kpi"><center><div class="num">{len(real_sites)}</div><div class="label">Sites</div></center></div>
    <div class="kpi"><center><div class="num">{total_devices}</div><div class="label">Devices</div></center></div>
    <div class="kpi"><center><div class="num">{total_links}</div><div class="label">Links</div></center></div>
    <div class="kpi"><center><div class="num">{total_clients}</div><div class="label">Clients</div></center></div>
    <div class="kpi"><center>{'<div class="num warn">' if never_scanned > 0 else '<div class="num">'}{never_scanned}</div><div class="label">Never CDP-scanned</div></center></div>
    {kg_tile_html}
    <a class="kpi kpi-link" href="stale.html" title="Review stale devices"><center><div class="num warn">{stale_device_count}</div><div class="label">Stale devices</div></center></a>
  </div>

  <div class="search-row">
    <input id="search" type="text" placeholder="Filter by name, octet, or code…" autocomplete="off">
  </div>

  <div class="panel">
    <div class="panel-head"><span class="label">Sites</span><span class="count" id="visible-count">{len(real_sites)} shown</span></div>
    <div id="site-list">{"".join(rows_html)}</div>
  </div>

  <footer>Site Awareness Dashboard — generated from sad.db, read-only</footer>
</div>
<script>
document.getElementById("search").addEventListener("input", (e) => {{
  const f = e.target.value.trim().toLowerCase();
  const rows = document.querySelectorAll("#site-list .row");
  let visible = 0;
  rows.forEach(r => {{
    const match = !f || r.textContent.toLowerCase().includes(f);
    r.style.display = match ? "" : "none";
    if(match) visible++;
  }});
  document.getElementById("visible-count").textContent = `${{visible}} shown`;
}});
{THEME_TOGGLE_JS}
</script>
</body>
</html>
'''


# ---------------------------------------------------------------------
# Stale devices page
# ---------------------------------------------------------------------

def _days_behind(last_seen, site_last_cdp_discovery):
    """Whole days between a device's last_seen and the site's last CDP
    scan (the same gap _is_stale() measures), or None when either side
    is missing/unparseable."""
    if not last_seen or not site_last_cdp_discovery:
        return None
    try:
        seen_dt = datetime.datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        scan_dt = datetime.datetime.fromisoformat(site_last_cdp_discovery.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, (scan_dt - seen_dt).days)


def _hostname_key(hostname):
    """Lowercased hostname with any domain suffix and trailing
    "(SERIAL)" removed - 'SW-A(FOC123).corp.local' and 'sw-a' compare
    equal. Only used to suggest merge candidates, never to decide
    anything on its own."""
    h = (hostname or "").strip().lower()
    h = re.sub(r"\(.*?\)\s*", "", h)
    return h.split(".")[0]


def _names_look_related(a_key, b_key) -> bool:
    if not a_key or not b_key:
        return False
    if a_key == b_key:
        return True
    short, long_ = sorted((a_key, b_key), key=len)
    # 'sw1' vs 'sw1-core' (prefix then a separator), but never
    # 'sw1' vs 'sw10'.
    return len(short) >= 4 and long_.startswith(short) and not long_[len(short)].isalnum()


def _duplicate_hint(stale_dev, fresh_devices, ips_by_device):
    """Best guess at which NOT-stale device at the same site this stale
    one is a duplicate of, or None. Returns (hostname, why). Evidence,
    strongest first: same serial number, a shared IP, a related name.
    """
    my_ips = ips_by_device.get(stale_dev["id"], set())
    my_key = _hostname_key(stale_dev["hostname"])
    best = None
    for other in fresh_devices:
        if other["id"] == stale_dev["id"]:
            continue
        why = None
        if stale_dev["serial_number"] and stale_dev["serial_number"] == other["serial_number"]:
            why, score = "same serial number", 3
        else:
            shared = my_ips & ips_by_device.get(other["id"], set())
            if shared:
                why, score = f"shares IP {sorted(shared)[0]}", 2
            elif _names_look_related(my_key, _hostname_key(other["hostname"])):
                why, score = "similar name", 1
        if why and (best is None or score > best[2]):
            best = (other["hostname"], why, score)
    return (best[0], best[1]) if best else None


def collect_stale_devices(conn, real_sites) -> list:
    """Every stale device across the given (real, non-Unassigned)
    sites. THE shared definition behind both the index tile's count and
    the stale devices page - the tile is len() of this - so the two
    can't disagree. Live devices only; soft-deleted ones never count.
    Sites that were never CDP-scanned are skipped (nothing to judge
    against - see _is_stale()).

    Returns a list of dicts, ordered by site then hostname.
    """
    out = []
    for s in real_sites:
        scan = s["last_cdp_discovery"]
        if not scan:
            continue
        devices = db.get_devices_for_site(conn, s["id"])
        reasons = {d["id"]: device_stale_reason(d, scan) for d in devices}
        if not any(reasons.values()):
            continue
        ips_by_device = {}
        for row in conn.execute(
            "SELECT di.device_id, di.ip FROM device_ips di JOIN devices d ON d.id = di.device_id WHERE d.site_id = ?",
            (s["id"],),
        ):
            ips_by_device.setdefault(row["device_id"], set()).add(row["ip"])
        fresh = [d for d in devices if not reasons[d["id"]]]
        label = s["site_name"] or f"(unset — octet {s['site_octet']})"
        for d in devices:
            reason = reasons[d["id"]]
            if not reason:
                continue
            hint = _duplicate_hint(d, fresh, ips_by_device)
            out.append({
                "site_octet": s["site_octet"],
                "site_label": label,
                "site_total": len(devices),
                "site_last_scan": scan,
                "hostname": d["hostname"],
                "mgmt_ip": d["mgmt_ip"],
                "platform": d["platform"],
                "source": d["source"],
                "last_seen": d["last_seen"],
                "days_behind": _days_behind(d["last_seen"], scan),
                "reason": reason,
                "duplicate_of": hint[0] if hint else None,
                "duplicate_why": hint[1] if hint else None,
            })
    return out


def render_stale_page(conn) -> str:
    real_sites = [s for s in db.get_all_sites(conn) if s["site_octet"] != "unassigned"]
    stale = collect_stale_devices(conn, real_sites)

    by_site = {}
    for d in stale:
        by_site.setdefault(d["site_octet"], []).append(d)

    panels = []
    for octet, devs in by_site.items():
        first = devs[0]
        rows = []
        for d in devs:
            source_label = "inventory" if d["source"] == "inventory_sync" else _esc(d["source"])
            source_cls = "source-inventory" if d["source"] == "inventory_sync" else "source-cdp"
            behind = f"{d['days_behind']} d behind scan" if d["days_behind"] is not None else "—"
            if d["duplicate_of"]:
                dup = (
                    f'<span class="badge dup" title="{_esc(d["duplicate_why"])}">'
                    f'maybe a duplicate of {_esc(d["duplicate_of"])}</span>'
                )
            else:
                dup = ""
            rows.append(f'''
      <div class="row" data-reason="{_esc(d['reason'])}" data-dup="{'1' if d['duplicate_of'] else '0'}">
        <div class="main">
          <div class="name">{_esc(d['hostname'])}</div>
          <div class="meta">{_esc(d['mgmt_ip'] or '-')} · {_esc(d['platform'] or 'unknown platform')} · last seen {_fmt_ts(d['last_seen'])} · {behind}</div>
        </div>
        <div class="badges">
          {dup}
          <span class="badge {source_cls}">{source_label}</span>
          <span class="badge reason">{_esc(d['reason'])}</span>
        </div>
      </div>''')
        panels.append(f'''
  <div class="panel site-panel">
    <div class="panel-head">
      <a class="site-link" href="site-{_esc(octet)}.html">{_esc(first['site_label'])} <span class="octet">octet {_esc(octet)}</span></a>
      <span class="count">{len(devs)} of {first['site_total']} stale · last CDP scan {_fmt_ts(first['site_last_scan'])}</span>
    </div>
    {"".join(rows)}
  </div>''')

    dup_count = sum(1 for d in stale if d["duplicate_of"])
    marked_count = sum(1 for d in stale if "marked" in d["reason"])
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if panels:
        body = "".join(panels)
    else:
        body = '<p class="empty">No stale devices right now.</p>'

    return f'''<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stale Devices — Site Awareness Dashboard</title>
<style>
{CSS_TOKENS}
*{{ box-sizing: border-box; }}
body{{ margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); -webkit-font-smoothing:antialiased; }}
.wrap{{ max-width:1200px; margin:0 auto; padding:24px 24px 60px; }}
a{{ color:inherit; }}
.backlink{{ display:inline-block; font-family:var(--mono); font-size:12px; color:var(--text-dim); border:1px solid var(--border); border-radius:999px; padding:5px 12px; text-decoration:none; margin-bottom:14px; }}
.backlink:hover{{ color:var(--accent); border-color:var(--accent); }}
header{{ display:flex; justify-content:space-between; align-items:flex-end; border-bottom:2px solid var(--border); padding-bottom:16px; margin-bottom:20px; gap:16px; flex-wrap:wrap; }}
header h1{{ margin:0; font-size:22px; font-weight:700; }}
.subtitle{{ font-family:var(--mono); font-size:12px; color:var(--text-dim); margin-top:4px; }}
button, .btn{{ background:var(--panel-2); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--sans); font-size:13px; padding:8px 14px; cursor:pointer; text-decoration:none; display:inline-block; }}
button:hover, .btn:hover{{ border-color:var(--accent); }}
.icon-btn{{ width:38px; height:38px; padding:0; display:flex; align-items:center; justify-content:center; font-size:16px; }}
.kpi-grid{{ display:grid; grid-template-columns:repeat(auto-fill, minmax(175px,1fr)); gap:12px; margin-bottom:20px; }}
.kpi{{ background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); padding:14px 16px; text-align:center; }}
.kpi .num{{ font-family:var(--mono); font-size:26px; font-weight:700; }}
.kpi .num.warn{{ color:var(--warn); }}
.kpi .label{{ font-family:var(--mono); font-size:11px; text-transform:uppercase; letter-spacing:.07em; color:var(--text-dim); margin-top:4px; }}
.controls{{ display:flex; gap:10px; margin-bottom:14px; flex-wrap:wrap; }}
#search{{ flex:1; min-width:220px; background:var(--panel); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--mono); font-size:13px; padding:10px 14px; }}
#search:focus, #reason-filter:focus{{ outline:none; border-color:var(--accent); }}
#reason-filter{{ background:var(--panel); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--mono); font-size:13px; padding:10px 12px; }}
.note{{ font-family:var(--mono); font-size:11.5px; color:var(--text-dim); margin:0 0 16px; line-height:1.5; }}
.panel{{ background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; margin-bottom:14px; }}
.panel-head{{ background:var(--panel-2); border-bottom:1px solid var(--border); padding:8px 14px; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; }}
.site-link{{ font-size:13.5px; font-weight:700; text-decoration:none; }}
.site-link:hover{{ color:var(--accent); }}
.site-link .octet{{ font-family:var(--mono); font-size:11px; font-weight:400; color:var(--text-dim); margin-left:6px; }}
.panel-head .count{{ font-family:var(--mono); font-size:11px; color:var(--text-dim); }}
.row{{ display:flex; align-items:center; gap:14px; padding:10px 14px; border-bottom:1px solid var(--border); }}
.row:last-child{{ border-bottom:none; }}
.row .main{{ flex:1; min-width:0; }}
.row .name{{ font-size:14px; font-weight:600; overflow-wrap:anywhere; }}
.row .meta{{ font-family:var(--mono); font-size:11.5px; color:var(--text-dim); margin-top:2px; }}
.badges{{ display:flex; gap:6px; flex:none; flex-wrap:wrap; justify-content:flex-end; }}
.badge{{ font-family:var(--mono); font-size:10.5px; border-radius:999px; padding:2px 9px; white-space:nowrap; border:1px solid var(--border); }}
.badge.source-inventory{{ color:var(--up); border-color:color-mix(in srgb, var(--up) 40%, var(--border)); }}
.badge.source-cdp{{ color:var(--text-dim); }}
.badge.reason{{ color:var(--warn); border-color:color-mix(in srgb, var(--warn) 40%, var(--border)); }}
.badge.dup{{ color:var(--accent); border-color:var(--accent-dim); }}
.empty{{ font-family:var(--mono); font-size:13px; color:var(--text-dim); padding:20px; text-align:center; }}
footer{{ margin-top:20px; font-family:var(--mono); font-size:11px; color:var(--text-dim); text-align:center; }}
{banner.CSS}
</style>
</head>
<body>
{banner.html()}
<div class="wrap">
  <a class="backlink" href="index.html">← All Sites</a>
  <header>
    <div>
      <h1>Stale Devices</h1>
      <div class="subtitle">{len(stale)} device(s) across {len(by_site)} site(s) · generated {generated_at}</div>
    </div>
    <button class="icon-btn" id="theme-toggle" title="Toggle theme">\U0001F319</button>
  </header>

  <div class="kpi-grid">
    <div class="kpi"><div class="num warn">{len(stale)}</div><div class="label">Stale devices</div></div>
    <div class="kpi"><div class="num">{len(by_site)}</div><div class="label">Sites affected</div></div>
    <div class="kpi"><div class="num">{dup_count}</div><div class="label">Possible duplicates</div></div>
    <div class="kpi"><div class="num">{marked_count}</div><div class="label">Marked by hand</div></div>
  </div>

  <p class="note">
    "not seen" = the device's last-seen time is {STALE_THRESHOLD_DAYS}+ days behind its site's most recent CDP scan.
    "marked" = flagged stale by hand in Site Manager. "Possible duplicate" is a hint only (same serial,
    shared IP, or a similar name as a device at the same site that is NOT stale) - merge or delete from
    the Site Manager tab in gui.py. This page is read-only.
  </p>

  <div class="controls">
    <input id="search" type="text" placeholder="Filter by hostname, IP, platform, or site…" autocomplete="off">
    <select id="reason-filter">
      <option value="">All reasons</option>
      <option value="not seen">Not seen</option>
      <option value="marked">Marked (any)</option>
      <option value="dup">Possible duplicates only</option>
    </select>
  </div>

  <div id="panels">{body}</div>

  <footer>Site Awareness Dashboard — generated from sad.db, read-only</footer>
</div>
<script>
function applyFilters(){{
  const f = document.getElementById("search").value.trim().toLowerCase();
  const r = document.getElementById("reason-filter").value;
  document.querySelectorAll(".site-panel").forEach(panel => {{
    const siteText = panel.querySelector(".panel-head").textContent.toLowerCase();
    let any = false;
    panel.querySelectorAll(".row").forEach(row => {{
      const reason = row.dataset.reason;
      const okReason = !r || (r === "dup" ? row.dataset.dup === "1" : reason.includes(r));
      const okText = !f || row.textContent.toLowerCase().includes(f) || siteText.includes(f);
      const show = okReason && okText;
      row.style.display = show ? "" : "none";
      if(show) any = true;
    }});
    panel.style.display = any ? "" : "none";
  }});
}}
document.getElementById("search").addEventListener("input", applyFilters);
document.getElementById("reason-filter").addEventListener("change", applyFilters);
{THEME_TOGGLE_JS}
</script>
</body>
</html>
'''


def generate_stale_page(conn) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "stale.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_stale_page(conn))
    return path


# ---------------------------------------------------------------------
# All-site map
# ---------------------------------------------------------------------

def build_site_map_data(conn) -> dict:
    """Assembles everything site_map_layout.compute_layout()/
    arrange_isolated() and site_map_svg.render_svg() need: which real
    sites have qualifying inter-site connections, the deduplicated edge
    list, and per-site display metadata.

    Tunnel-only edges (CDP-derived cross-site links deliberately left
    out - see below). Deduplicated by the actual DEVICE pair (not just
    the site pair) before being aggregated into a site-pair count - a
    physical tunnel recorded from BOTH ends' own scans (once each site
    has scanned the other) is the same real connection, not two.
    Matched tunnel_links rows (device_b_id set) whose two devices
    belong to different real sites become an edge. A ONE-SIDED tunnel
    (device_b_id NULL - see match_tunnels()'s own docstring) has no
    known far end to draw an edge to, so it's counted per origin site
    instead and surfaced as a marker on that site's own node, not as a
    dangling edge.

    CDP cross-site links are NOT drawn here (deliberately dropped,
    per Cadence - this map only ever shows one node per SITE, and a
    CDP link is a specific DEVICE-to-DEVICE cable; on a site-level map
    that just reads as a same-strength edge between two sites that
    might have one link or forty, without ever showing the thing that
    would actually explain it - the individual devices and cabling.
    That's exactly what the per-site topology diagrams already show.
    Tunnels are different: a GRE tunnel genuinely IS a site-to-site
    concept (it's how one whole site reaches another over the WAN), so
    it belongs on a site-level map in a way a CDP cable between two
    specific switches doesn't).
    """
    real_sites = db.get_all_sites(conn, include_unassigned=False)
    real_site_ids = {s["id"] for s in real_sites}

    device_counts = {}
    for s in real_sites:
        device_counts[s["id"]] = conn.execute(
            "SELECT COUNT(*) AS c FROM devices WHERE site_id = ?", (s["id"],)
        ).fetchone()["c"]

    tunnel_rows = db.get_all_tunnel_links(conn)
    tunnel_device_pairs = {}
    # Interface name(s) for each device pair - a matched tunnel_links
    # pair produces two mirror-image rows (one from each side's own
    # perspective), and each row already carries BOTH ends' interface
    # names, so either row alone is enough; both are folded in here
    # (via a set) purely so this stays correct even if that ever
    # changes. Tracked per device pair first, then rolled up into
    # per-site-pair edges below, same shape as the counts.
    tunnel_device_pair_names = {}
    one_sided_counts = {}
    for row in tunnel_rows:
        if row["device_a_site_id"] not in real_site_ids:
            continue
        if row["device_b_id"] is None:
            one_sided_counts[row["device_a_site_id"]] = one_sided_counts.get(row["device_a_site_id"], 0) + 1
            continue
        if row["device_b_site_id"] not in real_site_ids:
            continue
        if row["device_a_site_id"] == row["device_b_site_id"]:
            continue  # a tunnel between two devices at the same site - not an inter-site connection to map
        key = frozenset((row["device_a_id"], row["device_b_id"]))
        tunnel_device_pairs[key] = (row["device_a_site_id"], row["device_b_site_id"])
        names = tunnel_device_pair_names.setdefault(key, set())
        if row["device_a_interface"]:
            names.add(row["device_a_interface"])
        if row["device_b_interface"]:
            names.add(row["device_b_interface"])

    tunnel_site_pair_counts = {}
    tunnel_site_pair_names = {}
    for dev_key, (site_a_id, site_b_id) in tunnel_device_pairs.items():
        key = frozenset((site_a_id, site_b_id))
        tunnel_site_pair_counts[key] = tunnel_site_pair_counts.get(key, 0) + 1
        tunnel_site_pair_names.setdefault(key, set()).update(tunnel_device_pair_names.get(dev_key, ()))

    edges = []
    for pair_key, count in tunnel_site_pair_counts.items():
        site_a_id, site_b_id = tuple(pair_key)
        edges.append({
            "site_a_id": site_a_id,
            "site_b_id": site_b_id,
            "kind": "tunnel",
            "count": count,
            "tunnel_names": sorted(tunnel_site_pair_names.get(pair_key, set())),
        })

    connected_site_ids = set()
    for edge in edges:
        connected_site_ids.add(edge["site_a_id"])
        connected_site_ids.add(edge["site_b_id"])
    isolated_site_ids = real_site_ids - connected_site_ids

    # Total edge weight touching each site - same quantity
    # site_map_layout.compute_layout() derives for itself (to decide
    # hub spacing/alignment), computed again here for site_map_svg's
    # node-sizing instead of threading it through the layout call.
    # Cheap to redo and keeps the two modules independently correct
    # rather than one silently depending on the other's internals.
    connection_weight = {}
    for edge in edges:
        connection_weight[edge["site_a_id"]] = connection_weight.get(edge["site_a_id"], 0) + edge["count"]
        connection_weight[edge["site_b_id"]] = connection_weight.get(edge["site_b_id"], 0) + edge["count"]

    site_meta = {}
    for s in real_sites:
        if not s["last_cdp_discovery"]:
            status = "none"
        elif _is_recent(s["last_cdp_discovery"]):
            status = "up"
        else:
            status = "stale"
        site_meta[s["id"]] = {
            "label": s["site_name"] or f"octet {s['site_octet']}",
            "octet": s["site_octet"],
            "href": f"site-{s['site_octet']}.html",
            "device_count": device_counts[s["id"]],
            "connection_weight": connection_weight.get(s["id"], 0),
            "status": status,
            "one_sided_tunnels": one_sided_counts.get(s["id"], 0),
        }

    return {
        "connected_site_ids": list(connected_site_ids),
        "isolated_site_ids": list(isolated_site_ids),
        "edges": edges,
        "site_meta": site_meta,
    }


def render_site_map_page(conn) -> str:
    data = build_site_map_data(conn)
    layout = site_map_layout.compute_layout(data["connected_site_ids"], data["edges"])

    cluster_bottom = site_map_layout.MARGIN
    if layout["positions"]:
        cluster_bottom = max(y for _x, y in layout["positions"].values()) + site_map_layout.MARGIN

    isolated = site_map_layout.arrange_isolated(data["isolated_site_ids"], cluster_bottom)

    canvas_width = site_map_layout.CANVAS_WIDTH
    canvas_height = max(
        site_map_layout.CANVAS_HEIGHT,
        int(cluster_bottom + isolated["height"] + site_map_layout.MARGIN),
    )

    svg = site_map_svg.render_svg(
        layout["positions"], isolated["positions"], data["edges"], data["site_meta"],
        canvas_width, canvas_height,
    )

    connected_count = len(data["connected_site_ids"])
    isolated_count = len(data["isolated_site_ids"])
    tunnel_edge_count = sum(1 for e in data["edges"] if e["kind"] == "tunnel")
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    isolated_note = ""
    if isolated_count:
        isolated_note = (
            f'<p style="padding:0 14px 14px; font-family:var(--mono); font-size:11.5px; color:var(--text-dim);">'
            f'{isolated_count} site(s) below have no known matched tunnel to any other site - '
            f'shown in a fixed grid, not part of the force-directed layout above (see legend). '
            f'CDP-derived cross-site links aren’t shown on this map - see each site’s own page for its '
            f'device-level topology.</p>'
        )

    return f'''<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>All-Site Map — Site Awareness Dashboard</title>
<style>
{CSS_TOKENS}
*{{ box-sizing: border-box; }}
body{{ margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); -webkit-font-smoothing:antialiased; }}
.wrap{{ max-width:1400px; margin:0 auto; padding:24px 24px 60px; }}
.backlink{{ display:inline-block; font-family:var(--mono); font-size:12px; color:var(--text-dim); border:1px solid var(--border); border-radius:999px; padding:5px 12px; text-decoration:none; margin-bottom:14px; }}
.backlink:hover{{ color:var(--accent); border-color:var(--accent); }}
header{{ display:flex; justify-content:space-between; align-items:flex-end; border-bottom:2px solid var(--border); padding-bottom:16px; margin-bottom:20px; gap:16px; flex-wrap:wrap; }}
header h1{{ margin:0; font-size:22px; font-weight:700; }}
.subtitle{{ font-family:var(--mono); font-size:12px; color:var(--text-dim); margin-top:4px; }}
button, .btn{{ background:var(--panel-2); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--sans); font-size:13px; padding:8px 14px; cursor:pointer; transition:border-color .15s ease, transform .1s ease; text-decoration:none; display:inline-block; }}
button:hover, .btn:hover{{ border-color:var(--accent); }}
button:active, .btn:active{{ transform:scale(.97); }}
.icon-btn{{ width:38px; height:38px; padding:0; display:flex; align-items:center; justify-content:center; font-size:16px; }}
.panel{{ background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; margin-bottom:18px; }}
.panel-head{{ background:var(--panel-2); border-bottom:1px solid var(--border); padding:8px 14px; display:flex; justify-content:space-between; align-items:center; }}
.panel-head .label{{ font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; }}
.panel-head .count{{ font-family:var(--mono); font-size:11px; background:var(--bg); border:1px solid var(--border); border-radius:999px; padding:2px 9px; color:var(--text-dim); }}
#map-viewport{{ position:relative; width:100%; height:70vh; min-height:460px; overflow:hidden; background:var(--bg); cursor:grab; }}
#map-viewport.dragging{{ cursor:grabbing; }}
#site-map{{ width:100%; height:100%; display:block; touch-action:none; }}
.map-controls{{ position:absolute; top:12px; right:12px; display:flex; flex-direction:column; gap:6px; z-index:2; }}
.map-controls button{{ width:32px; height:32px; padding:0; font-size:16px; line-height:1; }}
.map-hint{{ position:absolute; bottom:10px; left:12px; font-family:var(--mono); font-size:10.5px; color:var(--text-dim); background:color-mix(in srgb, var(--panel) 80%, transparent); border:1px solid var(--border); border-radius:6px; padding:4px 9px; pointer-events:none; }}
.site-node-link{{ text-decoration:none; cursor:pointer; }}
.site-node-circle{{ fill:var(--panel-2); stroke:var(--border); stroke-width:1.5; transition:stroke .1s ease, stroke-width .1s ease; }}
.site-node:hover .site-node-circle{{ stroke:var(--accent); stroke-width:2.5; }}
.site-node-circle.site-node-up{{ stroke:var(--up); }}
.site-node-circle.site-node-stale{{ stroke:var(--warn); }}
.site-node-circle.site-node-none{{ stroke:var(--border); stroke-dasharray:2 2; }}
.site-node-warn-dot{{ fill:var(--warn); stroke:var(--bg); stroke-width:1.5; }}
.site-node-label{{ font-family:var(--mono); font-size:10.5px; fill:var(--text); }}
.site-node-sub{{ font-family:var(--mono); font-size:9px; fill:var(--text-dim); }}
.site-edge{{ stroke:var(--text-dim); stroke-width:1.3; opacity:0.55; }}
.site-edge.tunnel{{ stroke:var(--accent); stroke-dasharray:5 4; opacity:0.85; }}
.site-edge-group:hover .site-edge{{ stroke:var(--accent); opacity:1; stroke-width:2.4; }}
.legend{{ display:flex; gap:22px; flex-wrap:wrap; padding:10px 14px; font-family:var(--mono); font-size:11px; color:var(--text-dim); border-top:1px solid var(--border); }}
.legend-item{{ display:flex; align-items:center; gap:6px; }}
.legend-swatch{{ width:22px; height:0; border-top:2px solid var(--text-dim); display:inline-block; }}
.legend-swatch.tunnel{{ border-top:2px dashed var(--accent); }}
.legend-dot{{ width:9px; height:9px; border-radius:50%; display:inline-block; border:1.5px solid var(--border); background:var(--panel-2); }}
.legend-dot.up{{ border-color:var(--up); }}
.legend-dot.stale{{ border-color:var(--warn); }}
.legend-dot.none{{ border-color:var(--border); border-style:dashed; }}
footer{{ margin-top:20px; font-family:var(--mono); font-size:11px; color:var(--text-dim); text-align:center; }}
{banner.CSS}
</style>
</head>
<body>
{banner.html()}
<div class="wrap">
  <a class="backlink" href="index.html">\u2190 All Sites</a>
  <header>
    <div>
      <h1>All-Site Map</h1>
      <div class="subtitle">{connected_count} connected \u00b7 {isolated_count} isolated \u00b7 {tunnel_edge_count} tunnel link(s) \u00b7 generated {generated_at}</div>
    </div>
    <div class="header-actions">
      <button class="icon-btn" id="theme-toggle" title="Toggle theme">\U0001F319</button>
    </div>
  </header>

  <div class="panel">
    <div class="panel-head"><span class="label">Site Map</span><span class="count">{connected_count + isolated_count} sites</span></div>
    <div id="map-viewport">
      {svg}
      <div class="map-controls">
        <button id="map-zoom-in" title="Zoom in">+</button>
        <button id="map-zoom-out" title="Zoom out">−</button>
        <button id="map-zoom-reset" title="Reset view">⌂</button>
      </div>
      <div class="map-hint">Scroll to zoom · drag to pan</div>
    </div>
    <div class="legend">
      <div class="legend-item"><span class="legend-swatch tunnel"></span>Matched tunnel</div>
      <div class="legend-item"><span class="legend-dot up"></span>Recently scanned</div>
      <div class="legend-item"><span class="legend-dot stale"></span>Not recently scanned</div>
      <div class="legend-item"><span class="legend-dot none"></span>Never CDP-scanned</div>
      <div class="legend-item"><span class="site-node-warn-dot" style="width:9px;height:9px;border-radius:50%;display:inline-block;"></span>Has an unconfirmed (one-sided) tunnel</div>
    </div>
    {isolated_note}
  </div>

  <footer>Site Awareness Dashboard — All-Site Map, generated from sad.db, read-only</footer>
</div>
<script>
{SITE_MAP_PAN_ZOOM_JS}
{THEME_TOGGLE_JS}
</script>
</body>
</html>
'''


# ---------------------------------------------------------------------
# Generation entry points
# ---------------------------------------------------------------------

CLIENT_SEARCH_MIN_QUERY_LENGTH = 4
CLIENT_SEARCH_MAX_RESULTS = 200


def _gather_all_clients_for_search(conn):
    """Pulls every client across every real site (Unassigned excluded,
    same as everywhere else on the index page) into one flat list for
    the standalone cross-site client search page. Each client's IP is
    correlated the same way render_clients_html() does per-site (via
    mac_parser.normalize_mac() against that site's own arp_entries,
    not a raw SQL join) - genuinely re-querying per site rather than
    reusing anything cached, since this needs to reflect every site's
    current data, not just whichever one/few pages happen to be
    regenerating right now.

    Includes model (from phone_enrichment, if any) alongside type, so
    the search page's badge can show the same "phone · CP-8865NR"
    detail the site pages do. Deliberately does NOT include serial/
    RIS status/RIS IP here - unlike the site page's plain rows, a
    search result row is already a link to its own site page, so
    adding a click-to-expand interaction on top of that would conflict
    with just clicking through; the fuller CUCM/RIS detail stays a
    site-page-only feature for that reason.
    """
    real_sites = [s for s in db.get_all_sites(conn) if s["site_octet"] != "unassigned"]
    enrichment_by_mac = {row["mac"]: row for row in db.get_all_phone_enrichment(conn)}

    results = []
    for site in real_sites:
        site_id = site["id"]
        client_rows = db.get_clients_for_site(conn, site_id)
        if not client_rows:
            continue
        arp_rows = db.get_arp_for_site(conn, site_id)
        devices_by_id = {d["id"]: d["hostname"] for d in db.get_devices_for_site(conn, site_id)}

        ip_by_mac = {}
        for arp in arp_rows:
            norm = mac_parser.normalize_mac(arp["mac"])
            ips = ip_by_mac.setdefault(norm, [])
            if arp["ip"] not in ips:
                ips.append(arp["ip"])

        for c in client_rows:
            ips = ip_by_mac.get(mac_parser.normalize_mac(c["mac"]), [])
            enrichment = enrichment_by_mac.get(mac_parser.normalize_mac(c["mac"]))
            results.append({
                "mac": c["mac"],
                "site": site["site_octet"],
                "siteName": site["site_name"] or "",
                "switch": devices_by_id.get(c["device_id"], ""),
                "iface": c["interface"] or "",
                "vlan": c["vlan"] or "",
                "ip": ", ".join(ips),
                "type": c["device_type"] or "",
                "model": (enrichment["model"] if enrichment else None) or "",
                "serial": (enrichment["serial_number"] if enrichment else None) or "",
                "risStatus": (enrichment["ris_status"] if enrichment else None) or "",
                "risIp": (enrichment["ris_ip"] if enrichment else None) or "",
                "phoneNumber": (enrichment["phone_number"] if enrichment else None) or "",
                "stale": _client_is_stale(c, site["last_mac_table_collection"]),
            })
    return results


def render_client_search_page(conn) -> str:
    clients = _gather_all_clients_for_search(conn)
    clients_json = json.dumps(clients)
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f'''<!DOCTYPE html>
<html data-theme="light">
<head>
<meta charset="UTF-8">
<title>Client Search \u2014 Site Awareness Dashboard</title>
<style>
{CSS_TOKENS}
body{{ margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); }}
.wrap{{ max-width:1100px; margin:0 auto; padding:24px; }}
a{{ color:inherit; }}
button, .btn{{ background:var(--panel-2); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--sans); font-size:13px; padding:8px 14px; cursor:pointer; transition:border-color .15s ease, transform .1s ease; text-decoration:none; display:inline-block; }}
button:hover, .btn:hover{{ border-color:var(--accent); }}
button:active, .btn:active{{ transform:scale(.97); }}
.header-actions{{ display:flex; gap:8px; align-items:center; }}
.icon-btn{{ width:38px; height:38px; padding:0; display:flex; align-items:center; justify-content:center; font-size:16px; }}
header{{ display:flex; justify-content:space-between; align-items:flex-start; padding-bottom:16px; border-bottom:1px solid var(--border); margin-bottom:20px; }}
h1{{ font-size:22px; margin:0 0 4px; }}
.subtitle{{ font-family:var(--mono); font-size:12px; color:var(--text-dim); }}
.backlink{{ display:inline-block; font-family:var(--mono); font-size:12px; color:var(--text-dim); border:1px solid var(--border); border-radius:999px; padding:5px 12px; text-decoration:none; margin-bottom:14px; }}
.backlink:hover{{ color:var(--accent); border-color:var(--accent); }}
.search-row{{ margin-bottom:10px; }}
#search{{ width:100%; box-sizing:border-box; background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:12px 14px; font-family:var(--mono); font-size:14px; color:var(--text); }}
#search:focus{{ outline:none; border-color:var(--accent); }}
#status{{ font-family:var(--mono); font-size:12px; color:var(--text-dim); margin-bottom:14px; }}
.row{{ display:flex; align-items:stretch; border-bottom:1px solid var(--border); background:var(--panel); }}
.row:first-child{{ border-radius:8px 8px 0 0; overflow:hidden; }}
.row:last-child{{ border-bottom:none; border-radius:0 0 8px 8px; overflow:hidden; }}
.row-main{{ flex:1; min-width:0; display:flex; align-items:center; gap:14px; padding:10px 14px; }}
.row-main:hover{{ background:var(--panel-2); }}
.row-link{{ display:flex; align-items:center; padding:0 16px; color:var(--text-dim); text-decoration:none; border-left:1px solid var(--border); font-size:16px; flex:none; }}
.row-link:hover{{ color:var(--accent); background:var(--panel-2); }}
.main{{ flex:1; min-width:0; display:flex; align-items:baseline; gap:10px; }}
.name{{ font-size:14px; font-weight:600; white-space:nowrap; }}
.meta{{ font-family:var(--mono); font-size:11.5px; color:var(--text-dim); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.match{{ background:var(--accent-dim); color:var(--text); border-radius:3px; padding:0 2px; }}
.badge{{ font-family:var(--mono); font-size:10.5px; border-radius:999px; padding:2px 9px; white-space:nowrap; border:1px solid var(--border); color:var(--accent); border-color:var(--accent-dim); flex:none; }}
.badge.stale{{ color:var(--text-dim); border-color:var(--border); border-style:dashed; }}
.remote-list{{ margin:0 16px 14px; border:1px solid var(--accent-dim); border-radius:8px; background:var(--panel-2); overflow:hidden; }}
.remote-list-title{{ font-family:var(--mono); font-size:10.5px; color:var(--text-dim); padding:8px 12px; border-bottom:1px solid var(--border); text-transform:uppercase; letter-spacing:.05em; }}
.enrich-row{{ display:flex; justify-content:space-between; gap:12px; font-family:var(--mono); font-size:12px; padding:7px 12px; border-bottom:1px solid var(--border); }}
.enrich-row:last-child{{ border-bottom:none; }}
.enrich-row span:first-child{{ color:var(--text-dim); }}
footer{{ margin-top:20px; font-family:var(--mono); font-size:11px; color:var(--text-dim); text-align:center; }}
{banner.CSS}
</style>
</head>
<body>
{banner.html()}
<div class="wrap">
  <a class="backlink" href="index.html">\u2190 All Sites</a>
  <header>
    <div>
      <h1>Client Search</h1>
      <div class="subtitle">{len(clients)} clients across {len({c["site"] for c in clients})} site(s) \u00b7 generated {generated_at}</div>
    </div>
    <div class="header-actions">
      <button class="icon-btn" id="theme-toggle" title="Toggle theme">\U0001F319</button>
    </div>
  </header>

  <div class="search-row">
    <input id="search" type="text" placeholder="Search by MAC, IP, site, switch, interface, or VLAN (min {CLIENT_SEARCH_MIN_QUERY_LENGTH} characters)\u2026" autocomplete="off">
  </div>
  <div id="status">Type at least {CLIENT_SEARCH_MIN_QUERY_LENGTH} characters to search.</div>
  <div id="results"></div>

  <footer>Data reflects the last time each site was scanned - it may be out of date. Verify anything found here before relying on it.</footer>
</div>
<script>
const CLIENTS = {clients_json};
const MIN_LEN = {CLIENT_SEARCH_MIN_QUERY_LENGTH};
const MAX_RESULTS = {CLIENT_SEARCH_MAX_RESULTS};

function normalizeMac(s) {{
  return (s || "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
}}

function escapeHtml(s) {{
  return String(s).replace(/[&<>"']/g, c => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}})[c]);
}}

function highlight(text, query) {{
  const t = String(text || "");
  const idx = t.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return escapeHtml(t);
  return escapeHtml(t.slice(0, idx)) + '<span class="match">' + escapeHtml(t.slice(idx, idx + query.length)) + '</span>' + escapeHtml(t.slice(idx + query.length));
}}

function macHtml(client, query) {{
  // Plain substring match gets precise highlighting like every other
  // field. A MAC that only matches once separators/case are stripped
  // (e.g. typing "aabbccdd" against a stored "aa:bb:cc:dd:ee:ff") gets
  // the whole field marked instead - mapping an exact substring range
  // back through a stripped-separator transform isn't worth the
  // complexity for what's already a secondary matching pass.
  if (client.mac.toLowerCase().includes(query.toLowerCase())) {{
    return highlight(client.mac, query);
  }}
  const normQuery = normalizeMac(query);
  if (normQuery.length > 0 && normalizeMac(client.mac).includes(normQuery)) {{
    return '<span class="match">' + escapeHtml(client.mac) + '</span>';
  }}
  return escapeHtml(client.mac);
}}

function matchesClient(client, query) {{
  const q = query.toLowerCase();
  const fields = ["mac", "site", "siteName", "switch", "iface", "vlan", "ip",
                  "model", "serial", "risStatus", "risIp", "phoneNumber"];
  for (const f of fields) {{
    if (String(client[f] || "").toLowerCase().includes(q)) return true;
  }}
  const normQuery = normalizeMac(query);
  if (normQuery.length > 0 && normalizeMac(client.mac).includes(normQuery)) return true;
  return false;
}}

function renderRow(client, query) {{
  const href = "site-" + client.site + ".html";
  let badges = "";
  let typeLabel = client.type === "cisco_phone" ? "phone" : (client.type === "vtc" ? "VTC" : "");
  if (typeLabel) {{
    if (client.model) typeLabel += " \u00b7 " + client.model;
    badges += '<span class="badge">' + escapeHtml(typeLabel) + '</span>';
  }}
  if (client.stale) badges += '<span class="badge stale">stale</span>';

  const hasExpand = client.serial || client.risStatus || client.risIp || client.phoneNumber;
  const panelId = "search-" + client.site + "-" + normalizeMac(client.mac);
  const mainAttrs = hasExpand ? ' onclick="toggleExpand(\\'' + panelId + '\\')" style="cursor:pointer;"' : "";

  let html = '<div class="row">'
    + '<div class="row-main"' + mainAttrs + '>'
    + '<div class="main">'
    + '<span class="name">' + highlight(client.siteName || client.site, query) + '</span>'
    + '<span class="meta">' + highlight(client.switch || "-", query)
    + ' \u00b7 ' + highlight(client.iface || "-", query)
    + ' \u00b7 VLAN ' + highlight(client.vlan || "-", query)
    + ' \u00b7 ' + highlight(client.ip || "-", query)
    + ' \u00b7 ' + macHtml(client, query)
    + '</span></div>'
    + '<div>' + badges + '</div>'
    + '</div>'
    + '<a class="row-link" href="' + href + '" title="Open the ' + escapeHtml(client.siteName || client.site) + ' site page">\u2197</a>'
    + '</div>';

  if (hasExpand) {{
    html += '<div id="' + panelId + '" class="remote-list" hidden>'
      + '<div class="remote-list-title">CUCM / RIS Details</div>'
      + '<div class="enrich-row"><span>Phone number(s)</span><span>' + escapeHtml(client.phoneNumber || "-") + '</span></div>'
      + '<div class="enrich-row"><span>Serial</span><span>' + escapeHtml(client.serial || "-") + '</span></div>'
      + '<div class="enrich-row"><span>RIS status</span><span>' + escapeHtml(client.risStatus || "-") + '</span></div>'
      + '<div class="enrich-row"><span>RIS IP</span><span>' + escapeHtml(client.risIp || "-") + '</span></div>'
      + '</div>';
  }}

  return html;
}}

function toggleExpand(id) {{
  const el = document.getElementById(id);
  el.hidden = !el.hidden;
}}

function runSearch() {{
  const query = document.getElementById("search").value.trim();
  const status = document.getElementById("status");
  const results = document.getElementById("results");

  if (query.length < MIN_LEN) {{
    status.textContent = "Type at least " + MIN_LEN + " characters to search.";
    results.innerHTML = "";
    return;
  }}

  const matched = CLIENTS.filter(c => matchesClient(c, query));
  const shown = matched.slice(0, MAX_RESULTS);

  status.textContent = matched.length > MAX_RESULTS
    ? "Showing " + MAX_RESULTS + " of " + matched.length + " results \u2014 refine your search."
    : matched.length + " result(s).";

  results.innerHTML = shown.map(c => renderRow(c, query)).join("");
}}

document.getElementById("search").addEventListener("input", runSearch);
{THEME_TOGGLE_JS}
</script>
</body>
</html>'''


def generate_client_search_page(conn) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "clients.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_client_search_page(conn))
    return path


def render_exports_page() -> str:
    """Lists whatever CSV files currently exist under OUTPUT_DIR/exports
    - a plain filesystem scan, no database access at all. Deliberately
    NOT called from generate_all()/generate_one() - this page only
    updates when csv_export.py itself calls generate_exports_page(),
    right after writing a file, so it never goes stale relative to
    what's actually in the folder, and never updates on an unrelated
    routine dashboard regeneration either.
    """
    exports_dir = os.path.join(OUTPUT_DIR, "exports")
    files = []
    if os.path.isdir(exports_dir):
        for fname in sorted(os.listdir(exports_dir)):
            if fname.lower().endswith(".csv"):
                fpath = os.path.join(exports_dir, fname)
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(fpath), tz=datetime.timezone.utc)
                files.append({"name": fname, "mtime": mtime.strftime("%Y-%m-%d %H:%M UTC")})

    if files:
        rows_html = "".join(f'''
    <a class="row" href="exports/{_esc(f["name"])}" download>
      <div class="main">
        <span class="name">{_esc(f["name"])}</span>
      </div>
      <div class="meta">{_esc(f["mtime"])}</div>
    </a>''' for f in files)
    else:
        rows_html = (
            '<p style="padding:14px; font-family:var(--mono); font-size:12px; color:var(--text-dim);">'
            'No exports yet - run utilities/csv_export.py (or the Export tab in gui.py) to create one.</p>'
        )

    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f'''<!DOCTYPE html>
<html data-theme="light">
<head>
<meta charset="UTF-8">
<title>Exports \u2014 Site Awareness Dashboard</title>
<style>
{CSS_TOKENS}
body{{ margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); }}
.wrap{{ max-width:800px; margin:0 auto; padding:24px; }}
a{{ color:inherit; }}
header{{ display:flex; justify-content:space-between; align-items:flex-start; padding-bottom:16px; border-bottom:1px solid var(--border); margin-bottom:20px; }}
header h1{{ margin:0; font-size:22px; font-weight:700; }}
.subtitle{{ font-family:var(--mono); font-size:12px; color:var(--text-dim); margin-top:4px; }}
.backlink{{ display:inline-block; font-family:var(--mono); font-size:12px; color:var(--text-dim); border:1px solid var(--border); border-radius:999px; padding:5px 12px; text-decoration:none; margin-bottom:14px; }}
.backlink:hover{{ color:var(--accent); border-color:var(--accent); }}
button, .btn{{ background:var(--panel-2); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--sans); font-size:13px; padding:8px 14px; cursor:pointer; transition:border-color .15s ease; text-decoration:none; display:inline-block; }}
button:hover, .btn:hover{{ border-color:var(--accent); }}
.header-actions{{ display:flex; gap:8px; align-items:center; }}
.icon-btn{{ width:38px; height:38px; padding:0; display:flex; align-items:center; justify-content:center; font-size:16px; }}
.panel{{ background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; }}
.row{{ display:flex; justify-content:space-between; align-items:center; gap:14px; padding:12px 14px; border-bottom:1px solid var(--border); text-decoration:none; color:inherit; }}
.row:last-child{{ border-bottom:none; }}
.row:hover{{ background:var(--panel-2); }}
.row .name{{ font-family:var(--mono); font-size:13px; font-weight:600; }}
.row .meta{{ font-family:var(--mono); font-size:11.5px; color:var(--text-dim); white-space:nowrap; }}
footer{{ margin-top:20px; font-family:var(--mono); font-size:11px; color:var(--text-dim); text-align:center; }}
{banner.CSS}
</style>
</head>
<body>
{banner.html()}
<div class="wrap">
  <a class="backlink" href="index.html">\u2190 All Sites</a>
  <header>
    <div>
      <h1>Exports</h1>
      <div class="subtitle">{len(files)} file(s) \u00b7 generated {generated_at}</div>
    </div>
    <div class="header-actions">
      <button class="icon-btn" id="theme-toggle" title="Toggle theme">\U0001F319</button>
    </div>
  </header>

  <div class="panel">{rows_html}</div>

  <footer>Exports only reflect the last time csv_export.py was run - they don't update on every dashboard regeneration.</footer>
</div>
<script>
{THEME_TOGGLE_JS}
</script>
</body>
</html>'''


def generate_exports_page() -> str:
    os.makedirs(os.path.join(OUTPUT_DIR, "exports"), exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "exports.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_exports_page())
    return path


def generate_site(conn, site_row) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"site-{site_row['site_octet']}.html"
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_site_page(conn, site_row))
    return path


def generate_index(conn) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "index.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_index_page(conn))
    return path


def generate_site_map(conn) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "site-map.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_site_map_page(conn))
    return path


def generate_all(db_path: str = None):
    db_path = db_path or db.DB_PATH
    with db.get_conn(db_path) as conn:
        sites = db.get_all_sites(conn)
        for site in sites:
            path = generate_site(conn, site)
            print(f"  Wrote {path}")
        index_path = generate_index(conn)
        print(f"  Wrote {index_path}")
        clients_path = generate_client_search_page(conn)
        print(f"  Wrote {clients_path}")
        stale_path = generate_stale_page(conn)
        print(f"  Wrote {stale_path}")
        kg_path = kg_pages.generate_kg_page(conn)
        if kg_path:
            print(f"  Wrote {kg_path}")
        # Re-derived from every site's own links/tunnel_links each
        # time, same as the index page and client search - not
        # incrementally updatable, so it's always fully regenerated
        # alongside them rather than only on some separate trigger.
        site_map_path = generate_site_map(conn)
        print(f"  Wrote {site_map_path}")
    print(f"Generated {len(sites)} site page(s) + index.")


def generate_one(site_key: str, db_path: str = None):
    db_path = db_path or db.DB_PATH
    with db.get_conn(db_path) as conn:
        site = db.find_site_by_any_key(conn, site_key)
        if site is None:
            print(f"No site found matching '{site_key}'.", file=sys.stderr)
            sys.exit(1)
        path = generate_site(conn, site)
        print(f"  Wrote {path}")
        index_path = generate_index(conn)
        print(f"  Wrote {index_path}")
        clients_path = generate_client_search_page(conn)
        print(f"  Wrote {clients_path}")
        stale_path = generate_stale_page(conn)
        print(f"  Wrote {stale_path}")
        kg_path = kg_pages.generate_kg_page(conn)
        if kg_path:
            print(f"  Wrote {kg_path}")
        # This one site's own cross-site links/tunnels can change the
        # all-site map too (a new inter-site edge, a newly-matched
        # tunnel) - regenerated alongside the index for the same
        # reason, every time, not just on a full "all sites" run.
        site_map_path = generate_site_map(conn)
        print(f"  Wrote {site_map_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", metavar="KEY", help="Regenerate just one site (plus the index) instead of everything")
    args = parser.parse_args()

    if args.site:
        generate_one(args.site)
    else:
        generate_all()