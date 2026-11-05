"""
kg_pages.py - dashboard HTML for GEM One KG (TACLANE) devices.

  render_site_panel(conn, site_id)   the collapsed "KG Devices" panel on a site page ("" when the site has none)
  render_kg_fleet_page(conn)         kg.html: every KG, soonest KEYMAT expiry first, with filters
  generate_kg_page(conn)             writes dashboard/kg.html (only when there are KGs)
  summary(conn)                      counts for the index page

Health (ok / warning / critical / unknown) is worked out here from the stored
fields and the thresholds in settings.json (see utilities/kg_health.py), so
changing a threshold only needs the dashboard regenerated, not a re-import.
Colors follow the rest of the dashboard: critical = --warn (red),
warning = --accent (amber), ok = --up (green).
"""
import datetime
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "utilities"))

import db  # noqa: E402
import kg_health  # noqa: E402
import settings_loader  # noqa: E402
import banner  # noqa: E402

OUTPUT_DIR = os.path.join(HERE, "dashboard")
_RANK = {"critical": 3, "warning": 2, "unknown": 1, "ok": 0}
_DOT = {"ok": "var(--up)", "warning": "var(--accent)", "critical": "var(--warn)", "unknown": "var(--text-dim)"}
_TXT = {"critical": "kg-c-crit", "warning": "kg-c-warn", "ok": "kg-c-dim", "unknown": "kg-c-dim"}
SA_VISIBLE = 8   # association rows shown before "show N more"

CSS = """
.kg-mono{ font-family:var(--mono); }
.kg-c-crit{ color:var(--warn); } .kg-c-warn{ color:var(--accent); } .kg-c-dim{ color:var(--text-dim); }
.kg-panel.kg-has-crit{ border-color:var(--warn); }
.kg-pill{ font-family:var(--mono); font-size:11px; border:1px solid var(--border); border-radius:999px; padding:2px 9px; white-space:nowrap; }
.kg-pill.crit{ color:var(--warn); border-color:var(--warn); } .kg-pill.warn{ color:var(--accent); border-color:var(--accent); }
.kg-pill.dashed{ border-style:dashed; color:var(--text-dim); }
.kg-head-note{ font-family:var(--mono); font-size:11px; color:var(--text-dim); }
.kg-cols, .kg-sum{ display:grid; grid-template-columns:2.1fr 1.4fr 1.6fr 1.3fr 1.5fr; gap:12px; align-items:center; padding:9px 14px; }
.kg-cols{ border-bottom:1px solid var(--border); font-family:var(--mono); font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--text-dim); }
details.kg{ border-bottom:1px solid var(--border); border-left:3px solid transparent; }
details.kg:last-of-type{ border-bottom:none; }
details.kg.h-critical{ border-left-color:var(--warn); } details.kg.h-warning{ border-left-color:var(--accent); }
details.kg > summary{ list-style:none; cursor:pointer; } details.kg > summary::-webkit-details-marker{ display:none; }
details.kg[open] > summary, details.kg > summary:hover{ background:var(--panel-2); }
.kg-name{ font-size:14px; font-weight:600; overflow-wrap:anywhere; }
.kg-sub{ font-family:var(--mono); font-size:11.5px; color:var(--text-dim); margin-top:2px; overflow-wrap:anywhere; }
.kg-state{ display:flex; align-items:center; gap:7px; font-size:13px; }
.kg-dot{ width:9px; height:9px; border-radius:50%; flex:none; display:inline-block; }
.kg-cell{ font-family:var(--mono); font-size:12.5px; }
.kg-flags{ display:flex; gap:6px; flex-wrap:wrap; margin-top:4px; }
.kg-body{ padding:14px 14px 16px; display:flex; flex-direction:column; gap:14px; }
.kg-why{ font-size:12.5px; color:var(--text-dim); }
.kg-cards{ display:grid; grid-template-columns:repeat(auto-fit, minmax(190px,1fr)); gap:12px; }
.kg-card{ background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:10px 12px; display:flex; flex-direction:column; gap:4px; }
.kg-card .t{ font-family:var(--mono); font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--text-dim); }
.kg-card .v{ font-family:var(--mono); font-size:13px; overflow-wrap:anywhere; }
.kg-card .s{ font-size:12px; color:var(--text-dim); display:flex; align-items:center; gap:6px; }
.kg-sa{ border:1px solid var(--border); border-radius:8px; overflow:hidden; }
.kg-sa-head{ background:var(--bg); padding:8px 12px; display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; border-bottom:1px solid var(--border); }
.kg-sa-head .l{ font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; }
.kg-sa-head .l span{ font-family:var(--mono); font-weight:400; color:var(--text-dim); }
.kg-sa-head button{ font-size:12px; padding:3px 11px; border-radius:999px; }
.kg-sa-head button.on{ border-color:var(--accent); color:var(--accent); }
.sa-row{ display:grid; grid-template-columns:1.3fr 1.3fr 1.8fr 1.2fr 1fr; gap:12px; padding:7px 12px; border-bottom:1px solid var(--border); font-family:var(--mono); font-size:12px; align-items:center; overflow-wrap:anywhere; }
.sa-row.hd{ font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--text-dim); }
.sa-row .peer{ font-family:var(--sans); } .sa-row .peer a{ color:inherit; text-decoration:none; } .sa-row .peer a:hover{ color:var(--accent); }
.sa-row.extra{ display:none; }
.kg-sa.show-all .sa-row.extra{ display:grid; }
.kg-sa.only-bad .sa-row:not(.bad):not(.hd){ display:none; }
.kg-sa.only-bad .sa-row.bad{ display:grid; }
.sa-more{ display:block; width:100%; text-align:center; font-size:12px; color:var(--text-dim); background:var(--panel-2); border:none; border-radius:0; padding:8px; }
.sa-more:hover{ color:var(--accent); }
.kg-foot{ background:var(--panel-2); border-top:1px solid var(--border); padding:8px 14px; display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; font-family:var(--mono); font-size:11px; color:var(--text-dim); }
@media (max-width:820px){ .kg-cols{ display:none; } .kg-sum{ grid-template-columns:1fr 1fr; } .sa-row{ grid-template-columns:1fr 1fr; } }
"""

JS = """
function kgOnlyBad(btn){ var box = btn.closest('.kg-sa'); box.classList.toggle('only-bad'); btn.classList.toggle('on'); }
function kgShowAll(btn){ btn.closest('.kg-sa').querySelectorAll('.sa-row.extra').forEach(function(r){ r.classList.remove('extra'); }); btn.remove(); }
function kgOpenFromHash(){
  var h = location.hash; if(h.indexOf('#kg-') !== 0) return;
  var el = document.getElementById(h.slice(1)); if(!el) return;
  for(var p = el; p; p = p.parentElement){ if(p.tagName === 'DETAILS') p.open = true; }
  el.scrollIntoView();
}
window.addEventListener('hashchange', kgOpenFromHash); kgOpenFromHash();
"""


def _esc(s) -> str:
    return "" if s is None else str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _slug(serial: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", serial or "")


def _fmt_ts(ts) -> str:
    if not ts:
        return "never"
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return str(ts)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _days_text(days):
    if days is None:
        return "no date"
    if days < 0:
        return f"expired {_plural(-days, 'day')} ago"
    if days == 0:
        return "expires today"
    return _plural(days, "day")


def _load(conn, site_id=None):
    """Returns (kgs, cfg, today, settings_note). Each kg is a dict with an "ev" health result."""
    note = None
    try:
        cfg = settings_loader.get_section("gemone")
    except settings_loader.SettingsError as e:
        cfg = dict(settings_loader.DEFAULTS["gemone"])
        note = f"settings.json could not be read, default thresholds used ({e})"
    today = datetime.date.today()
    kgs = []
    for row in db.get_kg_devices(conn, site_id=site_id):
        k = dict(row)
        k["ev"] = kg_health.evaluate(k, cfg, today, unreachable=k["assoc_unreachable"])
        kgs.append(k)
    return kgs, cfg, today, note


def _name(k) -> str:
    return k["system_name"] or k["serial_number"]


def _site_href(k) -> str:
    octet = k["site_octet"] or "unassigned"
    return f"site-{_esc(octet)}.html#kg-{_slug(k['serial_number'])}"


def _freshness(conn, cfg):
    """(html text, css class) describing how old the imported data is."""
    last = db.get_kg_last_import(conn)
    if last is None or not last["file_collected_at"]:
        return "No GEM One file imported yet", "kg-c-warn"
    try:
        collected = datetime.datetime.fromisoformat(last["file_collected_at"])
        age_days = (datetime.datetime.now(datetime.timezone.utc) - collected).total_seconds() / 86400
    except ValueError:
        return f"Data from file collected {_esc(last['file_collected_at'])}", "kg-c-dim"
    limit = cfg.get("data_stale_after_days")
    if age_days >= 1:
        age = _plural(int(age_days), "day") + " old"
    else:
        age = f"{max(1, int(age_days * 24))} h old" if age_days * 24 >= 1 else "under an hour old"
    stale = limit is not None and age_days > limit
    return (f"Data from file collected {_fmt_ts(last['file_collected_at'])} ({age})"
            + (" - older than expected, run the GEM One pull" if stale else "")), ("kg-c-warn" if stale else "kg-c-dim")


def _is_manual(k) -> bool:
    return k.get("source") == "manual"


_MANUAL_TITLE = "Entered by hand. This unit is not read by GEM One."


def _flags(k, cfg) -> str:
    out = []
    if _is_manual(k):
        out.append(f'<span class="kg-pill dashed" title="{_MANUAL_TITLE}">manual</span>')
    if k["missing_since"]:
        out.append(f'<span class="kg-pill dashed" title="Not in the latest GEM One file since {_esc(k["missing_since"])}">not in latest file</span>')
    if k["last_error"]:
        out.append(f'<span class="kg-pill crit" title="{_esc(k["last_error"])}">last pull failed</span>')
    return f'<div class="kg-flags">{"".join(out)}</div>' if out else ""


def _summary_row(k, cfg) -> str:
    ev = k["ev"]
    state = k["state"] or "unknown"
    km = (f'<span class="kg-mono">{_esc(k["ffvs_exp_date"])}</span> <span class="{_TXT[ev["keymat_health"]]}">&middot; {_days_text(ev["keymat_days"])}</span>'
          if k["ffvs_exp_date"] else '<span class="kg-c-dim">-</span>')
    bt = (f'<span class="kg-mono">{_esc(k["battery_change_date"])}</span> <span class="{_TXT[ev["battery_health"]]}">&middot; {ev["battery_years"]} yr</span>'
          if k["battery_change_date"] else '<span class="kg-c-dim">-</span>')
    total, bad = k["assoc_total"], k["assoc_unreachable"]
    if not total and _is_manual(k):
        sa = '<span class="kg-c-dim">-</span>'
    elif not total:
        sa = '0 <span class="kg-c-dim">&middot; none</span>'
    elif bad:
        sa = f'{total} <span class="kg-c-warn">&middot; {bad} unreachable</span>'
    else:
        sa = f'{total} <span class="kg-c-dim">&middot; all reachable</span>'
    return f'''<div class="kg-sum" title="{_esc('; '.join(ev['reasons']))}">
      <div><div class="kg-name">{_esc(_name(k))}</div><div class="kg-sub">{_esc(k["device_type"] or "-")} &middot; {_esc(k["serial_number"])}</div>{_flags(k, cfg)}</div>
      <div class="kg-state"><span class="kg-dot" style="background:{_DOT[ev['state_health']]}"></span>{_esc(state)}</div>
      <div class="kg-cell">{km}</div>
      <div class="kg-cell">{bt}</div>
      <div class="kg-cell">{sa}</div>
    </div>'''


def _iface_card(title, ip, mac, status) -> str:
    up = (status or "").strip().lower()
    color = "var(--up)" if up == "up" else "var(--warn)" if up == "down" else "var(--text-dim)"
    return (f'<div class="kg-card"><div class="t">{title}</div><div class="v">{_esc(ip or "-")}</div>'
            f'<div class="v kg-c-dim" style="font-size:11.5px">{_esc(mac or "-")}</div>'
            f'<div class="s"><span class="kg-dot" style="background:{color};width:8px;height:8px"></span>'
            f'{"Interface " + _esc(status) if status else "Interface status unknown"}</div></div>')


def _if_cell(ip, status) -> str:
    """The interface IP, with a dot showing its status (hover for the text), for the fleet page."""
    up = (status or "").strip().lower()
    color = "var(--up)" if up == "up" else "var(--warn)" if up == "down" else "var(--text-dim)"
    return (f'<span class="kg-dot" style="background:{color};width:8px;height:8px" title="Interface {_esc(status) if status else "status unknown"}"></span> '
            f'<span class="kg-mono">{_esc(ip) if ip else "-"}</span>')


def _reachable_counts(conn) -> dict:
    """{kg_id: number of security associations whose pair is reachable}."""
    return {r[0]: r[1] for r in conn.execute(
        "SELECT kg_id, COUNT(*) FROM kg_security_associations WHERE pair_reachable = 1 GROUP BY kg_id")}


def _peers(all_kgs) -> dict:
    peers = {}
    for k in all_kgs:
        for ip in (k["ct_ip"], k["pt_ip"]):
            if ip:
                peers[ip] = k
    return peers


def _assoc_html(conn, k, peers) -> str:
    rows = db.get_kg_associations(conn, k["id"])
    if not rows:
        return '<div class="kg-sa"><div class="kg-sa-head"><div class="l">Security associations <span>0</span></div></div></div>'
    bad = sum(1 for r in rows if r["pair_reachable"] == 0)
    parts = []
    for i, r in enumerate(rows):
        peer = peers.get(r["remote_ct"]) or peers.get(r["remote_pt"])
        if peer is not None and peer["id"] != k["id"]:
            manual_tag = f' <span class="kg-pill dashed" title="{_MANUAL_TITLE}">manual</span>' if _is_manual(peer) else ""
            peer_html = f'<a href="{_site_href(peer)}">{_esc(_name(peer))}</a> <span class="kg-c-dim">&middot; site {_esc(peer["site_octet"] or "?")}</span>{manual_tag}'
        else:
            peer_html = '<span class="kg-c-dim">not in SAD</span>'
        reach = r["pair_reachable"]
        dot, label = (("var(--up)", "Yes") if reach == 1 else ("var(--warn)", "No") if reach == 0 else ("var(--text-dim)", "?"))
        cls = "sa-row" + (" bad" if reach == 0 else "") + (" extra" if i >= SA_VISIBLE else "")
        parts.append(
            f'<div class="{cls}"><div>{_esc(r["remote_ct"] or "-")}</div><div>{_esc(r["remote_pt"] or "-")}</div>'
            f'<div class="peer">{peer_html}</div><div>{_esc(r["method"] or "-")}</div>'
            f'<div><span class="kg-dot" style="background:{dot};width:8px;height:8px"></span> {label}</div></div>')
    more = ""
    if len(rows) > SA_VISIBLE:
        more = f'<button class="sa-more" onclick="kgShowAll(this)">&hellip; {len(rows) - SA_VISIBLE} more (click to show)</button>'
    filt = f'<button onclick="kgOnlyBad(this)">Unreachable only ({bad})</button>' if bad else ""
    return (f'<div class="kg-sa"><div class="kg-sa-head"><div class="l">Security associations <span>{len(rows)}</span></div>{filt}</div>'
            f'<div class="sa-row hd"><div>Remote CT</div><div>Remote PT</div><div>Peer in SAD</div><div>Method</div><div>Reachable</div></div>'
            f'{"".join(parts)}{more}</div>')


def _device_block(conn, k, cfg, peers) -> str:
    ev = k["ev"]
    why = ("Needs attention: " + "; ".join(ev["reasons"])) if ev["reasons"] else "No problems found by the current thresholds."
    if k["last_error"]:
        why += f" Last pull failed: {k['last_error']}."
    if _is_manual(k):
        why = ("Entered by hand, so there is no GEM One data for it. "
               + (("Needs attention: " + "; ".join(ev["reasons"])) if ev["reasons"] else
                  "Health shows as unknown until a state or dates are filled in (Edit on the KG devices tab in SAD)."
                  if ev["health"] == "unknown" else "No problems found by the current thresholds."))
    if _is_manual(k):
        data_card = (f'<div class="kg-card"><div class="t">Source</div><div class="v">Manual entry</div>'
                     f'<div class="s">added {_fmt_ts(k["first_seen"])}</div></div>')
    else:
        data_card = (f'<div class="kg-card"><div class="t">GEM One data</div><div class="v">{_fmt_ts(k["data_collected_at"])}</div>'
                     f'<div class="s">first seen {_fmt_ts(k["first_seen"])}</div></div>')
    return f'''
    <details class="kg h-{ev['health']}" id="kg-{_slug(k['serial_number'])}">
      <summary>{_summary_row(k, cfg)}</summary>
      <div class="kg-body">
        <div class="kg-why">{_esc(why)}</div>
        <div class="kg-cards">
          {_iface_card("PT Interface", k["pt_ip"], k["pt_mac"], k["pt_status"])}
          {_iface_card("CT Interface", k["ct_ip"], k["ct_mac"], k["ct_status"])}
          <div class="kg-card"><div class="t">Software</div><div class="v">{_esc(k["software_version"] or "-")}</div><div class="s">{_esc(k["device_type"] or "")}</div></div>
          {data_card}
        </div>
        {_assoc_html(conn, k, peers)}
      </div>
    </details>'''


def _sorted(kgs):
    return sorted(kgs, key=lambda k: (-_RANK[k["ev"]["health"]], _name(k).lower()))


def _counts(kgs) -> dict:
    c = {"critical": 0, "warning": 0, "unknown": 0, "ok": 0}
    for k in kgs:
        c[k["ev"]["health"]] += 1
    return c


def render_site_panel(conn, site_id: int) -> str:
    """The collapsed KG panel for one site page, or "" when the site has no KGs."""
    kgs, cfg, today, note = _load(conn, site_id)
    if not kgs:
        return ""
    peers = _peers(_load(conn)[0])
    c = _counts(kgs)
    pills = ""
    if c["critical"]:
        pills += f'<span class="kg-pill crit">{c["critical"]} critical</span>'
    if c["warning"]:
        pills += f'<span class="kg-pill warn">{c["warning"]} warning</span>'
    dated = [k["ev"]["keymat_days"] for k in kgs if k["ev"]["keymat_days"] is not None]
    nxt = ""
    if dated:
        soon = min(dated)
        health = "critical" if soon <= (cfg.get("keymat_critical_days") or 0) else "warning" if soon <= (cfg.get("keymat_warn_days") or 0) else "ok"
        nxt = f'<span class="kg-head-note {_TXT[health]}">next KEYMAT: {_days_text(soon)}</span>'
    fresh, fresh_cls = _freshness(conn, cfg)
    missing = sum(1 for k in kgs if k["missing_since"])
    foot_right = f"{_plural(missing, 'KG')} not in the latest file" if missing else ""
    if note:
        foot_right = (foot_right + " | " if foot_right else "") + _esc(note)
    body = "".join(_device_block(conn, k, cfg, peers) for k in _sorted(kgs))
    return f'''
  <details class="panel kg-panel{' kg-has-crit' if c['critical'] else ''}" id="kg-panel">
    <summary class="panel-head"><span class="label"><span class="chevron">▸</span>KG Devices</span><span style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">{nxt}{pills}<span class="count">{len(kgs)} total</span></span></summary>
    <div class="kg-cols"><div>Device</div><div>State</div><div>KEYMAT expires</div><div>Battery changed</div><div>Associations</div></div>
    {body}
    <div class="kg-foot"><div class="{fresh_cls}">{fresh}</div><div>{foot_right}</div></div>
  </details>'''


def summary(conn) -> dict:
    """Counts for the index page: {"total", "critical", "warning", "attention"}."""
    kgs, cfg, today, note = _load(conn)
    c = _counts(kgs)
    return {"total": len(kgs), "critical": c["critical"], "warning": c["warning"], "attention": c["critical"] + c["warning"]}


# ---------------------------------------------------------------------
# Fleet page
# ---------------------------------------------------------------------

def render_kg_fleet_page(conn) -> str:
    import dashboard_generate as dg   # shared theme tokens and helpers; imported late to avoid a circular import
    kgs, cfg, today, note = _load(conn)
    reachable = _reachable_counts(conn)
    c = _counts(kgs)
    warn_days = cfg.get("keymat_warn_days") or 0
    expiring = sum(1 for k in kgs if k["ev"]["keymat_days"] is not None and k["ev"]["keymat_days"] <= warn_days)
    unassigned = sum(1 for k in kgs if (k["site_octet"] or "unassigned") == "unassigned")
    manual_count = sum(1 for k in kgs if _is_manual(k))
    kgs.sort(key=lambda k: (k["ev"]["keymat_days"] is None, k["ev"]["keymat_days"] if k["ev"]["keymat_days"] is not None else 0, _name(k).lower()))
    fresh, fresh_cls = _freshness(conn, cfg)
    rows = []
    for k in kgs:
        ev = k["ev"]
        site = "Unassigned" if (k["site_octet"] or "unassigned") == "unassigned" else (k["site_name"] or f"Site {k['site_octet']}")
        km = (f'<span class="kg-mono">{_esc(k["ffvs_exp_date"])}</span> <span class="{_TXT[ev["keymat_health"]]}">&middot; {_days_text(ev["keymat_days"])}</span>'
              if k["ffvs_exp_date"] else '<span class="kg-c-dim">no KEYMAT date</span>')
        bt = (f'<span class="kg-mono">{ev["battery_years"]} yr</span>' if k["battery_change_date"] else '<span class="kg-c-dim">-</span>')
        total_sa = k["assoc_total"]
        ok_sa = reachable.get(k["id"], 0)
        if not total_sa and _is_manual(k):
            sa_cell = '<span class="kg-c-dim">-</span>'
        elif not total_sa:
            sa_cell = '<span class="kg-c-dim">no SAs</span>'
        else:
            sa_cell = f'<span class="{"kg-c-warn" if k["assoc_unreachable"] else ""}">{ok_sa} of {total_sa} SAs</span>'
        flags = []
        if k["missing_since"]:
            flags.append("missing")
        if k["last_error"]:
            flags.append("error")
        rows.append(f'''
      <a class="row kg-row" href="{_site_href(k)}" data-health="{ev['health']}" data-flags="{' '.join(flags)}" data-state="{_esc((k['state'] or '').lower())}" data-days="{ev['keymat_days'] if ev['keymat_days'] is not None else 999999}" data-batt="{ev['battery_years'] if ev['battery_years'] is not None else -1}" data-name="{_esc(_name(k).lower())}" data-site="{_esc(site.lower())}">
        <span class="kg-dot" style="background:{_DOT[ev['health']]}" title="{_esc(ev['health'])}"></span>
        <div class="main">
          <div class="name">{_esc(_name(k))}</div>
          <div class="meta">{_esc(site)} &middot; {_esc(k["device_type"] or "-")} &middot; {_esc(k["serial_number"])}</div>
        </div>
        <div class="kg-col"><div class="kg-lbl">PT IP</div>{_if_cell(k["pt_ip"], k["pt_status"])}</div>
        <div class="kg-col"><div class="kg-lbl">CT IP</div>{_if_cell(k["ct_ip"], k["ct_status"])}</div>
        <div class="kg-col"><div class="kg-lbl">Software</div><span class="kg-mono">{_esc(k["software_version"] or "-")}</span></div>
        <div class="kg-col"><div class="kg-lbl">KEYMAT</div>{km}</div>
        <div class="kg-col"><div class="kg-lbl">Battery age</div>{bt}</div>
        <div class="kg-col"><div class="kg-lbl">Reachable</div>{sa_cell}</div>
        <div class="badges">{''.join(f'<span class="badge reason">{f}</span>' for f in flags)}{'<span class="badge" title="' + _MANUAL_TITLE + '">manual</span>' if _is_manual(k) else ""}</div>
      </a>''')
    body = "".join(rows) if rows else '<p class="empty">No KG devices have been imported yet.</p>'
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f'''<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KG Devices — Site Awareness Dashboard</title>
<style>
{dg.CSS_TOKENS}
*{{ box-sizing: border-box; }}
body{{ margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); -webkit-font-smoothing:antialiased; }}
.wrap{{ max-width:1200px; margin:0 auto; padding:24px 24px 60px; }}
a{{ color:inherit; }}
.backlink{{ display:inline-block; font-family:var(--mono); font-size:12px; color:var(--text-dim); border:1px solid var(--border); border-radius:999px; padding:5px 12px; text-decoration:none; margin-bottom:14px; }}
.backlink:hover{{ color:var(--accent); border-color:var(--accent); }}
header{{ display:flex; justify-content:space-between; align-items:flex-end; border-bottom:2px solid var(--border); padding-bottom:16px; margin-bottom:20px; gap:16px; flex-wrap:wrap; }}
header h1{{ margin:0; font-size:22px; font-weight:700; }}
.subtitle{{ font-family:var(--mono); font-size:12px; color:var(--text-dim); margin-top:4px; }}
button{{ background:var(--panel-2); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--sans); font-size:13px; padding:8px 14px; cursor:pointer; }}
button:hover{{ border-color:var(--accent); }}
.icon-btn{{ width:38px; height:38px; padding:0; display:flex; align-items:center; justify-content:center; font-size:16px; }}
.kpi-grid{{ display:flex; flex-wrap:wrap; justify-content:center; gap:12px; margin-bottom:20px; }}
.kpi{{ flex:0 1 190px; background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); padding:14px 16px; text-align:center; }}
.kpi .num{{ font-family:var(--mono); font-size:26px; font-weight:700; }}
.kpi .num.warn{{ color:var(--warn); }} .kpi .num.amber{{ color:var(--accent); }}
.kpi .label{{ font-family:var(--mono); font-size:11px; text-transform:uppercase; letter-spacing:.07em; color:var(--text-dim); margin-top:4px; }}
.controls{{ display:flex; gap:10px; margin-bottom:14px; flex-wrap:wrap; }}
#search{{ flex:1; min-width:220px; background:var(--panel); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--mono); font-size:13px; padding:10px 14px; }}
#sort-by, #health-filter{{ background:var(--panel); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:var(--mono); font-size:13px; padding:10px 12px; }}
#search:focus, #sort-by:focus, #health-filter:focus{{ outline:none; border-color:var(--accent); }}
.note{{ font-family:var(--mono); font-size:11.5px; color:var(--text-dim); margin:0 0 16px; line-height:1.5; }}
.panel{{ background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; margin-bottom:14px; }}
.row{{ display:flex; align-items:center; gap:14px; padding:10px 14px; border-bottom:1px solid var(--border); text-decoration:none; color:inherit; }}
.row:last-child{{ border-bottom:none; }} .row:hover{{ background:var(--panel-2); }}
.row .main{{ flex:1.6; min-width:0; }}
.row .name{{ font-size:14px; font-weight:600; overflow-wrap:anywhere; }}
.row .meta{{ font-family:var(--mono); font-size:11.5px; color:var(--text-dim); margin-top:2px; overflow-wrap:anywhere; }}
.kg-col{{ flex:1; min-width:0; font-family:var(--mono); font-size:12.5px; }}
.kg-lbl{{ font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:var(--text-dim); margin-bottom:2px; }}
.badges{{ display:flex; gap:6px; flex:none; flex-wrap:wrap; justify-content:flex-end; min-width:70px; }}
.badge{{ font-family:var(--mono); font-size:10.5px; border-radius:999px; padding:2px 9px; white-space:nowrap; border:1px solid var(--border); }}
.badge.reason{{ color:var(--warn); border-color:color-mix(in srgb, var(--warn) 40%, var(--border)); }}
{CSS}
.empty{{ font-family:var(--mono); font-size:13px; color:var(--text-dim); padding:20px; text-align:center; }}
footer{{ margin-top:20px; font-family:var(--mono); font-size:11px; color:var(--text-dim); text-align:center; }}
@media (max-width:820px){{ .row{{ flex-wrap:wrap; }} .kg-col{{ flex:1 1 40%; }} }}
{banner.CSS}
</style>
</head>
<body>
{banner.html()}
<div class="wrap">
  <a class="backlink" href="index.html">← All Sites</a>
  <header>
    <div>
      <h1>KG Devices</h1>
      <div class="subtitle">{len(kgs)} KG(s){f" ({manual_count} entered by hand)" if manual_count else ""} · generated {generated_at}</div>
    </div>
    <button class="icon-btn" id="theme-toggle" title="Toggle theme">\U0001F319</button>
  </header>

  <div class="kpi-grid">
    <div class="kpi"><div class="num">{len(kgs)}</div><div class="label">KG devices</div></div>
    <div class="kpi"><div class="num {'warn' if c['critical'] else ''}">{c['critical']}</div><div class="label">Critical</div></div>
    <div class="kpi"><div class="num {'amber' if c['warning'] else ''}">{c['warning']}</div><div class="label">Warning</div></div>
    <div class="kpi"><div class="num {'amber' if expiring else ''}">{expiring}</div><div class="label">KEYMAT within {warn_days} days</div></div>
    <div class="kpi"><div class="num {'amber' if unassigned else ''}">{unassigned}</div><div class="label">No site assigned</div></div>
  </div>

  <p class="note">
    Starts sorted by soonest KEYMAT expiry; use the sort menu to change it. Health is worked out from the thresholds in settings.json (state, KEYMAT expiry,
    battery age, interface status). Click a row to open that KG on its site page. {_esc(note or '')}
  </p>

  <div class="controls">
    <input id="search" type="text" placeholder="Filter by name, serial, site, state…" autocomplete="off">
    <select id="sort-by" title="Sort order">
      <option value="keymat">Sort: soonest KEYMAT</option>
      <option value="health">Sort: worst health first</option>
      <option value="battery">Sort: oldest battery</option>
      <option value="name">Sort: name</option>
      <option value="site">Sort: site</option>
    </select>
    <select id="health-filter">
      <option value="">All health levels</option>
      <option value="critical">Critical</option>
      <option value="warning">Warning</option>
      <option value="unknown">Unknown</option>
      <option value="ok">OK</option>
      <option value="flagged">Missing or failed to pull</option>
    </select>
  </div>

  <div class="panel" id="rows">{body}</div>

  <footer><span class="{fresh_cls}">{fresh}</span> — Site Awareness Dashboard, generated from sad.db, read-only</footer>
</div>
<script>
function applyFilters(){{
  const f = document.getElementById("search").value.trim().toLowerCase();
  const h = document.getElementById("health-filter").value;
  document.querySelectorAll("#rows .kg-row").forEach(row => {{
    const okH = !h || (h === "flagged" ? row.dataset.flags !== "" : row.dataset.health === h);
    const okT = !f || (row.textContent + " " + (row.dataset.state || "")).toLowerCase().includes(f);
    row.style.display = (okH && okT) ? "" : "none";
  }});
}}
const RANK = {{critical:3, warning:2, unknown:1, ok:0}};
function num(r, k){{ return parseFloat(r.dataset[k]); }}
function byName(a, b){{ return a.dataset.name < b.dataset.name ? -1 : a.dataset.name > b.dataset.name ? 1 : 0; }}
const SORTS = {{
  keymat:  (a, b) => num(a, "days") - num(b, "days") || byName(a, b),
  health:  (a, b) => RANK[b.dataset.health] - RANK[a.dataset.health] || num(a, "days") - num(b, "days") || byName(a, b),
  battery: (a, b) => num(b, "batt") - num(a, "batt") || byName(a, b),
  name:    byName,
  site:    (a, b) => (a.dataset.site < b.dataset.site ? -1 : a.dataset.site > b.dataset.site ? 1 : 0) || byName(a, b),
}};
function applySort(){{
  const box = document.getElementById("rows");
  Array.from(box.querySelectorAll(".kg-row")).sort(SORTS[document.getElementById("sort-by").value]).forEach(r => box.appendChild(r));
}}
document.getElementById("sort-by").addEventListener("change", applySort);
document.getElementById("search").addEventListener("input", applyFilters);
document.getElementById("health-filter").addEventListener("change", applyFilters);
{dg.THEME_TOGGLE_JS}
</script>
</body>
</html>
'''


def generate_kg_page(conn):
    """Writes dashboard/kg.html when there are KGs; returns its path, or None."""
    if not db.get_kg_devices(conn):
        return None
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "kg.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_kg_fleet_page(conn))
    return path