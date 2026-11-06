"""
aci_pages.py (v1.0) - builds the static ACI explorer (dashboard/aci.html plus
dashboard/aci/*.js data files) from the newest stored APIC pull of each site.

Python only emits data; all behavior lives in aci_template.html. Per site:
  <octet>_index.js   small: every entity as [dn, class, label] (search + tree roots)
  <octet>_<n>.js     entity details (attributes, children, edges), n = crc32(dn) % shards,
                     loaded by the page only when an entity is opened
Plain .js files (script tags) so it works from a file share. A manifest skips a site
whose pull, anchors and overrides have not changed.

Usage:  python3 aci_pages.py        (the dashboard generate action can call generate_aci_pages too)
"""
import datetime
import json
import os
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "utilities"))

import db  # noqa: E402
import aci_db  # noqa: E402
import aci_graph  # noqa: E402
import banner  # noqa: E402
from config_viewer import CSS_TOKENS, _write_atomic, _dump  # noqa: E402

OUTPUT_DIR = os.path.join(HERE, "dashboard")
TEMPLATE_PATH = os.path.join(HERE, "aci_template.html")
PER_SHARD = 400


def _site_label(dn, e):
    a = e["a"]
    if e["c"] and a.get("tDn") and "Rs" in e["c"]:
        return aci_graph.split_dn(a["tDn"])[-1]
    return aci_graph.label(dn, a)


def generate_aci_pages(conn, out_dir: str = None) -> dict:
    out_dir = out_dir or OUTPUT_DIR
    data_dir = os.path.join(out_dir, "aci")
    os.makedirs(data_dir, exist_ok=True)
    aci_db.ensure(conn)
    try:
        with open(os.path.join(data_dir, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        manifest = {}
    stats = {"sites": 0, "written": 0, "skipped": 0}
    sites = []
    for s in conn.execute("""SELECT id, site_octet, site_name FROM sites WHERE deleted_at IS NULL AND id IN
                             (SELECT DISTINCT site_id FROM aci_raw) ORDER BY site_octet""").fetchall():
        sid, octet = s["id"], s["site_octet"]
        pulls, when, sig = aci_db.latest_pulls(conn, sid)
        anchors, overrides = aci_db.overlay(conn, sid)
        sig += f":{len(anchors)}:{len(overrides)}:{max([o['at'] or '' for o in overrides] + [a['source'] for a in anchors] + [''])}"
        stats["sites"] += 1
        meta = {"o": octet, "n": s["site_name"] or "", "at": when}
        sites.append(meta)
        if manifest.get(octet) == sig and os.path.exists(os.path.join(data_dir, f"{octet}_index.js")):
            stats["skipped"] += 1
            continue
        ents = aci_graph.build(pulls, anchors, overrides)["ents"]
        shards = max(1, min(256, len(ents) // PER_SHARD))
        buckets = [dict() for _ in range(shards)]
        index = []
        for dn, e in ents.items():
            index.append([dn, e["c"], _site_label(dn, e)])
            a = {k: v for k, v in e["a"].items() if k != "dn" and v != ""}
            buckets[zlib.crc32(dn.encode()) % shards][dn] = {k: v for k, v in (
                ("c", e["c"]), ("a", a), ("p", e["p"]), ("k", e["k"]), ("o", e["o"]), ("i", e["i"]), ("m", e["m"]), ("t", e["t"])) if v or k == "c"}
        for n, b in enumerate(buckets):
            _write_atomic(os.path.join(data_dir, f"{octet}_{n}.js"),
                          f"(window.ACI_D=window.ACI_D||{{}})[{_dump(octet)}]=Object.assign((window.ACI_D||{{}})[{_dump(octet)}]||{{}},{_dump(b)});\n")
        index.sort(key=lambda r: r[0])
        _write_atomic(os.path.join(data_dir, f"{octet}_index.js"),
                      f"(window.ACI_I=window.ACI_I||{{}})[{_dump(octet)}]={_dump({'shards': shards, 'ents': index})};\n")
        manifest[octet] = sig
        stats["written"] += 1
    _write_atomic(os.path.join(data_dir, "manifest.json"), _dump(manifest))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    _write_atomic(os.path.join(data_dir, "sites.js"), f"window.ACI_GENERATED={_dump(stamp)};\nwindow.ACI_SITES={_dump(sites)};\n")
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        page = f.read().replace("__CSS_TOKENS__", CSS_TOKENS).replace("__BANNER_CSS__", banner.CSS).replace("__BANNER__", banner.html())
    _write_atomic(os.path.join(out_dir, "aci.html"), page)
    return stats


if __name__ == "__main__":
    with db.get_conn() as conn:
        s = generate_aci_pages(conn)
    print(f"  Wrote {os.path.join(OUTPUT_DIR, 'aci.html')} - {s['sites']} site(s): {s['written']} rebuilt, {s['skipped']} unchanged.")
