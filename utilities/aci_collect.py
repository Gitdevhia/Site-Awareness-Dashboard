"""aci_collect.py (v1.0) - pull the Cisco ACI config from an APIC and store it in sad.db.

The config is pulled in pieces with all properties (the APIC refuses a full-property subtree
on uni itself): uni, then every child of uni (access policies, each tenant, fabric, domains...)
as its own query, then the operational classes. Pulls go to the write queue (action
aci_save_raw_pull) in size-bounded items; a query identical to its newest stored pull is not
stored again. A "_run" row lists the queries of each run, so older query names are ignored. A small masked "shape report" (counts, attribute names, masked samples) is also
written to aci_probe_output/ so it can be carried out by hand if needed.

Per site (settings.json -> "aci" -> "sites" -> {site_octet: [apic1, apic2, apic3]}):
  APICs are tried in list order. An APIC is skipped on a connect/login failure;
  a failed query does NOT fail over (the next APIC would give the same answer).
Read-only: only GET requests (plus the login POST).

Run alone against one site:  python utilities/aci_collect.py 20 [--user NAME]
Self-test (fake APIC):       python utilities/aci_collect.py --selftest
"""
import collections
import hashlib
import json
import os
import re
import socket
import sys
import time
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import settings_loader  # noqa: E402

VERSION = "2.0"
_VOLATILE = {"modTs", "lcOwn", "childAction", "monPolDn", "uid", "dn_ts"}  # stripped before hashing
_MASK_KEYS = {"sysName", "sysDesc", "mgmtIp", "chassisIdV", "portIdV", "devId", "ip", "addr", "mac",
              "descr", "nameAlias", "annotation", "serial", "oobMgmtAddr", "inbMgmtAddr", "pwd"}
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:.-][0-9A-Fa-f]{2}){5}\b|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b")
_SAMPLES = 3


def _cfg():
    return settings_loader.get_section("aci")


def _url(apic):
    return apic if "://" in apic else "https://" + apic


def _reachable(url, timeout=5):
    u = urlparse(url)
    with socket.create_connection((u.hostname, u.port or (80 if u.scheme == "http" else 443)), timeout=timeout):
        pass


def connect(apics, user, password, cfg, say=print):
    """Return (session, base_url) for the first APIC that is reachable and accepts the login."""
    import requests
    verify = cfg["verify"]
    if verify is False:
        import urllib3
        urllib3.disable_warnings()
        say("WARNING: TLS verification disabled (aci.verify=false)")
    name = f"apic:{cfg['login_domain']}\\{user}" if cfg.get("login_domain") else user
    errors = []
    for apic in apics:
        base = _url(apic).rstrip("/")
        try:
            _reachable(base)
            s = requests.Session()
            s.verify = verify
            r = s.post(base + "/api/aaaLogin.json", timeout=30,
                       json={"aaaUser": {"attributes": {"name": name, "pwd": password}}})
            r.raise_for_status()
            say(f"connected to {apic}")
            return s, base
        except Exception as e:  # connect/login failure -> next APIC
            errors.append(f"{apic}: {type(e).__name__}: {e}")
            say(f"APIC {apic} unavailable ({type(e).__name__}: {e}), trying next")
    raise ConnectionError("no APIC usable - " + "; ".join(errors))


def _get(s, base, path, timeout):
    t0 = time.time()
    r = s.get(base + path, timeout=timeout)
    if r.status_code >= 400:  # the APIC explains itself in the body; raise_for_status() drops that
        raise RuntimeError(f"HTTP {r.status_code} for {path}: {r.text[:300]}")
    return r.json(), time.time() - t0, len(r.content)


def _hash(imdata, ignore=_VOLATILE):
    def clean(o):
        if isinstance(o, dict):
            return {k: clean(v) for k, v in sorted(o.items()) if k not in ignore}
        return [clean(i) for i in o] if isinstance(o, list) else o
    return hashlib.sha256(json.dumps(clean(imdata), sort_keys=True).encode()).hexdigest()


def _flat(objs, parent, out):
    for o in objs:
        for cls, body in o.items():
            attrs = body.get("attributes", {})
            dn = attrs.get("dn") or (parent or "") + "/" + attrs.get("rn", "")
            out[dn] = (cls, attrs)
            _flat(body.get("children", []), dn, out)
    return out


def _diff(a, b, ignore=_VOLATILE, top=12):
    """Which attributes changed between two pulls of the same query (for an unstable hash)."""
    fa, fb = _flat(a, None, {}), _flat(b, None, {})
    n = collections.Counter()
    for dn in fa.keys() & fb.keys():
        for k in set(fa[dn][1]) | set(fb[dn][1]):
            if k not in ignore and fa[dn][1].get(k) != fb[dn][1].get(k):
                n[f"{fa[dn][0]}.{k}"] += 1
    extra = len(fa.keys() ^ fb.keys())
    return ", ".join(f"{k}({v})" for k, v in n.most_common(top)) + (f"; {extra} object(s) only in one pull" if extra else "")


def _walk(objs, stats, depth=0):
    """Count classes, collect attribute names and a few samples per class."""
    for o in objs:
        for cls, body in o.items():
            st = stats.setdefault(cls, {"count": 0, "attributes": set(), "samples": [], "parents": set()})
            st["count"] += 1
            attrs = body.get("attributes", {})
            st["attributes"].update(attrs)
            if len(st["samples"]) < _SAMPLES:
                st["samples"].append(attrs)
            kids = body.get("children", [])
            for k in kids:
                for kc in k:
                    stats.setdefault(kc, {"count": 0, "attributes": set(), "samples": [], "parents": set()})["parents"].add(cls)
            _walk(kids, stats, depth + 1)


def _mask(attrs):
    out = {}
    for k, v in attrs.items():
        v = "***" if k in _MASK_KEYS and v else str(v)
        out[k] = _MAC.sub("MAC", _IP.sub("IP", v))
    return out


def _shape(imdata):
    stats = {}
    _walk(imdata, stats)
    return {c: {"count": s["count"], "parents": sorted(s["parents"]), "attributes": sorted(s["attributes"]),
                "samples": [_mask(a) for a in s["samples"]]} for c, s in sorted(stats.items())}


MAX_ITEM = 20_000_000  # characters of packed payload per write-queue item


def _queue_store(site_id, pulls):
    import write_queue
    import aci_db  # noqa: F401  (registers the ACI queue actions)
    return write_queue.queue_and_wait("aci_save_raw_pull", timeout=600, site_id=site_id, pulls=pulls)


def _chunks(packed):
    cur, size = [], 0
    for p in packed:
        if cur and size + len(p["payload"]) > MAX_ITEM:
            yield cur
            cur, size = [], 0
        cur.append(p)
        size += len(p["payload"])
    if cur:
        yield cur


def _roots(s, base, cfg, timeout, say):
    """DNs of the objects directly under uni: from settings (config_roots) or asked from the APIC."""
    if cfg["config_roots"]:
        return list(cfg["config_roots"])
    data, _, _ = _get(s, base, cfg["config_children_query"], timeout)
    dns = [a["dn"] for o in data.get("imdata", []) for b in o.values() for a in [b.get("attributes", {})] if a.get("dn")]
    say(f"{len(dns)} object(s) under uni")
    return sorted(dns)


def probe_site(octet, apics, user, password, cfg=None, say=print, site_id=None, store=_queue_store):
    """Pull the config and operational classes from one site; store them (if site_id is given)
    and write the shape report. store(site_id, pulls) is replaceable for tests."""
    import aci_db
    cfg = cfg or _cfg()
    timeout = cfg["timeout_seconds"]
    ignore = _VOLATILE | set(cfg["hash_ignore"])
    out_dir = settings_loader.resolve_path(cfg["probe_output_dir"])
    os.makedirs(out_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    s, base = connect(apics, user, password, cfg, say)
    report = {"probe_version": VERSION, "site": octet, "apic": "(masked)", "queries": {}, "created": stamp}
    # (stored name, path, fallback path, report label)
    plan = [("uni", "/api/mo/uni.json", None, "uni")]
    try:
        roots = _roots(s, base, cfg, timeout, say)
    except Exception as e:
        say(f"cannot list the objects under uni: {type(e).__name__}: {e} (set aci.config_roots to list them by hand)")
        roots = []
    for i, dn in enumerate(roots):
        fb = f"/api/mo/{dn}.json?{cfg['config_fallback_options']}" if cfg["config_fallback_options"] else None
        plan.append((dn, f"/api/mo/{dn}.json?{cfg['config_options']}", fb, f"root{i}"))
    plan += [(c, f"/api/class/{c}.json", None, c) for c in cfg["operational_classes"]]
    packed = []
    for name, path, fb, label in plan:
        say(f"pulling {label if label.startswith('root') else name}")
        try:
            try:
                data, secs, size = _get(s, base, path, timeout)
                mode = "full"
            except Exception as e:
                if not fb:
                    raise
                say(f"{label}: {type(e).__name__}: {e} - retrying with {cfg['config_fallback_options']}")
                data, secs, size = _get(s, base, fb, timeout)
                mode = "fallback"
            imdata = data.get("imdata", [])
            packed.append({"query": name, "hash": _hash(imdata, ignore), "payload": aci_db.pack(imdata), "size": size})
            q = {"seconds": round(secs, 1), "bytes": size, "objects_top": len(imdata), "mode": mode, "hash": packed[-1]["hash"]}
            say(f"pulled {label}: {len(imdata)} top object(s), {size / 1e6:.1f} MB, {secs:.1f}s" + (" (config-only fallback)" if mode == "fallback" else ""))
            if label == "root0" and cfg["probe_repeat"]:
                say(f"pulling {label} again (hash stability)")
                again, _, _ = _get(s, base, fb if mode == "fallback" else path, timeout)
                same = _hash(again.get("imdata", []), ignore) == q["hash"]
                q["hash_stable_between_pulls"] = same
                if not same:
                    q["changed_attributes"] = _diff(imdata, again.get("imdata", []), ignore)
                    say(f"HASH NOT STABLE for {label}; changing attributes: {q['changed_attributes']} "
                        "(add names to aci.hash_ignore)")
            q["shape"] = _shape(imdata)
            report["queries"][label] = q
        except Exception as e:  # one failed query must not lose the others
            report["queries"][label] = {"error": f"{type(e).__name__}: {e}"}
            say(f"query {label} failed: {type(e).__name__}: {e}")
            if cfg.get("debug"):
                import traceback
                say(traceback.format_exc())
    if site_id is not None and packed:
        names = [p[0] for p in plan]  # the queries of this run, failed ones included
        packed.append({"query": "_run", "hash": _hash(names), "payload": aci_db.pack(names), "size": len(names)})
        total = collections.Counter()
        for chunk in _chunks(packed):
            total.update(store(site_id, chunk))
        say(f"stored raw pull: {dict(total)}")
    rep_path = os.path.join(out_dir, f"shape_report_{octet}_{stamp}.json")
    with open(rep_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)
    say(f"shape report: {rep_path}")
    return rep_path


def run_site(octet, site_id, user, password, say=print):
    """Orchestrator entry: returns False (skipped) if the site has no APIC configured."""
    cfg = _cfg()
    apics = cfg["sites"].get(str(octet))
    if not apics:
        say("skipped: no APIC configured for this site")
        return False
    probe_site(str(octet), apics, user, password, cfg, say, site_id=site_id)
    return True


def _selftest():
    import tempfile
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    infra = {"imdata": [{"infraInfra": {"attributes": {"dn": "uni/infra", "modTs": "1"}, "children": [
        {"infraAccPortGrp": {"attributes": {"rn": "funcprof/accportgrp-x", "name": "x",
                                             "descr": "host 10.1.2.3 aa:bb:cc:dd:ee:ff"}}}]}}]}
    tenant = {"imdata": [{"fvTenant": {"attributes": {"dn": "uni/tn-a", "name": "a"}}}]}
    children = {"imdata": [{"infraInfra": {"attributes": {"dn": "uni/infra"}}}, {"fvTenant": {"attributes": {"dn": "uni/tn-a"}}}]}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj, code=200):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self._send({"imdata": []})

        def do_GET(self):
            if "query-target=children" in self.path:
                return self._send(children)
            if self.path.startswith("/api/mo/uni/infra"):
                return self._send(infra)
            if self.path.startswith("/api/mo/uni/tn-a"):  # refuses all properties, accepts config-only
                if "prop-include=all" in self.path:
                    return self._send({"imdata": [{"error": {"attributes": {"text": "rsp-subtree not supported"}}}]}, 400)
                return self._send(tenant)
            if self.path.startswith("/api/mo/uni.json"):
                return self._send({"imdata": [{"polUni": {"attributes": {"dn": "uni"}}}]})
            if "lldpAdjEp" in self.path:
                return self._send({"imdata": [{"lldpAdjEp": {"attributes": {"sysName": "host1", "mgmtIp": "10.9.9.9"}}}]})
            self.send_error(500)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    dead_port = dead.getsockname()[1]
    dead.close()
    cfg = dict(settings_loader.DEFAULTS["aci"], verify=True, probe_repeat=True,
               probe_output_dir=tempfile.mkdtemp(), operational_classes=["lldpAdjEp", "fabricNode"])
    msgs = []
    stored = []
    rep = probe_site("t", [f"http://127.0.0.1:{dead_port}", f"http://127.0.0.1:{srv.server_port}"],
                     "u", "p", cfg, msgs.append, site_id=1, store=lambda sid, pulls: stored.extend(pulls) or {"stored": len(pulls)})
    r = json.load(open(rep))
    assert any("trying next" in m for m in msgs), "failover not used"
    q = r["queries"]
    assert q["root0"]["hash_stable_between_pulls"] and q["root0"]["shape"]["infraAccPortGrp"]["count"] == 1
    assert q["root1"]["mode"] == "fallback" and any("retrying" in m for m in msgs), "fallback not used"
    assert "error" in q["fabricNode"] and q["lldpAdjEp"]["shape"]["lldpAdjEp"]["samples"][0]["sysName"] == "***"
    assert "10.1.2.3" not in json.dumps(r) and "aa:bb" not in json.dumps(r)
    import aci_db
    assert [p["query"] for p in stored][-1] == "_run"
    assert aci_db.unpack([p for p in stored if p["query"] == "_run"][0]["payload"]) == \
        ["uni", "uni/infra", "uni/tn-a", "lldpAdjEp", "fabricNode"]
    a1 = [{"fvTenant": {"attributes": {"dn": "uni/tn-a", "pkts": "1", "modTs": "1"}}}]
    a2 = [{"fvTenant": {"attributes": {"dn": "uni/tn-a", "pkts": "2", "modTs": "2"}}}]
    assert _hash(a1) != _hash(a2) and _hash(a1, _VOLATILE | {"pkts"}) == _hash(a2, _VOLATILE | {"pkts"})
    assert _diff(a1, a2) == "fvTenant.pkts(1)"
    try:
        connect([f"http://127.0.0.1:{dead_port}"], "u", "p", cfg, msgs.append)
        raise AssertionError("expected ConnectionError")
    except ConnectionError:
        pass
    print("selftest OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        import getpass
        user = sys.argv[sys.argv.index("--user") + 1] if "--user" in sys.argv else input("APIC user: ")
        import db
        with db.get_conn() as c:
            site = db.find_site_by_any_key(c, sys.argv[1])
        if not site or not run_site(site["site_octet"], site["id"], user, getpass.getpass("APIC password: ")):
            sys.exit(1)
