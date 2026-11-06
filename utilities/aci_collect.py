"""aci_collect.py (v0.1, phase 0 probe) - pull the Cisco ACI config from an APIC.

Phase 0 only saves what it pulled to files and writes a small, masked "shape
report" that can be carried out by hand. Nothing is written to sad.db yet.

Per site (settings.json -> "aci" -> "sites" -> {site_octet: [apic1, apic2, apic3]}):
  APICs are tried in list order. An APIC is skipped on a connect/login failure;
  a failed query does NOT fail over (the next APIC would give the same answer).
Read-only: only GET requests (plus the login POST).

Run alone against one site:  python utilities/aci_collect.py 20 [--user NAME]
Self-test (fake APIC):       python utilities/aci_collect.py --selftest
"""
import gzip
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

VERSION = "0.1"
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
            say(f"APIC {apic} unavailable ({type(e).__name__}), trying next")
    raise ConnectionError("no APIC usable - " + "; ".join(errors))


def _get(s, base, path, timeout):
    t0 = time.time()
    r = s.get(base + path, timeout=timeout)
    r.raise_for_status()
    return r.json(), time.time() - t0, len(r.content)


def _hash(imdata):
    def clean(o):
        if isinstance(o, dict):
            return {k: clean(v) for k, v in sorted(o.items()) if k not in _VOLATILE}
        return [clean(i) for i in o] if isinstance(o, list) else o
    return hashlib.sha256(json.dumps(clean(imdata), sort_keys=True).encode()).hexdigest()


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


def probe_site(octet, apics, user, password, cfg=None, say=print):
    """Pull the whole config + operational classes from one site; save raw + shape report."""
    cfg = cfg or _cfg()
    timeout = cfg["timeout_seconds"]
    out_dir = settings_loader.resolve_path(cfg["probe_output_dir"])
    os.makedirs(out_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    s, base = connect(apics, user, password, cfg, say)
    report = {"probe_version": VERSION, "site": octet, "apic": "(masked)",
              "queries": {}, "created": stamp}
    raw = {}
    queries = {"uni": cfg["config_query"]}
    queries.update({c: f"/api/class/{c}.json" for c in cfg["operational_classes"]})
    for name, path in queries.items():
        say(f"pulling {name}")
        try:
            data, secs, size = _get(s, base, path, timeout)
            imdata = data.get("imdata", [])
            raw[name] = imdata
            q = {"seconds": round(secs, 1), "bytes": size, "objects_top": len(imdata), "hash": _hash(imdata)}
            if name == "uni":
                q["top_level_children"] = sorted({c for o in imdata for b in o.values()
                                                  for k in b.get("children", []) for c in k})
                if cfg["probe_repeat"]:
                    say("pulling uni again (hash stability)")
                    again, _, _ = _get(s, base, path, timeout)
                    q["hash_stable_between_pulls"] = _hash(again.get("imdata", [])) == q["hash"]
            q["shape"] = _shape(imdata)
            report["queries"][name] = q
        except Exception as e:  # one failed query must not lose the others
            report["queries"][name] = {"error": f"{type(e).__name__}: {e}"}
            say(f"query {name} failed: {type(e).__name__}")
    raw_path = os.path.join(out_dir, f"raw_{octet}_{stamp}.json.gz")
    with gzip.open(raw_path, "wt", encoding="utf-8") as f:
        json.dump(raw, f)
    rep_path = os.path.join(out_dir, f"shape_report_{octet}_{stamp}.json")
    with open(rep_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)
    say(f"saved {os.path.basename(raw_path)} and {os.path.basename(rep_path)} in {out_dir}")
    return rep_path


def run_site(octet, user, password, say=print):
    """Orchestrator entry: returns False (skipped) if the site has no APIC configured."""
    cfg = _cfg()
    apics = cfg["sites"].get(str(octet))
    if not apics:
        say("skipped: no APIC configured for this site")
        return False
    probe_site(str(octet), apics, user, password, cfg, say)
    return True


def _selftest():
    import tempfile
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    uni = {"imdata": [{"polUni": {"attributes": {"dn": "uni"}, "children": [
        {"infraInfra": {"attributes": {"dn": "uni/infra", "modTs": "1"}, "children": [
            {"infraAccPortGrp": {"attributes": {"dn": "uni/infra/funcprof/accportgrp-x", "name": "x",
                                                 "descr": "host 10.1.2.3 aa:bb:cc:dd:ee:ff"}}}]}},
        {"fvTenant": {"attributes": {"dn": "uni/tn-a", "name": "a"}}}]}}]}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj):
            b = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self._send({"imdata": []})

        def do_GET(self):
            if self.path.startswith("/api/mo/uni"):
                return self._send(uni)
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
    rep = probe_site("t", [f"http://127.0.0.1:{dead_port}", f"http://127.0.0.1:{srv.server_port}"],
                     "u", "p", cfg, msgs.append)
    r = json.load(open(rep))
    assert any("trying next" in m for m in msgs), "failover not used"
    q = r["queries"]
    assert q["uni"]["hash_stable_between_pulls"] and q["uni"]["shape"]["infraAccPortGrp"]["count"] == 1
    assert "error" in q["fabricNode"] and q["lldpAdjEp"]["shape"]["lldpAdjEp"]["samples"][0]["sysName"] == "***"
    assert "10.1.2.3" not in json.dumps(r) and "aa:bb" not in json.dumps(r)
    assert q["uni"]["top_level_children"] == ["fvTenant", "infraInfra"]
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
        if not run_site(sys.argv[1], user, getpass.getpass("APIC password: ")):
            sys.exit(1)
