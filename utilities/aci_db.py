"""aci_db.py (v1.0) - ACI tables in sad.db and the write-queue actions that fill them.

Importing this module registers its actions in write_queue.ACTIONS (db.py and
write_queue.py need no changes). Every function takes `conn` first, like db.py's
write functions, and is only ever called by the queue drain (writes) or by readers.
Any process that should drain ACI items must import this module.

aci_raw        one row per (site, query) pull; an identical pull is not stored again
aci_anchors    cluster anchors: which DN is the data / ipmi AAEP of which cluster
aci_overrides  manual edits that survive re-pulls (kind: attr | entity | edge)
"""
import base64
import json
import time
import zlib

import db
import write_queue

SCHEMA = """
CREATE TABLE IF NOT EXISTS aci_raw (
    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER NOT NULL, query TEXT NOT NULL,
    fetched_at TEXT NOT NULL, content_hash TEXT NOT NULL, payload_z BLOB NOT NULL, size_bytes INTEGER);
CREATE INDEX IF NOT EXISTS ix_aci_raw ON aci_raw (site_id, query, id);
CREATE TABLE IF NOT EXISTS aci_anchors (
    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER NOT NULL, cluster TEXT NOT NULL, role TEXT NOT NULL,
    dn TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'manual', created_by TEXT, created_at TEXT,
    UNIQUE (site_id, cluster, role, dn));
CREATE TABLE IF NOT EXISTS aci_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER NOT NULL, dn TEXT NOT NULL, kind TEXT NOT NULL,
    key TEXT NOT NULL DEFAULT '', value_json TEXT, action TEXT NOT NULL DEFAULT 'set', created_by TEXT, created_at TEXT,
    UNIQUE (site_id, dn, kind, key));
"""


def ensure(conn):
    conn.executescript(SCHEMA)


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def pack(obj) -> str:
    """JSON-compress-base64: how a pull travels through the (JSON text) write queue."""
    return base64.b64encode(zlib.compress(json.dumps(obj, separators=(",", ":")).encode())).decode()


def unpack(text: str):
    return json.loads(zlib.decompress(base64.b64decode(text)))


def save_raw_pull(conn, site_id: int, pulls: list, fetched_at: str = None) -> dict:
    """pulls: [{"query", "hash", "payload"(packed), "size"}]. Returns {"stored": n, "unchanged": n}."""
    ensure(conn)
    out = {"stored": 0, "unchanged": 0}
    for p in pulls:
        last = conn.execute("SELECT content_hash FROM aci_raw WHERE site_id=? AND query=? ORDER BY id DESC LIMIT 1",
                            (site_id, p["query"])).fetchone()
        if last and last[0] == p["hash"]:
            out["unchanged"] += 1
            continue
        conn.execute("INSERT INTO aci_raw (site_id, query, fetched_at, content_hash, payload_z, size_bytes) VALUES (?,?,?,?,?,?)",
                     (site_id, p["query"], fetched_at or _now(), p["hash"], base64.b64decode(p["payload"]), p["size"]))
        out["stored"] += 1
    db.log_activity("aci_pull", f"site_id={site_id} stored={out['stored']} unchanged={out['unchanged']}", conn=conn)
    return out


def set_anchor(conn, site_id: int, cluster: str, role: str, dn: str, source: str = "manual", user: str = None):
    ensure(conn)
    conn.execute("INSERT OR REPLACE INTO aci_anchors (site_id, cluster, role, dn, source, created_by, created_at) VALUES (?,?,?,?,?,?,?)",
                 (site_id, cluster, role, dn, source, user, _now()))
    db.log_activity("aci_anchor_set", f"site_id={site_id} {cluster}/{role} {dn}", conn=conn)


def delete_anchor(conn, site_id: int, cluster: str, role: str, dn: str):
    ensure(conn)
    conn.execute("DELETE FROM aci_anchors WHERE site_id=? AND cluster=? AND role=? AND dn=?", (site_id, cluster, role, dn))
    db.log_activity("aci_anchor_delete", f"site_id={site_id} {cluster}/{role} {dn}", conn=conn)


def set_override(conn, site_id: int, dn: str, kind: str, key: str = "", value=None, action: str = "set", user: str = None):
    """attr: key=attribute name, value=new value | entity: action 'hide' or 'add' (value=attrs) |
    edge: key='<type>><target dn>', action 'add' or 'hide'."""
    ensure(conn)
    conn.execute("INSERT OR REPLACE INTO aci_overrides (site_id, dn, kind, key, value_json, action, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
                 (site_id, dn, kind, key, json.dumps(value), action, user, _now()))
    db.log_activity("aci_override_set", f"site_id={site_id} {kind} {dn} {key}", conn=conn)


def delete_override(conn, site_id: int, dn: str, kind: str, key: str = ""):
    ensure(conn)
    conn.execute("DELETE FROM aci_overrides WHERE site_id=? AND dn=? AND kind=? AND key=?", (site_id, dn, kind, key))
    db.log_activity("aci_override_delete", f"site_id={site_id} {kind} {dn} {key}", conn=conn)


def purge_raw(conn, before: str):
    """Delete pulls fetched before 'YYYY-MM-DD', always keeping each (site, query)'s newest and first pull."""
    ensure(conn)
    n = conn.execute("""DELETE FROM aci_raw WHERE fetched_at < ? AND id NOT IN
        (SELECT MAX(id) FROM aci_raw GROUP BY site_id, query UNION SELECT MIN(id) FROM aci_raw GROUP BY site_id, query)""",
                     (before,)).rowcount
    db.log_activity("aci_purge", f"before={before} deleted={n}", conn=conn)
    return n


# ---- readers (not queued) -------------------------------------------------

def latest_pulls(conn, site_id: int):
    """({query: imdata list}, {query: fetched_at}, signature) from the newest stored pull of each query."""
    ensure(conn)
    pulls, when, sig = {}, {}, []
    for r in conn.execute("""SELECT query, fetched_at, content_hash, payload_z FROM aci_raw WHERE id IN
                             (SELECT MAX(id) FROM aci_raw WHERE site_id=? GROUP BY query)""", (site_id,)):
        pulls[r[0]] = json.loads(zlib.decompress(r[3]))
        when[r[0]] = r[1]
        sig.append(r[2][:12])
    return pulls, when, "".join(sorted(sig))


def overlay(conn, site_id: int):
    """(anchors, overrides) as plain dict lists."""
    ensure(conn)
    a = [dict(zip(("cluster", "role", "dn", "source"), tuple(r))) for r in
         conn.execute("SELECT cluster, role, dn, source FROM aci_anchors WHERE site_id=?", (site_id,))]
    o = [dict(zip(("dn", "kind", "key", "value", "action", "by", "at"), r[:3] + (json.loads(r[3] or "null"),) + r[4:]))
         for r in (tuple(x) for x in
         conn.execute("SELECT dn, kind, key, value_json, action, created_by, created_at FROM aci_overrides WHERE site_id=?", (site_id,)))]
    return a, o


write_queue.ACTIONS.update({
    "aci_save_raw_pull": save_raw_pull, "aci_set_anchor": set_anchor, "aci_delete_anchor": delete_anchor,
    "aci_set_override": set_override, "aci_delete_override": delete_override, "aci_purge_raw": purge_raw,
})
