"""aci_graph.py (v1.0) - build a generic entity/edge graph from a raw APIC pull.

No class-specific code. Entities are keyed by full DN; containment comes from the
tree (or the DN), edges from every relation object (a '...Rs...' object with a tDn).
Relation objects stay entities (they carry attributes such as encap/mode) and also yield an edge parent -> tDn.
Overrides and anchors are applied on top (build(..., anchors, overrides)).
"""
import re

_REL = re.compile(r"^[a-z0-9]+R([st])[A-Z]")  # fvRsPathAtt, infraRsAttEntP, ... (Rs = to target, Rt = reverse)


def split_dn(dn: str) -> list:
    """Split a DN on '/' but not inside [...] (e.g. 'pathep-[eth1/5]')."""
    parts, depth, cur = [], 0, []
    for ch in dn:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        if ch == "/" and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def parent_dn(dn: str):
    p = split_dn(dn)
    return "/".join(p[:-1]) if len(p) > 1 else None


def label(dn: str, attrs: dict) -> str:
    return attrs.get("name") or attrs.get("id") or split_dn(dn)[-1]


def build(pulls: dict, anchors=(), overrides=()) -> dict:
    """pulls: {query: imdata}. Returns {"ents": {dn: {c, a, p, k[], o[], i[], m[], t[]}}}."""
    ents = {}

    def ent(dn, cls="", attrs=None, parent=None):
        e = ents.get(dn)
        if e is None:
            e = ents[dn] = {"c": cls, "a": attrs or {}, "p": parent, "k": [], "o": [], "i": [], "m": [], "t": []}
        elif cls and not e["c"]:
            e["c"], e["a"] = cls, attrs or {}
        return e

    def walk(objs, parent):
        for o in objs:
            for cls, body in o.items():
                attrs = body.get("attributes", {})
                dn = attrs.get("dn") or (parent + "/" + attrs["rn"] if parent and attrs.get("rn") else None)
                if dn is None:
                    continue
                parent_of = parent or parent_dn(dn)
                e = ent(dn, cls, attrs, parent_of)
                if parent_of:
                    ent(parent_of)["k"].append(dn)
                rel = _REL.match(cls)
                if rel and rel.group(1) == "s" and attrs.get("tDn") and parent_of:
                    ent(parent_of)["o"].append([cls, attrs["tDn"], dn])  # [type, target, relation object dn]
                walk(body.get("children", []), dn)

    for imdata in pulls.values():
        walk(imdata, None)
    for dn, e in list(ents.items()):  # edges: targets exist as (stub) entities; fill reverse side
        for typ, tgt, rel in e["o"]:
            ent(tgt)["i"].append([typ, dn, rel])
    for dn, e in ents.items():  # stubs created from references get a parent chain only through their DN
        if e["p"] is None and not e["c"]:
            e["p"] = parent_dn(dn)
    _apply(ents, anchors, overrides)
    return {"ents": ents}


def _apply(ents, anchors, overrides):
    for a in anchors:
        e = ents.get(a["dn"])
        if e is not None:
            e["t"].append([a["cluster"], a["role"], a.get("source", "manual")])
    for o in overrides:
        dn, kind, act, key, val = o["dn"], o["kind"], o["action"], o["key"], o["value"]
        e = ents.get(dn)
        if kind == "entity" and act == "add" and e is None:
            e = ents[dn] = {"c": (val or {}).get("_class", "manual"), "a": dict(val or {}), "p": parent_dn(dn),
                            "k": [], "o": [], "i": [], "m": ["*"], "t": []}
            if e["p"] in ents:
                ents[e["p"]]["k"].append(dn)
        elif e is None:
            continue
        elif kind == "entity" and act == "hide":
            e["m"].append("hidden")
        elif kind == "attr":
            e["a"][key] = val
            e["m"].append(key)
        elif kind == "edge":
            typ, _, tgt = key.partition(">")
            if act == "add":
                e["o"].append([typ, tgt, ""])
                ents.setdefault(tgt, {"c": "", "a": {}, "p": parent_dn(tgt), "k": [], "o": [], "i": [], "m": [], "t": []})["i"].append([typ, dn, ""])
                e["m"].append("edge:" + key)
            else:
                e["o"] = [x for x in e["o"] if not (x[0] == typ and x[1] == tgt)]
                if tgt in ents:
                    ents[tgt]["i"] = [x for x in ents[tgt]["i"] if not (x[0] == typ and x[1] == dn)]
                e["m"].append("edge-hidden:" + key)
