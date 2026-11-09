"""settings_loader.py - reads settings.json (project root) for the parts of SAD
that need more than the classification banner.

get_section("gemone") returns that section of settings.json merged over the
built-in defaults below, so a missing file or a missing key still gives a
complete, usable dict. The file is re-read whenever it changes on disk.
A file that exists but cannot be parsed raises SettingsError instead of
silently falling back to defaults, because a wrong threshold is worse than
a clear error."""
import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.path.join(PROJECT_ROOT, "settings.json")

DEFAULTS = {
    "gemone": {
        "script": "gemone/gemone_full_pull.py",
        "output_file": "gemone/output.json",
        "site_map_file": "gemone/kg_site_map.csv",
        "credential_name": "gemone",
        "run_timeout_seconds": 1800,
        "keymat_warn_days": 30,
        "keymat_critical_days": 0,
        "battery_warn_years": 2.0,
        "battery_critical_years": None,
        "state_health": {"Secure Comm": "ok", "Network Active": "warning"},
        "interface_down_health": "critical",
        "unreachable_pairs_warn": False,
        "data_stale_after_days": 2,
        # Extra choices for the Add KG type list (it already offers every type
        # found in the data, plus ViaSat).
        "manual_kg_types": [],
    },
    "aci": {
        # {site_octet: [apic1, apic2, apic3]} - tried in order. Example: {"20": ["apic1.example", "apic2.example"]}
        "sites": {},
        "login_domain": "",
        "verify": False,  # False | True | "path/to/ca.pem". False prints one warning per run.
        "timeout_seconds": 600,
        # The config is pulled per object under uni (the APIC refuses rsp-subtree on uni itself with all
        # properties). config_roots: DNs to pull; empty = ask the APIC for the children of uni.
        "config_roots": [],
        "config_children_query": "/api/mo/uni.json?query-target=children",
        "config_options": "rsp-subtree=full&rsp-prop-include=all",
        # Used for a root the APIC refuses with config_options ("" = no fallback, the root fails).
        "config_fallback_options": "rsp-subtree=full&rsp-prop-include=config-only",
        "hash_ignore": [],  # attribute names to leave out of the change hash (runtime counters etc.)
        "operational_classes": ["fabricNode", "fabricExplicitGEp", "fabricPathEp", "lldpAdjEp", "cdpAdjEp"],
        "probe_output_dir": "aci_probe_output",
        "probe_repeat": True,  # pull uni twice to check the hash is stable
        "debug": False,  # True: print a full traceback when a query fails
    },
    "command_runner": {
        "max_workers": 24,
        "per_site_limit": 5,
    },
}

_cache = {"stamp": "unset", "data": {}}


class SettingsError(Exception):
    pass


def _load():
    try:
        st = os.stat(SETTINGS_PATH)
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None
    if stamp == _cache["stamp"]:
        return _cache["data"]
    data = {}
    if stamp is not None:
        try:
            with open(SETTINGS_PATH, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("the file must hold a JSON object")
        except (OSError, ValueError) as e:
            raise SettingsError(f"Could not read {SETTINGS_PATH}: {e}") from None
    _cache["stamp"], _cache["data"] = stamp, data
    return data


def get_section(name: str) -> dict:
    """The named section merged over its defaults (a new dict each call)."""
    merged = dict(DEFAULTS.get(name, {}))
    section = _load().get(name)
    if isinstance(section, dict):
        for k, v in section.items():
            merged[k] = v
    return merged


def resolve_path(relative: str) -> str:
    """A path from settings.json, taken relative to the project root unless absolute."""
    return relative if os.path.isabs(relative) else os.path.join(PROJECT_ROOT, relative)