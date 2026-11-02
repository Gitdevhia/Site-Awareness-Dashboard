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