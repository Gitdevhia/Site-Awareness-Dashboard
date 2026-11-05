"""
gemone_import.py - checks and imports the file gemone_full_pull.py writes
(KG / TACLANE devices from GEM One) into sad.db.

Run from the project root, like the other SAD scripts.

    python gemone_import.py                      check the file and show what an import would do (changes nothing)
    python gemone_import.py --apply              import it
    python gemone_import.py --check              only validate the file, no database access
    python gemone_import.py --file other.json    use a different file (default: settings.json gemone.output_file)
    python gemone_import.py --force --apply      import a file older than the last import, or one with no devices
    python gemone_import.py --map                load the serial-to-site CSV (default: settings.json gemone.site_map_file)
    python gemone_import.py --map --apply        ... and save it
    python gemone_import.py --list               show every KG in the database with its health

The site map CSV has two columns with a header row: serial,site
(site is the site octet, for example 10). A KG with no mapping lands in the
Unassigned site until it is mapped.
"""
import argparse
import csv
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "utilities"))

import db  # noqa: E402
import kg_health  # noqa: E402
import settings_loader  # noqa: E402
import write_queue  # noqa: E402

SUPPORTED_SCHEMA = 1
DATE_FIELDS = ("currFfvsExpDate", "neBatteryChangeDate")


def load_file(path: str) -> dict:
    """The parsed JSON file. Raises ValueError with a plain-language reason."""
    if not os.path.exists(path):
        raise ValueError(f"File not found: {path}")
    try:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise ValueError(f"Could not read {path} as JSON: {e}") from None
    if not isinstance(data, dict):
        raise ValueError("The file must contain a JSON object at the top level")
    return data


def validate(data: dict):
    """Returns (problems, warnings). Problems mean the file should not be
    imported; warnings are things worth knowing that do not stop it."""
    problems, warnings = [], []
    if data.get("schema_version") != SUPPORTED_SCHEMA:
        problems.append(f"schema_version is {data.get('schema_version')!r}, expected {SUPPORTED_SCHEMA}")
    ts = data.get("collected_at")
    if not isinstance(ts, str):
        problems.append("collected_at is missing")
    else:
        try:
            datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            problems.append(f"collected_at {ts!r} is not an ISO 8601 timestamp")
    devices = data.get("devices")
    if not isinstance(devices, list):
        problems.append("devices is missing or is not a list")
        return problems, warnings
    count = data.get("device_count")
    if count is not None and count != len(devices):
        problems.append(f"device_count says {count} but the file holds {len(devices)} devices (truncated file?)")
    errors = data.get("errors")
    if errors is not None and not isinstance(errors, list):
        problems.append("errors is not a list")
        errors = []
    if not devices and not errors:
        problems.append("the file lists no devices")

    seen = set()
    for i, d in enumerate(devices, 1):
        if not isinstance(d, dict):
            problems.append(f"device #{i} is not an object")
            continue
        serial = d.get("serialNumber")
        if not isinstance(serial, str) or not serial.strip():
            problems.append(f"device #{i} has no serialNumber")
            continue
        serial = serial.strip()
        if serial in seen:
            warnings.append(f"{serial}: appears more than once")
        seen.add(serial)
        for field in DATE_FIELDS:
            value = d.get(field)
            if value is None:
                continue
            try:
                datetime.datetime.strptime(str(value).strip()[:10], "%Y-%m-%d")
            except ValueError:
                warnings.append(f"{serial}: {field} {str(value)[:30]!r} is not a YYYY-MM-DD date")
        sas = d.get("securityAssociations")
        if sas is not None and not isinstance(sas, list):
            warnings.append(f"{serial}: securityAssociations is not a list")
        else:
            for j, a in enumerate(sas or [], 1):
                if not isinstance(a, dict):
                    warnings.append(f"{serial}: security association #{j} is not an object")
                    continue
                pr = a.get("pairReachable")
                if pr is not None and not isinstance(pr, bool):
                    warnings.append(f"{serial}: security association #{j} pairReachable {pr!r} is not true/false")
    for e in errors or []:
        if not isinstance(e, dict) or not e.get("serialNumber"):
            warnings.append("an entry in errors has no serialNumber")
    return problems, warnings


def _print_list(items, limit=10, indent="    "):
    for item in items[:limit]:
        print(f"{indent}{item}")
    if len(items) > limit:
        print(f"{indent}... and {len(items) - limit} more")


def run_import(path: str, apply: bool, force: bool, check_only: bool) -> int:
    print(f"File: {path}")
    try:
        data = load_file(path)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 1
    problems, warnings = validate(data)
    print(f"Collected at: {data.get('collected_at')}   devices: {len(data.get('devices') or [])}   "
          f"errors listed: {len(data.get('errors') or [])}")
    if warnings:
        print(f"{len(warnings)} warning(s):")
        _print_list(warnings, 15)
    if problems:
        print(f"{len(problems)} problem(s), the file will not be imported:")
        _print_list(problems, 15)
        return 1
    if check_only:
        print("File is valid.")
        return 0

    db.init_db()
    if apply:
        try:
            summary = write_queue.queue_and_wait(
                "import_kg_snapshot", timeout=120, data=data, source=os.path.basename(path), force=force)
        except (RuntimeError, TimeoutError) as e:
            print(f"ERROR: import failed: {e}")
            return 1
    else:
        try:
            with db.get_conn() as conn:
                summary = db.import_kg_snapshot(conn, data, source=os.path.basename(path), force=force)
                conn.rollback()
        except ValueError as e:
            print(f"ERROR: {e}")
            return 1

    print(f"{'Imported' if apply else 'Would import'}: {summary['added']} added, {summary['updated']} updated, "
          f"{summary['reactivated']} brought back, {summary['skipped']} skipped, {summary['errors']} with errors, "
          f"{summary['missing']} missing from the file, {summary['associations']} security associations.")
    if summary.get("took_over"):
        print(f"{len(summary['took_over'])} hand-entered KG(s) are now fed by GEM One (their serial is in the file):")
        _print_list(summary["took_over"], 20)
    if summary.get("possible_matches"):
        print("Possible duplicates: a new GEM One unit shares an IP with a hand-entered one. If they are the same unit, "
              "open the hand-entered one with Edit on the KG devices tab and enter the real serial:")
        _print_list([f"{new} has the same IP as {manual}" for new, manual in summary["possible_matches"]], 20)
    if summary["unmapped"]:
        print(f"{len(summary['unmapped'])} KG(s) have no site assigned and are in Unassigned:")
        _print_list(summary["unmapped"], 20)
    if summary["warnings"]:
        print("Import warnings:")
        _print_list(summary["warnings"], 15)
    if not apply:
        print("Dry run only, nothing was changed. Add --apply to import.")
    return 0


def run_map(path: str, apply: bool) -> int:
    print(f"Site map: {path}")
    if not os.path.exists(path):
        print(f"ERROR: file not found: {path}")
        return 1
    rows = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                row = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
                rows.append({"serial": row.get("serial", ""), "site": row.get("site", "")})
    except (OSError, csv.Error) as e:
        print(f"ERROR: could not read the CSV: {e}")
        return 1
    if not rows:
        print("ERROR: no rows found. The file needs a header line: serial,site")
        return 1
    db.init_db()
    if apply:
        try:
            summary = write_queue.queue_and_wait("import_kg_site_map", timeout=60, rows=rows)
        except (RuntimeError, TimeoutError) as e:
            print(f"ERROR: {e}")
            return 1
    else:
        with db.get_conn() as conn:
            summary = db.import_kg_site_map(conn, rows)
            conn.rollback()
    print(f"{'Saved' if apply else 'Would save'} {summary['applied']} assignment(s), {summary['skipped']} row(s) skipped.")
    if summary["unknown_site"]:
        print(f"{len(summary['unknown_site'])} row(s) name a site SAD does not know and were not applied:")
        _print_list([f"{s} -> {o}" for s, o in summary["unknown_site"]], 20)
    if not apply:
        print("Dry run only, nothing was changed. Add --apply to save.")
    return 0


def run_list() -> int:
    cfg = settings_loader.get_section("gemone")
    db.init_db()
    with db.get_conn() as conn:
        rows = db.get_kg_devices(conn)
        last = db.get_kg_last_import(conn)
    if last is not None:
        print(f"Last import: {last['imported_at']} (file collected {last['file_collected_at']})")
    if not rows:
        print("No KG devices in the database yet.")
        return 0
    print(f"{'Health':9} {'Name':24} {'Serial':18} {'Site':14} {'State':16} {'KEYMAT':>7} {'Battery':>8} {'SAs':>5}")
    for k in rows:
        ev = kg_health.evaluate(dict(k), cfg, unreachable=k["assoc_unreachable"])
        flags = (" MISSING" if k["missing_since"] else "") + (" ERROR" if k["last_error"] else "") + (" MANUAL" if k["source"] == "manual" else "")
        days = "-" if ev["keymat_days"] is None else f"{ev['keymat_days']}d"
        years = "-" if ev["battery_years"] is None else f"{ev['battery_years']}y"
        site = k["site_octet"] or "?"
        print(f"{ev['health']:9} {(k['system_name'] or '-')[:24]:24} {k['serial_number'][:18]:18} {site[:14]:14} "
              f"{(k['state'] or '-')[:16]:16} {days:>7} {years:>8} {k['assoc_total']:>5}{flags}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Check and import GEM One KG data into SAD.")
    ap.add_argument("--file", help="JSON file to import (default: settings.json gemone.output_file)")
    ap.add_argument("--apply", action="store_true", help="really write to the database (default is a dry run)")
    ap.add_argument("--check", action="store_true", help="only validate the file")
    ap.add_argument("--force", action="store_true", help="allow an older file or one with no devices")
    ap.add_argument("--map", nargs="?", const="", metavar="CSV", help="load the serial-to-site CSV instead")
    ap.add_argument("--list", action="store_true", help="list the KG devices already in the database")
    args = ap.parse_args()

    try:
        cfg = settings_loader.get_section("gemone")
    except settings_loader.SettingsError as e:
        print(f"ERROR: {e}")
        return 1
    if args.list:
        return run_list()
    if args.map is not None:
        return run_map(args.map or settings_loader.resolve_path(cfg["site_map_file"]), args.apply)
    return run_import(args.file or settings_loader.resolve_path(cfg["output_file"]), args.apply, args.force, args.check)


if __name__ == "__main__":
    sys.exit(main())