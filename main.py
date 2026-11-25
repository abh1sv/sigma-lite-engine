import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from typing import Any, Dict, Optional
import yaml

from src.parser import stream_events
from src.engine import load_rules, evaluate_event
from src.enricher import AlertEnricher
from src.reporter import generate_markdown_report, generate_json_report


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Loads default settings from config.yaml if present."""
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def compute_sha256(file_path: str) -> str:
    """Computes the SHA-256 hash of an evidence file in 64KB chunks (low RAM)."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def export_live_windows_log(channel: str, lookback_hours: int = 24) -> str:
    """Exports the most recent N hours of a live Windows Event Log channel to a temp .evtx file."""
    temp_fd, temp_path = tempfile.mkstemp(suffix=".evtx", prefix=f"live_{channel}_")
    os.close(temp_fd)
    os.remove(temp_path)

    lookback_ms = lookback_hours * 3600 * 1000
    cmd = [
        "wevtutil", "epl", channel, temp_path,
        f"/q:*[System[TimeCreated[timediff(@SystemTime) <= {lookback_ms}]]]"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to export live '{channel}' log (run terminal as Administrator for Security logs): "
            f"{result.stderr.strip()}"
        )
    return temp_path


def interactive_menu(default_output_dir: str) -> Dict[str, Any]:
    """Guided interactive menu when main.py is run without CLI flags."""
    print("\n====================================================")
    print("   Sigma-Lite: Detection-as-Code & Triage Workbench ")
    print("====================================================")
    print("  [1] Scan a log file (.evtx or .xml)")
    print("  [2] Scan live Windows System log")
    print("  [3] Scan live Windows Security log (Admin required)")
    print("  [4] Scan live Windows Application log")
    print("  [5] Run full 5-rule attack simulation demo")
    print("  [0] Exit")

    choice = input("\nSelect an option [0-5]: ").strip()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if choice == "0":
        print("Exiting.")
        sys.exit(0)
    elif choice == "1":
        path = input("Enter or drag-and-drop path to .evtx / .xml file: ").strip().strip('"').strip("'")
        base = os.path.splitext(os.path.basename(path))[0]
        return {
            "file": path,
            "live": None,
            "output": os.path.join(default_output_dir, f"{base}_report_{ts}.md"),
            "json": None,
        }
    elif choice == "2":
        return {
            "file": None,
            "live": "System",
            "output": os.path.join(default_output_dir, f"live_System_{ts}.md"),
            "json": None,
        }
    elif choice == "3":
        return {
            "file": None,
            "live": "Security",
            "output": os.path.join(default_output_dir, f"live_Security_{ts}.md"),
            "json": None,
        }
    elif choice == "4":
        return {
            "file": None,
            "live": "Application",
            "output": os.path.join(default_output_dir, f"live_Application_{ts}.md"),
            "json": None,
        }
    elif choice == "5":
        return {
            "file": "samples/attack_simulation.xml",
            "live": None,
            "output": os.path.join(default_output_dir, "sample_incident_report.md"),
            "json": None,
        }
    else:
        print("[!] Invalid selection. Please enter a number between 0 and 5.")
        sys.exit(1)


def main() -> None:
    cfg = load_config()
    rules_dir = cfg.get("rules_dir", "rules")
    default_out_dir = cfg.get("default_output_dir", "reports")
    cache_db = cfg.get("cache_db", "ioc_cache.db")
    cfg_api_key = cfg.get("abuseipdb_api_key") or None
    lookback_hours = int(cfg.get("live_lookback_hours", 24))

    parser = argparse.ArgumentParser(
        description="Sigma-Lite: Lightweight Detection-as-Code & SOC Alert Enrichment Engine"
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-f", "--file", help="Path to Windows Event Log (.evtx) or exported Event XML (.xml)")
    group.add_argument("--live", choices=["Security", "System", "Application"], help="Scan live Windows Event Log channel")
    parser.add_argument("-r", "--rules", default=rules_dir, help="Directory containing Sigma YAML rules")
    parser.add_argument("-o", "--output", default=None, help="Output Markdown incident report path")
    parser.add_argument("--json", default=None, help="Optional path to export alerts as JSON")
    parser.add_argument("--api-key", default=cfg_api_key, help="Optional AbuseIPDB API key")

    args = parser.parse_args()

    # Launch interactive mode if neither -f nor --live was supplied
    if not args.file and not args.live:
        selections = interactive_menu(default_out_dir)
        target_file_arg = selections["file"]
        live_channel = selections["live"]
        output_path = args.output or selections["output"]
        json_out = args.json or selections["json"]
    else:
        target_file_arg = args.file
        live_channel = args.live
        output_path = args.output or os.path.join(default_out_dir, "incident_report.md")
        json_out = args.json

    start_time = time.perf_counter()
    temp_live_file: Optional[str] = None

    try:
        if live_channel:
            print(f"\n[*] Exporting last {lookback_hours}h of live Windows '{live_channel}' log...")
            temp_live_file = export_live_windows_log(live_channel, lookback_hours)
            target_file = temp_live_file
            source_label = f"Live Windows Channel: {live_channel} (Last {lookback_hours}h)"
        else:
            target_file = target_file_arg
            source_label = target_file_arg

        evidence_hash = compute_sha256(target_file)
        print(f"[*] Evidence SHA-256: {evidence_hash}")

        print(f"[*] Loading Sigma rules from '{args.rules}'...")
        rules = load_rules(args.rules)
        print(f"[+] Loaded {len(rules)} active detection rules.")

        enricher = AlertEnricher(cache_db_path=cache_db, abuseipdb_key=args.api_key)

        print(f"[*] Streaming events from '{source_label}'...")
        total_events = 0
        triggered_alerts = []

        for event in stream_events(target_file):
            total_events += 1
            hits = evaluate_event(event, rules)
            for hit in hits:
                enriched_hit = enricher.enrich_alert(hit)
                triggered_alerts.append(enriched_hit)
                print(f"    [!] ALERT [{enriched_hit['level']}] {enriched_hit['title']} (Host: {event.get('Computer')})")

        md_path = generate_markdown_report(
            alerts=triggered_alerts,
            source_file=source_label,
            total_events_scanned=total_events,
            output_path=output_path,
            evidence_sha256=evidence_hash,
        )

        if json_out:
            json_path = generate_json_report(triggered_alerts, json_out)
            print(f"[+] JSON report exported to: {json_path}")

        elapsed = time.perf_counter() - start_time
        print(f"\n[✓] Scan complete in {elapsed:.3f}s | Events scanned: {total_events} | Alerts: {len(triggered_alerts)}")
        print(f"[✓] Incident report saved to: {md_path}")

    finally:
        if temp_live_file and os.path.exists(temp_live_file):
            os.remove(temp_live_file)


if __name__ == "__main__":
    main()