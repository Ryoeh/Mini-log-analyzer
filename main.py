
import argparse
from pathlib import Path

from parser import parse_log_file
from analyzer import analyze_logs
from detector import detect_suspicious_activity
from report import (
    print_report,
    save_json_report,
    save_text_report,
)


def main():
    parser = argparse.ArgumentParser(
        description="Mini Apache Log Analyzer"
    )

    parser.add_argument(
        "--file",
        required=True,
        help="Path to the Apache access log file"
    )

    parser.add_argument(
        "--json",
        help="Path where the JSON report will be saved"
    )

    parser.add_argument(
        "--txt",
        help="Path where the TXT report will be saved"
    )

    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top IPs and endpoints to display"
    )

    args = parser.parse_args()

    log_path = Path(args.file)

    if not log_path.is_file():
        parser.error(f"Log file not found: {log_path}")

    if args.top < 1:
        parser.error("--top must be greater than 0")

    print("[+] Reading Apache logs...")

    try:
        total_lines = sum(
            1 for _ in log_path.open(
                "r", encoding="utf-8", errors="replace"
            )
        )

        logs = parse_log_file(log_path)

    except OSError as error:
        parser.error(f"Unable to read log file: {error}")

    if not logs:
        parser.error("No valid log entries found.")

    malformed = total_lines - len(logs)

    print(f"[+] Successfully parsed: {len(logs)} entries")
    print(f"[+] Malformed entries: {malformed}")

    print("[+] Analyzing traffic...")

    analysis = analyze_logs(logs, top_n=args.top)

    print("[+] Detecting suspicious activity...")

    findings = detect_suspicious_activity(logs)

    print_report(
        analysis,
        findings,
        malformed
    )

    if args.json:
        save_json_report(
            analysis,
            findings,
            malformed,
            args.json
        )

    if args.txt:
        save_text_report(
            analysis,
            findings,
            malformed,
            args.txt
        )

    print("\n[+] Analysis completed successfully.")


if __name__ == "__main__":
    main()