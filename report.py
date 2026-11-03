
import json
from pathlib import Path


def generate_text_report(analysis, findings, malformed=0):

    lines = [
        "=" * 45,
        "          MINI APACHE LOG ANALYZER",
        "=" * 45,
        "",
        f"Total requests: {analysis['total_requests']}",
        f"Unique IPs: {analysis['unique_ips']}",
        f"Total bytes: {analysis['total_bytes']}",
        f"Average response size: {analysis['average_response_size']} bytes",
        f"Malformed entries: {malformed}",
        "",
        "--- HTTP STATUS CODES ---",
    ]

    for status, count in analysis["status_codes"].items():
        lines.append(f"{status}: {count}")

    lines.extend([
        "",
        "--- STATUS GROUPS ---"
    ])

    for group, count in analysis["status_groups"].items():
        lines.append(f"{group}: {count}")

    lines.extend([
        "",
        "--- HTTP METHODS ---"
    ])

    for method, count in analysis["methods"].items():
        lines.append(f"{method}: {count}")

    lines.extend([
        "",
        "--- TOP IP ADDRESSES ---"
    ])

    for item in analysis["top_ips"]:
        lines.append(
            f"{item['ip']}: {item['requests']} requests"
        )

    lines.extend([
        "",
        "--- TOP ENDPOINTS ---"
    ])

    for item in analysis["top_endpoints"]:
        lines.append(
            f"{item['endpoint']}: {item['requests']} requests"
        )

    lines.extend([
        "",
        "--- SECURITY FINDINGS ---"
    ])

    if findings:

        for finding in findings:
            lines.append(
                f"[{finding['severity']}] "
                f"{finding['type']} - "
                f"{finding['ip']}"
            )

            lines.append(
                f"    {finding['description']}"
            )

    else:
        lines.append("No suspicious indicators detected.")

    lines.append("")
    lines.append("=" * 45)

    return "\n".join(lines)


def print_report(analysis, findings, malformed=0):

    print(
        generate_text_report(
            analysis,
            findings,
            malformed
        )
    )


def save_text_report(
    analysis,
    findings,
    malformed,
    output_path
):

    path = Path(output_path)

    path.parent.mkdir(parents=True, exist_ok=True)

    content = generate_text_report(
        analysis,
        findings,
        malformed
    )

    path.write_text(content, encoding="utf-8")

    print(f"[+] TXT report saved to: {path}")


def save_json_report(
    analysis,
    findings,
    malformed,
    output_path
):

    path = Path(output_path)

    path.parent.mkdir(parents=True, exist_ok=True)

    report_data = {
        "analysis": analysis,
        "security_findings": findings,
        "malformed_entries": malformed,
    }

    content = json.dumps(
        report_data,
        indent=4,
        default=str
    )

    path.write_text(content, encoding="utf-8")

    print(f"[+] JSON report saved to: {path}")
