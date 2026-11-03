
import re
from collections import Counter


SUSPICIOUS_PATTERNS = [
    re.compile(r"/\.env(?:/|$)", re.IGNORECASE),
    re.compile(r"/\.git(?:/|$)", re.IGNORECASE),
    re.compile(r"/wp-admin(?:/|$)", re.IGNORECASE),
    re.compile(r"/phpmyadmin(?:/|$)", re.IGNORECASE),
    re.compile(r"/etc/passwd(?:/|$)", re.IGNORECASE),
    re.compile(r"/admin(?:/|$)", re.IGNORECASE),
]


def detect_suspicious_activity(
    logs,
    request_threshold=5,
    auth_threshold=3
):
    """
    Detect potentially suspicious patterns in Apache logs.
    Returns a list of findings.
    """

    if request_threshold < 1 or auth_threshold < 1:
        raise ValueError("Thresholds must be greater than 0.")

    findings = []

    ip_counter = Counter()
    auth_counter = Counter()

    for log in logs:

        ip = log["ip"]
        path = log["path"]
        status = log["status"]

        ip_counter[ip] += 1

        if status in (401, 403):
            auth_counter[ip] += 1

        for pattern in SUSPICIOUS_PATTERNS:

            if pattern.search(path):

                findings.append({
                    "severity": "MEDIUM",
                    "type": "SUSPICIOUS_PATH",
                    "ip": ip,
                    "path": path,
                    "description": (
                        "Request to a potentially sensitive endpoint."
                    )
                })

                break

    for ip, count in ip_counter.items():

        if count >= request_threshold:

            findings.append({
                "severity": "LOW",
                "type": "HIGH_REQUEST_VOLUME",
                "ip": ip,
                "count": count,
                "description": (
                    "IP generated an unusually high number "
                    "of requests."
                )
            })

    for ip, count in auth_counter.items():

        if count >= auth_threshold:

            findings.append({
                "severity": "HIGH",
                "type": "REPEATED_AUTH_ERRORS",
                "ip": ip,
                "count": count,
                "description": (
                    "Multiple HTTP 401/403 responses "
                    "associated with the same IP."
                )
            })

    return findings
