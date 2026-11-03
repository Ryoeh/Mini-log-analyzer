
import re
from datetime import datetime
from pathlib import Path


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<path>\S+)\s+'
    r'(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?$'
)


def parse_log_line(line):
    """
    Parse a single Apache Common or Combined Log Format entry.

    Returns:
        dict: Parsed log entry.
        None: If the log entry is invalid.
    """

    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z"
        )

        status = int(data["status"])

        size = (
            None
            if data["size"] == "-"
            else int(data["size"])
        )

        return {
            "ip": data["ip"],
            "timestamp": timestamp,
            "method": data["method"],
            "path": data["path"],
            "protocol": data["protocol"],
            "status": status,
            "size": size,
            "referer": data["referer"] or "-",
            "user_agent": data["user_agent"] or "-",
        }

    except (ValueError, TypeError):
        return None


def parse_log_file(file_path):
    """
    Parse an entire Apache access log file.

    Invalid entries are skipped.

    Returns:
        list: Successfully parsed log entries.
    """

    entries = []

    try:
        with Path(file_path).open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line in file:
                entry = parse_log_line(line)

                if entry is not None:
                    entries.append(entry)

    except OSError:
        raise

    return entries