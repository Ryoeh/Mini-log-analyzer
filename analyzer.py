
from collections import Counter


def analyze_logs(logs, top_n=5):
    """
    Analyze parsed Apache logs and return traffic statistics.
    """

    if not logs:
        raise ValueError("No logs provided for analysis.")

    if top_n < 1:
        raise ValueError("top_n must be greater than 0.")

    ip_counter = Counter()
    endpoint_counter = Counter()
    method_counter = Counter()
    status_counter = Counter()

    total_bytes = 0
    known_sizes = 0

    for log in logs:

        ip_counter[log["ip"]] += 1

        endpoint_counter[log["path"]] += 1

        method_counter[log["method"]] += 1

        status_counter[log["status"]] += 1

        if log["size"] is not None:
            total_bytes += log["size"]
            known_sizes += 1

    status_groups = {
        "2xx": sum(
            count for status, count in status_counter.items()
            if 200 <= status < 300
        ),
        "3xx": sum(
            count for status, count in status_counter.items()
            if 300 <= status < 400
        ),
        "4xx": sum(
            count for status, count in status_counter.items()
            if 400 <= status < 500
        ),
        "5xx": sum(
            count for status, count in status_counter.items()
            if 500 <= status < 600
        ),
    }

    average_response_size = (
        total_bytes / known_sizes
        if known_sizes else 0
    )

    return {
        "total_requests": len(logs),

        "unique_ips": len(ip_counter),

        "total_bytes": total_bytes,

        "average_response_size": round(
            average_response_size, 2
        ),

        "status_codes": dict(
            sorted(status_counter.items())
        ),

        "status_groups": status_groups,

        "methods": dict(method_counter),

        "top_ips": [
            {"ip": ip, "requests": count}
            for ip, count in ip_counter.most_common(top_n)
        ],

        "top_endpoints": [
            {"endpoint": endpoint, "requests": count}
            for endpoint, count in endpoint_counter.most_common(top_n)
        ],
    }
