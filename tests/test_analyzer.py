
import unittest

from analyzer import analyze_logs


class TestAnalyzer(unittest.TestCase):

    def setUp(self):
        self.logs = [
            {
                "ip": "192.0.2.10",
                "path": "/index.html",
                "method": "GET",
                "status": 200,
                "size": 100,
            },
            {
                "ip": "192.0.2.10",
                "path": "/login",
                "method": "POST",
                "status": 401,
                "size": 50,
            },
            {
                "ip": "192.0.2.11",
                "path": "/index.html",
                "method": "GET",
                "status": 200,
                "size": 200,
            },
        ]

    def test_total_requests(self):
        result = analyze_logs(self.logs)

        self.assertEqual(result["total_requests"], 3)

    def test_unique_ips(self):
        result = analyze_logs(self.logs)

        self.assertEqual(result["unique_ips"], 2)

    def test_status_codes(self):
        result = analyze_logs(self.logs)

        self.assertEqual(result["status_codes"][200], 2)
        self.assertEqual(result["status_codes"][401], 1)

    def test_top_ips(self):
        result = analyze_logs(self.logs)

        self.assertEqual(
            result["top_ips"][0]["ip"],
            "192.0.2.10"
        )

    def test_status_groups(self):
        result = analyze_logs(self.logs)

        self.assertEqual(result["status_groups"]["2xx"], 2)
        self.assertEqual(result["status_groups"]["4xx"], 1)

    def test_total_bytes(self):
        result = analyze_logs(self.logs)

        self.assertEqual(result["total_bytes"], 350)

    def test_average_size(self):
        result = analyze_logs(self.logs)

        self.assertEqual(result["average_response_size"], 116.67)

    def test_empty_logs(self):
        with self.assertRaises(ValueError):
            analyze_logs([])

    def test_invalid_top_n(self):
        with self.assertRaises(ValueError):
            analyze_logs(self.logs, top_n=0)


if __name__ == "__main__":
    unittest.main()
