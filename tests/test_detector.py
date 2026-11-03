import unittest

from detector import detect_suspicious_activity


class TestDetector(unittest.TestCase):

    def setUp(self):
        self.logs = [
            {
                "ip": "192.0.2.10",
                "path": "/index.html",
                "status": 200,
            },
            {
                "ip": "192.0.2.10",
                "path": "/admin",
                "status": 403,
            },
            {
                "ip": "192.0.2.10",
                "path": "/login",
                "status": 401,
            },
            {
                "ip": "192.0.2.10",
                "path": "/login",
                "status": 401,
            },
            {
                "ip": "192.0.2.11",
                "path": "/index.html",
                "status": 200,
            },
        ]

    def test_suspicious_path(self):
        findings = detect_suspicious_activity(self.logs)

        result = [
            item for item in findings
            if item["type"] == "SUSPICIOUS_PATH"
        ]

        self.assertGreaterEqual(len(result), 1)

    def test_repeated_auth_errors(self):
        findings = detect_suspicious_activity(self.logs)

        result = [
            item for item in findings
            if item["type"] == "REPEATED_AUTH_ERRORS"
        ]

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip"], "192.0.2.10")
        self.assertEqual(result[0]["count"], 3)

    def test_high_request_volume(self):
        findings = detect_suspicious_activity(
            self.logs,
            request_threshold=4
        )

        result = [
            item for item in findings
            if item["type"] == "HIGH_REQUEST_VOLUME"
        ]

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip"], "192.0.2.10")
        self.assertEqual(result[0]["count"], 4)

    def test_custom_threshold(self):
        findings = detect_suspicious_activity(
            self.logs,
            request_threshold=3
        )

        result = [
            item for item in findings
            if item["type"] == "HIGH_REQUEST_VOLUME"
        ]

        self.assertEqual(len(result), 1)

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_suspicious_activity(
                self.logs,
                request_threshold=0
            )

    def test_invalid_auth_threshold(self):
        with self.assertRaises(ValueError):
            detect_suspicious_activity(
                self.logs,
                auth_threshold=0
            )

    def test_empty_logs(self):
        findings = detect_suspicious_activity([])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
