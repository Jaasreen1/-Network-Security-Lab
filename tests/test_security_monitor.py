import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from security_monitor import validate_target, check_headers

class SecurityMonitorTests(unittest.TestCase):
    def test_local_target(self):
        self.assertEqual(validate_target("http://127.0.0.1:8000"), "http://127.0.0.1:8000")
    def test_localhost(self):
        self.assertEqual(validate_target("https://localhost"), "https://localhost")
    def test_external_target_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("https://example.com")
    def test_private_network_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("http://192.168.1.1")
    def test_credentials_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("http://user:pass@localhost")
    def test_missing_headers_are_potential(self):
        findings = check_headers({}, "https")
        self.assertTrue(all(f["status"] == "potential" for f in findings))
        self.assertEqual(len(findings), 3)
    def test_present_headers(self):
        findings = check_headers({"Strict-Transport-Security":"max-age=100","X-Content-Type-Options":"nosniff","Content-Security-Policy":"default-src 'self'"},"https")
        self.assertEqual(findings, [])
    def test_http_no_hsts_finding(self):
        self.assertNotIn("missing-hsts", [f["id"] for f in check_headers({}, "http")])
