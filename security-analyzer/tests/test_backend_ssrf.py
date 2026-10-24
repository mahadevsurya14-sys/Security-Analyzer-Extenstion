"""
Security Analyzer - SSRF Security & Backend API Tests
Validates SSRF prevention, IP filtering, and FastAPI endpoint security.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.ssrf_guard import validate_target_url, SSRFValidationError
from backend.main import app


class TestSSRFProtection(unittest.TestCase):
    def test_blocks_localhost_and_loopback(self):
        with self.assertRaises(SSRFValidationError):
            validate_target_url("http://localhost:8080")

        with self.assertRaises(SSRFValidationError):
            validate_target_url("http://127.0.0.1:8000")

        with self.assertRaises(SSRFValidationError):
            validate_target_url("http://127.0.0.2")

    def test_blocks_rfc1918_private_ips(self):
        with self.assertRaises(SSRFValidationError):
            validate_target_url("http://10.0.0.1/admin")

        with self.assertRaises(SSRFValidationError):
            validate_target_url("http://192.168.1.1/")

        with self.assertRaises(SSRFValidationError):
            validate_target_url("http://172.16.0.5/api")

    def test_blocks_cloud_metadata(self):
        with self.assertRaises(SSRFValidationError):
            validate_target_url("http://169.254.169.254/latest/meta-data/")

        with self.assertRaises(SSRFValidationError):
            validate_target_url("http://metadata.google.internal/computeMetadata/v1/")

    def test_blocks_non_http_schemes(self):
        with self.assertRaises(SSRFValidationError):
            validate_target_url("ftp://ftp.example.com")

        with self.assertRaises(SSRFValidationError):
            validate_target_url("file:///etc/passwd")

        with self.assertRaises(SSRFValidationError):
            validate_target_url("gopher://127.0.0.1:70")


class TestBackendAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_endpoint(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "online")
        self.assertEqual(data.get("service"), "Security Analyzer API")

    def test_scan_endpoint_blocks_ssrf(self):
        resp = self.client.post("/api/scan", json={"target_url": "http://127.0.0.1:8000/internal"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("SSRF Safety Policy Violation", resp.json().get("detail", ""))

        resp_meta = self.client.post("/api/scan", json={"target_url": "http://169.254.169.254/secret"})
        self.assertEqual(resp_meta.status_code, 400)


if __name__ == "__main__":
    unittest.main()
