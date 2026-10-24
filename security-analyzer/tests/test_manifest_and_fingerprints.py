"""
Security Analyzer - Manifest and Fingerprints Integrity Tests
Validates Chrome Manifest V3 conformance and fingerprint database syntax.
"""

import json
import os
import re
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestManifestIntegrity(unittest.TestCase):
    def setUp(self):
        self.manifest_path = os.path.join(PROJECT_ROOT, "manifest.json")
        self.assertTrue(os.path.exists(self.manifest_path), "manifest.json must exist")
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            self.manifest = json.load(f)

    def test_manifest_v3_specification(self):
        self.assertEqual(self.manifest.get("manifest_version"), 3, "Must target Manifest V3")
        self.assertEqual(self.manifest.get("name"), "Security Analyzer", "Product name must be Security Analyzer")
        self.assertTrue(self.manifest.get("version"), "Must have a version number")

    def test_referenced_files_exist(self):
        # Service worker
        sw = self.manifest.get("background", {}).get("service_worker")
        self.assertTrue(sw, "Service worker must be declared")
        self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, sw)), f"Service worker file {sw} must exist")

        # Popup
        popup = self.manifest.get("action", {}).get("default_popup")
        self.assertTrue(popup, "Popup must be declared")
        self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, popup)), f"Popup file {popup} must exist")

        # Icons
        icons = self.manifest.get("icons", {})
        for size, path in icons.items():
            self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, path)), f"Icon {path} must exist on disk")

        # Content scripts
        for cs in self.manifest.get("content_scripts", []):
            for js_file in cs.get("js", []):
                self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, js_file)), f"Content script {js_file} must exist")


class TestFingerprintsDatabase(unittest.TestCase):
    def setUp(self):
        self.fp_path = os.path.join(PROJECT_ROOT, "engine", "fingerprints.json")
        self.assertTrue(os.path.exists(self.fp_path), "fingerprints.json must exist")
        with open(self.fp_path, "r", encoding="utf-8") as f:
            self.fp = json.load(f)

    def test_database_structure(self):
        techs = self.fp.get("technologies", [])
        self.assertGreaterEqual(len(techs), 20, "Should contain comprehensive fingerprint definitions")

        valid_categories = {
            "JavaScript Framework", "UI Framework", "JavaScript Library",
            "CMS", "Analytics & RUM", "Advertising", "Security Service",
            "CDN", "Hosting & PaaS", "Web Server", "Programming Language",
            "API & WebSocket", "PWA & Performance"
        }

        for tech in techs:
            self.assertIn("id", tech, "Technology must have an id")
            self.assertIn("name", tech, "Technology must have a name")
            self.assertIn("category", tech, f"Technology {tech.get('name')} must have a category")
            self.assertIn(tech["category"], valid_categories, f"Invalid category {tech['category']}")
            self.assertIn("rules", tech, "Technology must have detection rules")

            # Validate all regexes in rules compile cleanly
            rules = tech["rules"]
            if "headers" in rules:
                for h_name, pattern in rules["headers"].items():
                    try:
                        re.compile(pattern, re.IGNORECASE)
                    except re.error as e:
                        self.fail(f"Invalid header regex in {tech['name']} for {h_name}: {e}")

            if "scripts" in rules:
                for pattern in rules["scripts"]:
                    try:
                        re.compile(pattern, re.IGNORECASE)
                    except re.error as e:
                        self.fail(f"Invalid script regex in {tech['name']}: {e}")

            if "meta" in rules:
                for m_name, pattern in rules["meta"].items():
                    try:
                        re.compile(pattern, re.IGNORECASE)
                    except re.error as e:
                        self.fail(f"Invalid meta regex in {tech['name']} for {m_name}: {e}")


if __name__ == "__main__":
    unittest.main()
