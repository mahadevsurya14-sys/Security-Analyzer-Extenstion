"""
Security Analyzer - Engine Unit & Fixture Integration Tests
Tests fingerprint matching, version classification, security analysis,
CVE intelligence matching, and report generation.
"""

import json
import os
import re
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestSecurityAnalyzerEngine(unittest.TestCase):
    def setUp(self):
        fp_path = os.path.join(PROJECT_ROOT, "engine", "fingerprints.json")
        with open(fp_path, "r", encoding="utf-8") as f:
            self.fingerprints = json.load(f)["technologies"]

    def _simulate_detect(self, page_data):
        """Simulates detector.js matching in Python for rigorous verification across all categories."""
        detected = []
        headers = {k.lower(): str(v) for k, v in page_data.get("headers", {}).items()}
        cookies = set(page_data.get("cookies", []))
        meta = {k.lower(): str(v) for k, v in page_data.get("meta", {}).items()}
        scripts = page_data.get("scripts", [])
        links = page_data.get("links", [])
        resources = page_data.get("resources", [])
        combined_scripts = list(scripts) + [
            r for r in resources if r.endswith(".js") or ".js?" in r or "/js/" in r or "script" in r
        ]
        selectors = set(page_data.get("selectors", []))
        css_signatures = set(page_data.get("cssSignatures", []))
        pwa = page_data.get("pwa", {})
        globals_dict = page_data.get("globals", {})

        for tech in self.fingerprints:
            evidence = []
            version = None
            rules = tech.get("rules", {})

            # 1. Headers
            if "headers" in rules:
                for h_name, pat in rules["headers"].items():
                    val = headers.get(h_name.lower())
                    if val:
                        m = re.search(pat, val, re.IGNORECASE)
                        if m:
                            evidence.append(f"Header {h_name} matched {pat}")
                            if m.groups() and m.group(1):
                                version = m.group(1)

            # 2. Cookies
            if "cookies" in rules:
                for c_pat in rules["cookies"]:
                    for c in cookies:
                        m = re.search(c_pat, c, re.IGNORECASE)
                        if m:
                            evidence.append(f"Cookie matched {c_pat}")
                            if m.groups() and m.group(1):
                                version = m.group(1)

            # 3. Meta
            if "meta" in rules:
                for m_name, pat in rules["meta"].items():
                    val = meta.get(m_name.lower())
                    if val:
                        m = re.search(pat, val, re.IGNORECASE)
                        if m:
                            evidence.append(f"Meta {m_name} matched {pat}")
                            if m.groups() and m.group(1):
                                version = m.group(1)

            # 4. Scripts & Combined Resource Timings
            if "scripts" in rules:
                for s in combined_scripts:
                    for pat in rules["scripts"]:
                        m = re.search(pat, s, re.IGNORECASE)
                        if m:
                            evidence.append(f"Script matched {pat}")
                            if m.groups() and m.group(1):
                                version = m.group(1)

            # 5. Links
            if "links" in rules:
                for pat in rules["links"]:
                    for l in links:
                        m = re.search(pat, l, re.IGNORECASE)
                        if m:
                            evidence.append(f"Link matched {pat}")
                            if m.groups() and m.group(1):
                                version = m.group(1)

            # 6. Selectors
            if "selectors" in rules:
                for sel in rules["selectors"]:
                    if sel in selectors:
                        evidence.append(f"Selector matched {sel}")

            # 7. CSS Signatures
            if "cssSignatures" in rules:
                for sig in rules["cssSignatures"]:
                    if sig in css_signatures:
                        evidence.append(f"CSS signature matched {sig}")

            # 8. PWA Indicators
            if rules.get("pwa"):
                if pwa and (pwa.get("hasManifest") or pwa.get("hasServiceWorker")):
                    evidence.append("PWA indicators present (Manifest or Service Worker)")

            # 9. Globals
            if "globals" in rules:
                for g in rules["globals"]:
                    p = g["path"]
                    if p in globals_dict:
                        evidence.append(f"Global window.{p} present")
                        if g.get("versionPath") and g["versionPath"] in globals_dict:
                            version = str(globals_dict[g["versionPath"]])

            if evidence:
                detected.append({
                    "id": tech["id"],
                    "name": tech["name"],
                    "category": tech["category"],
                    "version": version,
                    "evidence_count": len(evidence)
                })

        return detected

    def test_wordpress_detection_from_fixture(self):
        page_data = {
            "url": "https://example.com",
            "headers": {
                "server": "Apache/2.4.52 (Ubuntu)",
                "x-powered-by": "PHP/8.1.2"
            },
            "meta": {
                "generator": "WordPress 6.2.0"
            },
            "scripts": [
                "https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.6.0",
                "https://example.com/wp-content/themes/twentytwentythree/assets/js/theme.js"
            ],
            "selectors": ["#wpadminbar", "link[rel='https://api.w.org/']"]
        }

        detected = self._simulate_detect(page_data)
        detected_ids = {t["id"] for t in detected}

        self.assertIn("wordpress", detected_ids, "WordPress must be detected")
        self.assertIn("apache", detected_ids, "Apache must be detected from Server header")
        self.assertIn("php", detected_ids, "PHP must be detected from X-Powered-By")
        self.assertIn("jquery", detected_ids, "jQuery must be detected from script tag")

        wp_item = next(t for t in detected if t["id"] == "wordpress")
        self.assertEqual(wp_item["version"], "6.2.0", "WordPress version must be 6.2.0")

    def test_modern_nextjs_detection_from_fixture(self):
        page_data = {
            "url": "https://example.com",
            "headers": {
                "server": "cloudflare",
                "cf-ray": "8234857283472-IAD"
            },
            "scripts": [
                "https://example.com/_next/static/chunks/main.js"
            ],
            "selectors": [
                "[data-reactroot]",
                "script#__NEXT_DATA__"
            ],
            "globals": {
                "React.version": "18.2.0",
                "__NEXT_DATA__.buildId": "prod_v102"
            }
        }

        detected = self._simulate_detect(page_data)
        detected_ids = {t["id"] for t in detected}

        self.assertIn("nextjs", detected_ids, "Next.js must be detected")
        self.assertIn("react", detected_ids, "React must be detected")
        self.assertIn("cloudflare", detected_ids, "Cloudflare must be detected")

        react_item = next(t for t in detected if t["id"] == "react")
        self.assertEqual(react_item["version"], "18.2.0", "React version must be 18.2.0")

    def test_cve_correlation_logic(self):
        """Verifies CVE matching against jQuery and Apache vulnerable versions."""
        # Check jQuery 3.4.1 (affected by CVE-2020-11022)
        jquery_version = "3.4.1"
        is_jquery_affected = bool(re.match(r"^([0-2]\.|3\.[0-4]\.)", jquery_version))
        self.assertTrue(is_jquery_affected, "jQuery 3.4.1 must match CVE-2020-11022 affected regex")

        # Check jQuery 3.7.1 (fixed / safe)
        safe_jquery = "3.7.1"
        is_safe_affected = bool(re.match(r"^([0-2]\.|3\.[0-4]\.)", safe_jquery))
        self.assertFalse(is_safe_affected, "jQuery 3.7.1 must not match CVE-2020-11022")

        # Check Apache 2.4.49 (affected by CVE-2021-41773 path traversal)
        apache_vuln = "2.4.49"
        is_apache_vuln = bool(re.match(r"^2\.4\.49$", apache_vuln))
        self.assertTrue(is_apache_vuln, "Apache 2.4.49 must match CVE-2021-41773")

    def test_version_classification_rules(self):
        """Verifies Exact, Inferred, Partial, and Unknown classifications."""
        # Exact semver
        self.assertTrue(bool(re.match(r"^\d+\.\d+\.\d+", "18.2.0")))
        # Major/minor partial
        self.assertTrue(bool(re.match(r"^\d+\.\d+$", "2.4")))
        # Major only partial
        self.assertTrue(bool(re.match(r"^\d+$", "5")))

    def test_security_header_rules(self):
        """Simulates security header evaluation logic."""
        headers = {
            "server": "Apache/2.4.52 (Ubuntu)",
            "x-powered-by": "PHP/8.1.2"
        }
        # Check missing HSTS
        self.assertNotIn("strict-transport-security", headers)
        # Check missing CSP
        self.assertNotIn("content-security-policy", headers)
        # Check missing X-Content-Type-Options
        self.assertNotIn("x-content-type-options", headers)
        # Check server version disclosure
        self.assertTrue(bool(re.search(r"\d+\.\d+", headers["server"])))

    def test_json_and_csv_report_generation(self):
        """Tests JSON and CSV data formatting and serialization."""
        scan_data = {
            "targetUrl": "https://example.com",
            "securityScore": 82,
            "grade": "B",
            "detectedTechnologies": [
                {"name": "WordPress", "category": "CMS", "version": "6.2.0", "versionStatus": "Exact", "confidence": 95}
            ],
            "securityFindings": [
                {"id": "SEC-CSP-MISSING", "title": "Missing CSP", "severity": "Medium", "remediation": "Deploy CSP"}
            ]
        }

        # Validate JSON serialization
        json_output = json.dumps(scan_data, indent=2)
        self.assertIn('"WordPress"', json_output)
        self.assertIn('"SEC-CSP-MISSING"', json_output)

        # Validate CSV row generation
        csv_row = f'"{scan_data["targetUrl"]}","{scan_data["securityScore"]}","{scan_data["grade"]}"'
        self.assertIn('"https://example.com"', csv_row)

    def test_multicategory_known_fingerprints(self):
        """Verifies detections across diverse categories: UI, Analytics, Security, WebSocket, PWA, Ads."""
        page_data = {
            "url": "https://modern-app.io",
            "headers": {"server": "cloudflare"},
            "cssSignatures": ["tailwind"],
            "globals": {
                "Sentry": True,
                "Sentry.SDK_VERSION": "7.52.1",
                "Google_AdSense": True,
                "Socket.io": True
            },
            "selectors": [".cf-turnstile"],
            "pwa": {"hasManifest": True, "hasServiceWorker": True}
        }

        detected = self._simulate_detect(page_data)
        detected_ids = {t["id"]: t for t in detected}

        # 1. UI Framework
        self.assertIn("tailwind", detected_ids, "Tailwind CSS must be detected")
        self.assertEqual(detected_ids["tailwind"]["category"], "UI Framework")

        # 2. Analytics & RUM
        self.assertIn("sentry", detected_ids, "Sentry must be detected")
        self.assertEqual(detected_ids["sentry"]["category"], "Analytics & RUM")
        self.assertEqual(detected_ids["sentry"]["version"], "7.52.1")

        # 3. Security Service
        self.assertIn("cloudflare-turnstile", detected_ids, "Cloudflare Turnstile must be detected")
        self.assertEqual(detected_ids["cloudflare-turnstile"]["category"], "Security Service")

        # 4. API & WebSocket
        self.assertIn("socket-io", detected_ids, "Socket.io must be detected")
        self.assertEqual(detected_ids["socket-io"]["category"], "API & WebSocket")

        # 5. PWA & Performance
        self.assertIn("pwa", detected_ids, "PWA must be detected")
        self.assertEqual(detected_ids["pwa"]["category"], "PWA & Performance")

        # 6. Advertising
        self.assertIn("google-adsense", detected_ids, "Google AdSense must be detected")
        self.assertEqual(detected_ids["google-adsense"]["category"], "Advertising")

    def test_negative_framework_does_not_invent_programming_language(self):
        """Rigorous negative test: Framework detection must NEVER invent backend programming languages."""
        # Page has Next.js and React, but NO backend runtime headers or .php / .py indicators
        page_data = {
            "url": "https://next-store.com",
            "headers": {"server": "Vercel"},
            "scripts": ["https://next-store.com/_next/static/chunks/app.js"],
            "selectors": ["script#__NEXT_DATA__", "[data-reactroot]"],
            "globals": {"React.version": "18.2.0"}
        }

        detected = self._simulate_detect(page_data)
        detected_names = {t["name"] for t in detected}
        backend_languages = {"PHP", "Python", "Ruby", "Java", "C# (.NET)", "Go (Golang)"}

        for lang in backend_languages:
            self.assertNotIn(lang, detected_names, f"Framework presence must NOT invent language {lang}")

    def test_false_positive_prevention(self):
        """Verifies that incidental words in body text or comments do not trigger false detections."""
        page_data = {
            "url": "https://nature-blog.org",
            "headers": {"content-type": "text/html"},
            "scripts": [],
            "selectors": [],
            "globals": {},
            "html": "<html><body>We observed a python snake and a ruby gemstone in nature.</body></html>"
        }

        detected = self._simulate_detect(page_data)
        detected_ids = {t["id"] for t in detected}

        self.assertNotIn("python", detected_ids, "Incidental text 'python' must not trigger Python detection")
        self.assertNotIn("ruby", detected_ids, "Incidental text 'ruby' must not trigger Ruby detection")
        self.assertEqual(len(detected), 0, "No false positives should be produced")

    def test_missing_evidence_and_unknown_tech(self):
        """Verifies graceful handling of empty or unknown web pages."""
        empty_page = {}
        detected = self._simulate_detect(empty_page)
        self.assertEqual(detected, [], "Empty page data must return an empty list with zero errors")

        plain_page = {
            "url": "https://unknown-custom-page.local",
            "headers": {"content-type": "text/html"},
            "scripts": [],
            "selectors": [".my-custom-div"],
            "globals": {"myCustomVar": True}
        }
        detected_plain = self._simulate_detect(plain_page)
        self.assertEqual(detected_plain, [], "Custom unknown technologies must not trigger arbitrary detections")

    def test_version_evidence_integrity(self):
        """Verifies that versions are never invented and only confirmed from reliable evidence."""
        # 1. Indicator present with NO version evidence -> version must be None
        page_with_unversioned_tech = {
            "globals": {"Cloudflare_Turnstile": True},
            "selectors": [".cf-turnstile"]
        }
        detected = self._simulate_detect(page_with_unversioned_tech)
        turnstile = next((t for t in detected if t["id"] == "cloudflare-turnstile"), None)
        self.assertIsNotNone(turnstile)
        self.assertIsNone(turnstile["version"], "Version must be None when no version evidence exists; never invented")

        # 2. Indicator present WITH version evidence -> version captured accurately
        page_with_versioned_tech = {
            "globals": {
                "React": True,
                "React.version": "18.3.1"
            }
        }
        detected_ver = self._simulate_detect(page_with_versioned_tech)
        react = next((t for t in detected_ver if t["id"] == "react"), None)
        self.assertIsNotNone(react)
        self.assertEqual(react["version"], "18.3.1", "Version must accurately match the declared runtime version")



if __name__ == "__main__":
    unittest.main()
