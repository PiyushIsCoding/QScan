import unittest

import core


class ScannerTests(unittest.TestCase):
    def test_comments_and_docstrings_are_not_reported(self):
        python_source = '''"""RSA-2048 documentation"""
# MD5 is mentioned in a comment
    KEY_BITS = 2048
    key = RSA.generate(KEY_BITS)
value = 1  # SHA-1 inline comment
'''
        javascript_source = '''/* ECDSA is documented here */
const cipher = createCipheriv("aes-256-gcm", key, iv);
'''

        findings = core._scan_code("fixture.py", python_source, "python")
        findings += core._scan_code("fixture.js", javascript_source, "javascript")

        self.assertEqual([finding["family"] for finding in findings], ["RSA", "AES"])
        self.assertEqual([finding["line"] for finding in findings], [4, 2])
        self.assertEqual(findings[0]["evidence"][1:], ["key size resolved from constant"])

    def test_embedded_ecdsa_size_is_not_reported_as_constant(self):
        findings = core._scan_code("fixture.py", "key = ec.SECP256R1()\n", "python")

        self.assertEqual(findings[0]["algorithm"], "ECDSA-P256")
        self.assertNotIn("key size resolved from constant", findings[0]["evidence"])

    def test_cbom_omits_empty_replacement(self):
        finding = {
            "id": "one", "asset_type": "algorithm", "family": "SHA-256", "algorithm": "SHA-256",
            "purpose": "hash", "key_size": None, "service": "service", "confidence": 0.8,
            "file": "app.py", "line": 1, "risk": {"severity": "LOW", "score": 10},
            "recommendation": {"target": "", "strategy": ""},
        }

        properties = core.to_cbom([finding])["components"][0]["properties"]

        self.assertNotIn("qscan:recommended-replacement", {p["name"] for p in properties})


if __name__ == "__main__":
    unittest.main()