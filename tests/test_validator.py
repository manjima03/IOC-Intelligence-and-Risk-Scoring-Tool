import unittest
from src.validator import validate_and_normalize

class ValidatorTests(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(validate_and_normalize("8.8.8.8")[2], "ip")
    def test_domain(self):
        ok, normalized, kind, _ = validate_and_normalize("Example.COM.")
        self.assertTrue(ok)
        self.assertEqual(normalized, "example.com")
        self.assertEqual(kind, "domain")
    def test_url(self):
        ok, normalized, kind, _ = validate_and_normalize("HTTPS://Example.com/login#section")
        self.assertTrue(ok)
        self.assertEqual(kind, "url")
        self.assertEqual(normalized, "https://example.com/login")
    def test_hash(self):
        ok, _, kind, _ = validate_and_normalize("a" * 64)
        self.assertTrue(ok)
        self.assertEqual(kind, "hash")
    def test_invalid(self):
        self.assertFalse(validate_and_normalize("not an indicator")[0])

if __name__ == "__main__":
    unittest.main()
