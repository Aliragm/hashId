import unittest
from hashid.identify import identify


class TestIdentify(unittest.TestCase):
    def test_empty_string(self):
        self.assertIsNone(identify(""))
        self.assertIsNone(identify("   "))

    def test_md5(self):
        result = identify("5d41402abc4b2a76b9719d911017c592")
        self.assertIsInstance(result, list)
        self.assertIn("MD5", result)

    def test_sha256(self):
        result = identify("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertIsInstance(result, list)
        self.assertIn("SHA-256", result)

    def test_bcrypt(self):
        result = identify("$2a$12$e8KERg9vhw1k.1rTcgO1IuNq9a3lUe1.G83Vn0oN1PzJ4E/w8V/Gy")
        self.assertIsInstance(result, list)
        self.assertEqual(result, ["bcrypt (revision with UTF-8 support)"])

    def test_mysql5(self):
        result = identify("*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29")
        self.assertIsInstance(result, list)
        self.assertEqual(result, ["MySQL5"])

    def test_jwt(self):
        result = identify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J")
        self.assertIsInstance(result, str)
        self.assertTrue(result.startswith("Not a hash: Probable JSON Web Token"))

    def test_base64(self):
        result = identify("SGVsbG8gV29ybGQ=")
        self.assertIsInstance(result, str)
        self.assertTrue(result.startswith("Not a hash: Probable Base64"))

    def test_generic_phc(self):
        result = identify("$customalgo$v=1$parameters$hash")
        self.assertIsInstance(result, list)
        self.assertEqual(result, ["Generic PHC: customalgo"])

    def test_unknown_hash(self):
        self.assertIsNone(identify("invalid_hash_value_123"))


if __name__ == "__main__":
    unittest.main()
