import unittest

from auth_lab import SecureAuth, VulnerableAuth


class AuthComparisonTest(unittest.TestCase):
    def setUp(self):
        self.vulnerable = VulnerableAuth()
        self.secure = SecureAuth()

    def test_same_sql_injection_succeeds_only_before_fix(self):
        payload = "' OR 1=1 --"
        self.assertTrue(self.vulnerable.login(payload, "x").ok)
        self.assertFalse(self.secure.login(payload, "x").ok)

    def test_password_is_not_stored_in_cleartext_after_fix(self):
        plain = self.vulnerable.db.execute("SELECT password FROM users").fetchone()[0]
        salt, digest = self.secure.db.execute("SELECT salt, digest FROM users").fetchone()
        self.assertEqual(plain, "correct-horse")
        self.assertEqual(len(salt), 16)
        self.assertEqual(len(digest), 32)
        self.assertNotIn(plain.encode(), digest)

    def test_long_input_is_rejected_after_fix(self):
        username = "a" * 1000
        self.assertFalse(self.vulnerable.login(username, "x").ok)
        self.assertEqual(self.secure.login(username, "x").message, "Неверные учётные данные")

    def test_user_enumeration_message_is_removed(self):
        self.assertNotEqual(
            self.vulnerable.login("alice", "x").message,
            self.vulnerable.login("absent", "x").message,
        )
        self.assertEqual(
            self.secure.login("alice", "x").message,
            self.secure.login("absent", "x").message,
        )

    def test_rate_limit_rejects_correct_password_after_five_failures(self):
        for _ in range(5):
            self.assertFalse(self.vulnerable.login("alice", "x").ok)
            self.assertFalse(self.secure.login("alice", "x").ok)
        self.assertTrue(self.vulnerable.login("alice", "correct-horse").ok)
        locked = self.secure.login("alice", "correct-horse")
        self.assertFalse(locked.ok)
        self.assertEqual(locked.message, "Временно ограничены попытки входа")


if __name__ == "__main__":
    unittest.main()
