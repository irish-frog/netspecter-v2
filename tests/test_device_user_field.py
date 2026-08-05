import unittest

from netspecter_ui_helpers import normalize_logged_in_user


class DeviceUserFieldTests(unittest.TestCase):
    def test_logged_in_user_domain_prefix_is_ignored(self):
        self.assertEqual("gavin", normalize_logged_in_user(r"WSL\gavin"))
        self.assertEqual("gavin", normalize_logged_in_user("DOMAIN/gavin"))
        self.assertEqual("gavin", normalize_logged_in_user("gavin@example.local"))

    def test_logged_in_user_keeps_plain_username(self):
        self.assertEqual("salvatore", normalize_logged_in_user(" salvatore "))


if __name__ == "__main__":
    unittest.main()
