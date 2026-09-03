import unittest
from unittest.mock import patch

from shrawler.smb import SMBAuth, connect_smb, create_smb_auth


class FakeClient:
    def __init__(self, host, remote, sess_port=445):
        self.host = host
        self.login_args = None
        self.kerberos_args = None
        self.logged_off = False

    def getDialect(self):
        return 0

    def login(self, *args):
        self.login_args = args

    def kerberosLogin(self, *args):
        self.kerberos_args = args

    def logoff(self):
        self.logged_off = True


class SMBTests(unittest.TestCase):
    def test_parse_hash_and_prompt(self):
        auth = create_smb_auth(
            "D/user@context",
            hashes=":abcd",
            no_pass=False,
            kerberos=False,
            aes_key=None,
        )
        self.assertEqual(auth.nthash, "abcd")
        with self.assertRaises(ValueError):
            create_smb_auth(
                "user@host",
                hashes="bad",
                no_pass=False,
                kerberos=False,
                aes_key=None,
            )
        with patch("shrawler.smb.getpass", return_value="secret") as prompt:
            auth = create_smb_auth(
                "user@host",
                hashes=None,
                no_pass=False,
                kerberos=False,
                aes_key=None,
            )
        prompt.assert_called_once()
        self.assertEqual(auth.password, "secret")
        self.assertEqual(auth.target_host, "host")
        self.assertEqual(auth.kdc_host, "host")

    def test_aes_key_implies_kerberos(self):
        auth = create_smb_auth(
            "D/user@dc",
            hashes=None,
            no_pass=True,
            kerberos=False,
            aes_key="aa",
        )
        self.assertTrue(auth.kerberos)
        self.assertEqual(auth.aes_key, "aa")

    def test_selected_host_and_kerberos_propagate(self):
        auth = SMBAuth("D", "u", "p", "", "", True, "aa", "target", "dc")
        client = connect_smb("selected", auth, client_factory=FakeClient)
        self.assertEqual(client.host, "selected")
        self.assertEqual(client.kerberos_args[5], "aa")
        self.assertEqual(client.kerberos_args[6], "dc")


if __name__ == "__main__":
    unittest.main()
