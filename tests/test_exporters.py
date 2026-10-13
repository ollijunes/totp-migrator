import json
import unittest
import uuid

from tests.fixtures import SYNTHETIC_SECRET
from totp_migrator.exporters import (
    EXPORTERS,
    export_1password,
    export_aegis,
    export_bitwarden,
    export_json,
    export_otpauth,
)
from totp_migrator.model import TotpAccount
from totp_migrator.otpauth import parse_otpauth_uri

ACCOUNTS = (
    TotpAccount("alice@example.test", "Example", SYNTHETIC_SECRET),
    TotpAccount("bob", "", SYNTHETIC_SECRET[:10], "SHA256", 8, 60),
)


class ExporterTests(unittest.TestCase):
    def test_every_format_is_pure_and_deterministic(self) -> None:
        for name, exporter in EXPORTERS.items():
            with self.subTest(format=name):
                self.assertEqual(exporter(ACCOUNTS), exporter(list(ACCOUNTS)))

    def test_every_format_handles_no_accounts(self) -> None:
        for name, exporter in EXPORTERS.items():
            with self.subTest(format=name):
                self.assertIsInstance(exporter(()), str)

    def test_otpauth_list_round_trips(self) -> None:
        lines = export_otpauth(ACCOUNTS).splitlines()
        self.assertEqual(tuple(parse_otpauth_uri(line) for line in lines), ACCOUNTS)

    def test_json(self) -> None:
        document = json.loads(export_json(ACCOUNTS))
        self.assertEqual((document["format"], document["version"]), ("totp-migrator", 1))
        bob = document["accounts"][1]
        self.assertEqual(bob["secret"], ACCOUNTS[1].secret_base32)
        self.assertEqual((bob["algorithm"], bob["digits"], bob["period"]), ("SHA256", 8, 60))
        self.assertEqual(parse_otpauth_uri(bob["uri"]), ACCOUNTS[1])

    def test_aegis_plain_vault(self) -> None:
        document = json.loads(export_aegis(ACCOUNTS))
        self.assertEqual(document["version"], 1)
        self.assertEqual(document["header"], {"slots": None, "params": None})
        self.assertEqual(document["db"]["version"], 2)
        entries = document["db"]["entries"]
        self.assertEqual(len(entries), 2)
        alice = entries[0]
        self.assertEqual(alice["type"], "totp")
        self.assertEqual((alice["issuer"], alice["name"]), ("Example", "alice@example.test"))
        self.assertEqual(
            alice["info"],
            {"secret": ACCOUNTS[0].secret_base32, "algo": "SHA1", "digits": 6, "period": 30},
        )
        uuids = {uuid.UUID(entry["uuid"]) for entry in entries}
        self.assertEqual(len(uuids), 2)

    def test_aegis_uuids_differ_for_same_label(self) -> None:
        twins = (ACCOUNTS[0], TotpAccount("alice@example.test", "Example", b"other-secret"))
        entries = json.loads(export_aegis(twins))["db"]["entries"]
        self.assertNotEqual(entries[0]["uuid"], entries[1]["uuid"])

    def test_bitwarden_unencrypted_json(self) -> None:
        document = json.loads(export_bitwarden(ACCOUNTS))
        self.assertIs(document["encrypted"], False)
        self.assertEqual(document["folders"], [])
        alice, bob = document["items"]
        self.assertEqual(alice["type"], 1)
        self.assertEqual(alice["name"], "Example (alice@example.test)")
        self.assertEqual(alice["login"]["username"], "alice@example.test")
        self.assertIsNone(alice["login"]["password"])
        self.assertEqual(parse_otpauth_uri(alice["login"]["totp"]), ACCOUNTS[0])
        self.assertEqual(bob["name"], "bob")
        self.assertEqual(parse_otpauth_uri(bob["login"]["totp"]), ACCOUNTS[1])

    def test_1password_templates_one_per_line(self) -> None:
        lines = export_1password(ACCOUNTS).splitlines()
        self.assertEqual(len(lines), 2)
        item = json.loads(lines[0])
        self.assertEqual(
            (item["title"], item["category"]), ("Example (alice@example.test)", "LOGIN")
        )
        fields = {field["type"]: field for field in item["fields"]}
        self.assertEqual(fields["STRING"]["purpose"], "USERNAME")
        self.assertEqual(fields["STRING"]["value"], "alice@example.test")
        self.assertEqual(parse_otpauth_uri(fields["OTP"]["value"]), ACCOUNTS[0])

    def test_unicode_survives(self) -> None:
        account = TotpAccount("käyttäjä", "Ääkköset Oy", SYNTHETIC_SECRET)
        for name, exporter in EXPORTERS.items():
            with self.subTest(format=name):
                output = exporter([account])
                if name != "otpauth":
                    self.assertIn("Ääkköset Oy", output)


if __name__ == "__main__":
    unittest.main()
