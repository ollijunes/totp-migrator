import base64
import csv
import io
import json
import unittest
import uuid

from tests.fixtures import SYNTHETIC_SECRET
from totp_migrator.exporters import (
    EXPORTERS,
    LIMITS,
    export_1password,
    export_aegis,
    export_bitwarden,
    export_json,
    export_lastpass,
    export_otpauth,
    lastpass_limit,
)
from totp_migrator.model import TotpAccount
from totp_migrator.otpauth import parse_otpauth_uri

ACCOUNTS = (
    TotpAccount("alice@example.test", "Example", SYNTHETIC_SECRET),
    TotpAccount("bob", "", SYNTHETIC_SECRET[:10], "SHA256", 8, 60),
)


class ExporterTests(unittest.TestCase):
    def test_every_format_except_aegis_is_deterministic(self) -> None:
        for name, exporter in EXPORTERS.items():
            if name != "aegis":
                with self.subTest(format=name):
                    self.assertEqual(exporter(ACCOUNTS), exporter(list(ACCOUNTS)))

    def test_aegis_uuids_are_fresh_and_injectable(self) -> None:
        first, second = (
            [entry["uuid"] for entry in json.loads(export_aegis(ACCOUNTS))["db"]["entries"]]
            for _ in range(2)
        )
        self.assertTrue(set(first).isdisjoint(second))
        fixed = uuid.UUID(int=1)
        entries = json.loads(export_aegis(ACCOUNTS, new_uuid=lambda: fixed))["db"]["entries"]
        self.assertEqual({entry["uuid"] for entry in entries}, {str(fixed)})

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
        self.assertEqual(document["db"]["version"], 3)
        self.assertEqual(document["db"]["groups"], [])
        entries = document["db"]["entries"]
        self.assertEqual(len(entries), 2)
        alice = entries[0]
        self.assertEqual(alice["type"], "totp")
        self.assertEqual(alice["groups"], [])
        self.assertIsNone(alice["icon_mime"])
        self.assertEqual((alice["issuer"], alice["name"]), ("Example", "alice@example.test"))
        self.assertEqual(
            alice["info"],
            {"secret": ACCOUNTS[0].secret_base32, "algo": "SHA1", "digits": 6, "period": 30},
        )
        uuids = {uuid.UUID(entry["uuid"]) for entry in entries}
        self.assertEqual(len(uuids), 2)

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

    def test_lastpass_generic_csv(self) -> None:
        tricky = TotpAccount('name, with "quotes"', "ACME, Inc.", SYNTHETIC_SECRET)
        rows = list(csv.DictReader(io.StringIO(export_lastpass([ACCOUNTS[0], tricky]))))
        self.assertEqual(
            list(rows[0]),
            ["url", "username", "password", "totp", "extra", "name", "grouping", "fav"],
        )
        alice, odd = rows
        self.assertEqual(alice["name"], "Example (alice@example.test)")
        self.assertEqual(alice["username"], "alice@example.test")
        self.assertEqual(alice["password"], "")
        self.assertEqual(
            base64.b32decode(alice["totp"] + "=" * (-len(alice["totp"]) % 8)), SYNTHETIC_SECRET
        )
        self.assertEqual((odd["username"], odd["name"]), (tricky.name, tricky.title))

    def test_lastpass_takes_only_default_parameters(self) -> None:
        self.assertIs(LIMITS["lastpass"], lastpass_limit)
        self.assertIsNone(lastpass_limit(ACCOUNTS[0]))
        for algorithm, digits, period in (("SHA256", 6, 30), ("SHA1", 8, 30), ("SHA1", 6, 60)):
            with self.subTest(algorithm=algorithm, digits=digits, period=period):
                account = TotpAccount("x", "", SYNTHETIC_SECRET, algorithm, digits, period)
                self.assertIn("only SHA1, 6-digit, 30-second", lastpass_limit(account))

    def test_unicode_survives(self) -> None:
        account = TotpAccount("käyttäjä", "Ääkköset Oy", SYNTHETIC_SECRET)
        for name, exporter in EXPORTERS.items():
            with self.subTest(format=name):
                output = exporter([account])
                if name != "otpauth":
                    self.assertIn("Ääkköset Oy", output)


if __name__ == "__main__":
    unittest.main()
