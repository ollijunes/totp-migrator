import unittest

from tests.fixtures import RFC_SEEDS, SYNTHETIC_SECRET
from totp_migrator.errors import MigratorError, UnsupportedAccount
from totp_migrator.model import TotpAccount
from totp_migrator.otpauth import build_otpauth_uri, parse_otpauth_uri

RFC_SHA1_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class ParseTests(unittest.TestCase):
    def test_key_uri_format_example(self) -> None:
        account = parse_otpauth_uri(
            f"otpauth://totp/Example:alice@google.com?secret={RFC_SHA1_BASE32}&issuer=Example"
        )
        self.assertEqual((account.issuer, account.name), ("Example", "alice@google.com"))
        self.assertEqual(account.secret, RFC_SEEDS["SHA1"])
        self.assertEqual((account.algorithm, account.digits, account.period), ("SHA1", 6, 30))

    def test_explicit_parameters(self) -> None:
        account = parse_otpauth_uri(
            "otpauth://totp/ACME%20Co:john.doe%40email.com?"
            f"secret={RFC_SHA1_BASE32}&issuer=ACME%20Co&algorithm=sha256&digits=8&period=60"
        )
        self.assertEqual((account.issuer, account.name), ("ACME Co", "john.doe@email.com"))
        self.assertEqual((account.algorithm, account.digits, account.period), ("SHA256", 8, 60))

    def test_lenient_secret_spelling(self) -> None:
        sloppy = "gezd gnbv-gy3t qojq gezd gnbv gy3t qojq===="
        account = parse_otpauth_uri(f"otpauth://totp/x?secret={sloppy.replace(' ', '%20')}")
        self.assertEqual(account.secret, RFC_SEEDS["SHA1"])

    def test_issuer_only_in_label(self) -> None:
        account = parse_otpauth_uri(f"otpauth://totp/Legacy:bob?secret={RFC_SHA1_BASE32}")
        self.assertEqual((account.issuer, account.name), ("Legacy", "bob"))

    def test_scheme_and_type_are_case_insensitive(self) -> None:
        account = parse_otpauth_uri(f"OTPAUTH://TOTP/x?secret={RFC_SHA1_BASE32}")
        self.assertEqual(account.name, "x")

    def test_unsupported_accounts(self) -> None:
        cases = [
            f"otpauth://hotp/x?secret={RFC_SHA1_BASE32}&counter=1",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&algorithm=MD5",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&digits=10",
        ]
        for uri in cases:
            with self.subTest(uri=uri.split("?")[0]), self.assertRaises(UnsupportedAccount):
                parse_otpauth_uri(uri)

    def test_display_spoofing_characters_are_rejected(self) -> None:
        for label in ("a%1B%5B31mX", "a%C2%9BX", "safe%E2%80%AEgpj", "a%E2%80%A8b", "a%E2%80%8Bb"):
            with self.subTest(label=label), self.assertRaises(MigratorError) as caught:
                parse_otpauth_uri(f"otpauth://totp/{label}?secret={RFC_SHA1_BASE32}")
            self.assertIn("control or invisible characters", str(caught.exception))

    def test_malformed(self) -> None:
        cases = {
            "otpauth://totp/x": "no secret",
            "otpauth://totp/x?secret=1189": "not valid base32",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&secret=AAAA": "repeats",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&period=-30": "positive integer",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&period=0": "period",
            f"otpauth://totp/?secret={RFC_SHA1_BASE32}": "name is empty",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&issuer=A%3AB": "issuer must not",
        }
        for uri, message in cases.items():
            with self.subTest(message=message):
                with self.assertRaises(MigratorError) as caught:
                    parse_otpauth_uri(uri)
                self.assertIn(message, str(caught.exception))


class BuildTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        accounts = [
            TotpAccount("alice@example.test", "Example", SYNTHETIC_SECRET),
            TotpAccount("bob", "", SYNTHETIC_SECRET, "SHA512", 8, 60),
            TotpAccount("user name/with?odd&chars", "ACME Co.", SYNTHETIC_SECRET, "SHA256", 7, 15),
            TotpAccount("Ünïcødé", "Ääkköset Oy", SYNTHETIC_SECRET),
            TotpAccount("ns:inner", "Outer", SYNTHETIC_SECRET),
        ]
        for account in accounts:
            with self.subTest(label=account.label):
                self.assertEqual(parse_otpauth_uri(build_otpauth_uri(account)), account)

    def test_every_parameter_is_explicit(self) -> None:
        uri = build_otpauth_uri(TotpAccount("alice", "Example", RFC_SEEDS["SHA1"]))
        self.assertEqual(
            uri,
            "otpauth://totp/Example:alice"
            f"?secret={RFC_SHA1_BASE32}&issuer=Example&algorithm=SHA1&digits=6&period=30",
        )


if __name__ == "__main__":
    unittest.main()
