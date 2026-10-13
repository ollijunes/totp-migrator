import unittest

from tests.fixtures import RFC_SEEDS, SYNTHETIC_SECRET
from totp_migrator.errors import MigratorError
from totp_migrator.model import SkippedAccount, TotpAccount
from totp_migrator.otpauth import build_otpauth_uri, parse_otpauth_uri

RFC_SHA1_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def parse(uri: str) -> TotpAccount:
    account = parse_otpauth_uri(uri)
    assert isinstance(account, TotpAccount)
    return account


class ParseTests(unittest.TestCase):
    def test_key_uri_format_example(self) -> None:
        account = parse(
            f"otpauth://totp/Example:alice@google.com?secret={RFC_SHA1_BASE32}&issuer=Example"
        )
        self.assertEqual((account.issuer, account.name), ("Example", "alice@google.com"))
        self.assertEqual(account.secret, RFC_SEEDS["SHA1"])
        self.assertEqual((account.algorithm, account.digits, account.period), ("SHA1", 6, 30))

    def test_explicit_parameters(self) -> None:
        account = parse(
            "otpauth://totp/ACME%20Co:john.doe%40email.com?"
            f"secret={RFC_SHA1_BASE32}&issuer=ACME%20Co&algorithm=sha256&digits=8&period=60"
        )
        self.assertEqual((account.issuer, account.name), ("ACME Co", "john.doe@email.com"))
        self.assertEqual((account.algorithm, account.digits, account.period), ("SHA256", 8, 60))

    def test_plus_in_query_is_a_space(self) -> None:
        account = parse(f"otpauth://totp/ACME%20Co:x?secret={RFC_SHA1_BASE32}&issuer=ACME+Co")
        self.assertEqual(account.issuer, "ACME Co")

    def test_lenient_secret_spelling(self) -> None:
        sloppy = "gezd%20gnbv-gy3t%20qojq%20gezd%20gnbv%20gy3t%20qojq===="
        self.assertEqual(parse(f"otpauth://totp/x?secret={sloppy}").secret, RFC_SEEDS["SHA1"])

    def test_issuer_only_in_label(self) -> None:
        account = parse(f"otpauth://totp/Legacy:bob?secret={RFC_SHA1_BASE32}")
        self.assertEqual((account.issuer, account.name), ("Legacy", "bob"))

    def test_scheme_and_type_are_case_insensitive(self) -> None:
        self.assertEqual(parse(f"OTPAUTH://TOTP/x?secret={RFC_SHA1_BASE32}").name, "x")

    def test_unsupported_accounts_are_skipped_with_their_label(self) -> None:
        cases = [
            f"otpauth://hotp/Example:x?secret={RFC_SHA1_BASE32}&counter=1",
            f"otpauth://totp/Example:x?secret={RFC_SHA1_BASE32}&algorithm=MD5",
            f"otpauth://totp/Example:x?secret={RFC_SHA1_BASE32}&digits=10",
            f"otpauth://totp/Example:x?secret={RFC_SHA1_BASE32}&period=3601",
            f"otpauth://totp/Example:x?secret={RFC_SHA1_BASE32}&period=0",
            "otpauth://totp/Example:x?secret=AAAAAAAA",
        ]
        for uri in cases:
            with self.subTest(uri=uri.split("?")[1]):
                skipped = parse_otpauth_uri(uri)
                self.assertIsInstance(skipped, SkippedAccount)
                self.assertEqual(skipped.label, "Example:x")

    def test_display_spoofing_characters_are_rejected(self) -> None:
        labels = ("a%1B%5B31mX", "a%C2%9BX", "safe%E2%80%AEgpj", "a%E2%80%A8b", "a%E2%80%8Bb")
        for label in labels:
            for kind in ("totp", "hotp"):
                with (
                    self.subTest(label=label, kind=kind),
                    self.assertRaises(MigratorError) as caught,
                ):
                    parse_otpauth_uri(f"otpauth://{kind}/{label}?secret={RFC_SHA1_BASE32}")
                self.assertIn("control or invisible characters", str(caught.exception))

    def test_malformed(self) -> None:
        cases = {
            "otpauth://totp/x": "no secret",
            "otpauth://totp/x?secret=1189": "not valid base32",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&secret=AAAA": "repeats a query",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&period=-30": "positive integer",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&period=" + "9" * 20: "positive integer",
            f"otpauth://totp/?secret={RFC_SHA1_BASE32}": "name is empty",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&issuer=A%3AB": "issuer must not",
            f"otpauth://totp/x%FF?secret={RFC_SHA1_BASE32}": "not valid UTF-8",
            f"otpauth://totp/x%ZZ?secret={RFC_SHA1_BASE32}": "invalid percent escape",
            f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&issuer=%E2": "not valid UTF-8",
            f"otpauth://[totp/x?secret={RFC_SHA1_BASE32}": "malformed",
        }
        for uri, message in cases.items():
            with self.subTest(message=message), self.assertRaises(MigratorError) as caught:
                parse_otpauth_uri(uri)
            self.assertIn(message, str(caught.exception))

    def test_errors_never_echo_parameter_names(self) -> None:
        uri = f"otpauth://totp/x?secret={RFC_SHA1_BASE32}&{RFC_SHA1_BASE32}=1&{RFC_SHA1_BASE32}=2"
        with self.assertRaises(MigratorError) as caught:
            parse_otpauth_uri(uri)
        self.assertNotIn(RFC_SHA1_BASE32.lower(), str(caught.exception).lower())


class BuildTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        accounts = [
            TotpAccount("alice@example.test", "Example", SYNTHETIC_SECRET),
            TotpAccount("bob", "", SYNTHETIC_SECRET, "SHA512", 8, 60),
            TotpAccount("user name/with?odd&chars+", "ACME Co.", SYNTHETIC_SECRET, "SHA256", 7, 15),
            TotpAccount("Ünïcødé", "Ääkköset Oy", SYNTHETIC_SECRET),
            TotpAccount("ns:inner", "Outer", SYNTHETIC_SECRET),
        ]
        for account in accounts:
            with self.subTest(label=account.label):
                self.assertEqual(parse(build_otpauth_uri(account)), account)

    def test_every_parameter_is_explicit(self) -> None:
        uri = build_otpauth_uri(TotpAccount("alice", "Example", RFC_SEEDS["SHA1"]))
        self.assertEqual(
            uri,
            "otpauth://totp/Example:alice"
            f"?secret={RFC_SHA1_BASE32}&issuer=Example&algorithm=SHA1&digits=6&period=30",
        )


if __name__ == "__main__":
    unittest.main()
