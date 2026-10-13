import base64
import unittest
import urllib.parse

from tests.fixtures import SYNTHETIC_SECRET, ga_account, ga_payload, ga_uri
from totp_migrator.errors import MigratorError
from totp_migrator.google import (
    MigrationBatch,
    check_batches_complete,
    parse_migration_payload,
    parse_migration_uri,
)
from totp_migrator.model import SkippedAccount, TotpAccount
from totp_migrator.protobuf import encode_field


def only_account(batch: MigrationBatch) -> TotpAccount:
    (entry,) = batch.entries
    assert isinstance(entry, TotpAccount)
    return entry


class PayloadTests(unittest.TestCase):
    def test_canonical_fixture(self) -> None:
        # Hand-assembled bytes, independent of the test encoder:
        # account {secret=0x42 * 10, name="a", algorithm=SHA1, digits=6, type=TOTP},
        # version=1, batch_size=1, batch_index=0, batch_id=7.
        payload = bytes.fromhex("0a150a0a" + "42" * 10 + "1201612001280130021001180120002807")
        batch = parse_migration_payload(payload)
        account = only_account(batch)
        self.assertEqual((account.secret, account.name, account.issuer), (b"\x42" * 10, "a", ""))
        self.assertEqual((account.algorithm, account.digits, account.period), ("SHA1", 6, 30))
        self.assertEqual((batch.version, batch.batch_size, batch.batch_index), (1, 1, 0))
        self.assertEqual(batch.batch_id, 7)

    def test_all_algorithms_and_digit_counts(self) -> None:
        cases = [(1, 1, "SHA1", 6), (2, 2, "SHA256", 8), (3, 1, "SHA512", 6)]
        for code, digit_code, algorithm, digits in cases:
            with self.subTest(algorithm=algorithm):
                payload = ga_payload(ga_account(algorithm=code, digits=digit_code))
                account = only_account(parse_migration_payload(payload))
                self.assertEqual((account.algorithm, account.digits), (algorithm, digits))

    def test_issuer_prefix_is_removed_from_name(self) -> None:
        payload = ga_payload(ga_account(name=b"Example:alice@example.test"))
        account = only_account(parse_migration_payload(payload))
        self.assertEqual((account.issuer, account.name), ("Example", "alice@example.test"))

    def test_issuer_is_taken_from_name_when_missing(self) -> None:
        payload = ga_payload(ga_account(name=b"Legacy:bob", issuer=b""))
        account = only_account(parse_migration_payload(payload))
        self.assertEqual((account.issuer, account.name), ("Legacy", "bob"))

    def test_issuer_prefix_matches_ignoring_case(self) -> None:
        payload = ga_payload(ga_account(name=b"EXAMPLE:alice", issuer=b"Example"))
        account = only_account(parse_migration_payload(payload))
        self.assertEqual((account.issuer, account.name), ("Example", "alice"))

    def test_conflicting_prefix_keeps_the_whole_name(self) -> None:
        payload = ga_payload(ga_account(name=b"Other:bob"))
        account = only_account(parse_migration_payload(payload))
        self.assertEqual((account.issuer, account.name), ("Example", "Other:bob"))

    def test_fields_in_any_order_and_multibyte_varints(self) -> None:
        account = (
            encode_field(6, 2)
            + encode_field(3, b"XYZ")
            + encode_field(5, 1)
            + encode_field(1, SYNTHETIC_SECRET)
            + encode_field(4, 1)
            + encode_field(2, b"b")
        )
        batch = parse_migration_payload(ga_payload(account, batch_id=300))
        self.assertEqual(only_account(batch).label, "XYZ:b")
        self.assertEqual(batch.batch_id, 300)

    def test_negative_batch_id_is_int32(self) -> None:
        batch = parse_migration_payload(ga_payload(ga_account(), batch_id=-5))
        self.assertEqual(batch.batch_id, -5)

    def test_hotp_counter_of_any_int64_value_is_accepted(self) -> None:
        payload = ga_payload(ga_account(otp_type=1, extra=encode_field(7, -1)))
        (entry,) = parse_migration_payload(payload).entries
        self.assertIsInstance(entry, SkippedAccount)

    def test_version_two_is_accepted(self) -> None:
        self.assertEqual(parse_migration_payload(ga_payload(ga_account(), version=2)).version, 2)


class SkippedAccountTests(unittest.TestCase):
    def test_unsupported_values_are_skipped_not_guessed(self) -> None:
        cases = {
            "hotp": ga_account(otp_type=1),
            "missing type": ga_account(otp_type=0),
            "md5": ga_account(algorithm=4),
            "missing algorithm": ga_account(algorithm=0),
            "missing digits": ga_account(digits=0),
            "unknown digits": ga_account(digits=3),
        }
        for case, account in cases.items():
            with self.subTest(case=case):
                batch = parse_migration_payload(ga_payload(account, ga_account(name=b"ok")))
                skipped, kept = batch.entries
                self.assertIsInstance(skipped, SkippedAccount)
                self.assertEqual(skipped.label, "Example:alice@example.test")
                self.assertIsInstance(kept, TotpAccount)

    def test_missing_name_is_skipped_under_the_issuer(self) -> None:
        (skipped,) = parse_migration_payload(ga_payload(ga_account(name=b""))).entries
        self.assertIsInstance(skipped, SkippedAccount)
        self.assertEqual((skipped.label, skipped.reason), ("Example", "account has no name"))

    def test_skipped_labels_are_validated_too(self) -> None:
        payload = ga_payload(ga_account(name=b"evil\x1b[2Jname", otp_type=1))
        with self.assertRaises(MigratorError) as caught:
            parse_migration_payload(payload)
        self.assertIn("account 1: account name contains control", str(caught.exception))


class MalformedPayloadTests(unittest.TestCase):
    def assert_rejected(self, payload: bytes, message: str) -> None:
        with self.assertRaises(MigratorError) as caught:
            parse_migration_payload(payload)
        self.assertIn(message, str(caught.exception))

    def test_truncated(self) -> None:
        payload = ga_payload(ga_account())
        for cut in (1, 5, len(payload) - 1):
            with self.subTest(cut=cut), self.assertRaises(MigratorError):
                parse_migration_payload(payload[:cut])

    def test_unknown_account_field(self) -> None:
        self.assert_rejected(
            ga_payload(ga_account(extra=encode_field(15, 1))), "account 1: unknown field 15"
        )

    def test_unknown_payload_field(self) -> None:
        self.assert_rejected(ga_payload(ga_account()) + encode_field(9, 1), "unknown field 9")

    def test_repeated_account_field(self) -> None:
        self.assert_rejected(
            ga_payload(ga_account(extra=encode_field(2, b"again"))), "repeated field 2"
        )

    def test_wrong_wire_type(self) -> None:
        self.assert_rejected(ga_payload(ga_account(extra=encode_field(7, b"x"))), "wrong wire type")

    def test_fixed64_where_an_account_belongs(self) -> None:
        self.assert_rejected(bytes([0x09]) + bytes(8), "wrong wire type")

    def test_short_or_empty_secret(self) -> None:
        for secret in (b"", b"\x01" * 7):
            with self.subTest(length=len(secret)):
                self.assert_rejected(
                    ga_payload(ga_account(secret=secret)),
                    "account 1: secret must be 8-256 bytes long",
                )

    def test_invalid_utf8_name(self) -> None:
        self.assert_rejected(ga_payload(ga_account(name=b"\xff\xfe")), "UTF-8")

    def test_unsupported_version(self) -> None:
        self.assert_rejected(ga_payload(ga_account(), version=3), "version 3")

    def test_batch_index_outside_batch(self) -> None:
        self.assert_rejected(
            ga_payload(ga_account(), batch_size=2, batch_index=2), "batch position"
        )

    def test_varint_longer_than_ten_bytes(self) -> None:
        self.assert_rejected(bytes([0x10]) + b"\xff" * 11, "varint is too long")

    def test_varint_larger_than_64_bits(self) -> None:
        # Ten bytes whose last one carries more than bit 63: 2**64 + 1.
        overflowing = b"\x81" + b"\x80" * 8 + b"\x02"
        self.assert_rejected(bytes([0x10]) + overflowing, "larger than 64 bits")


class UriTests(unittest.TestCase):
    def test_standard_percent_encoded(self) -> None:
        batch = parse_migration_uri(ga_uri(ga_payload(ga_account())))
        self.assertEqual(only_account(batch).secret, SYNTHETIC_SECRET)

    def test_raw_plus_and_slash_are_not_spaces(self) -> None:
        secret = bytes([0xFB, 0xEF, 0xFF] * 7)
        data = base64.b64encode(ga_payload(ga_account(secret=secret))).decode("ascii")
        self.assertTrue("+" in data or "/" in data)
        batch = parse_migration_uri("otpauth-migration://offline?data=" + data)
        self.assertEqual(only_account(batch).secret, secret)

    def test_urlsafe_alphabet_without_padding(self) -> None:
        secret = bytes([0xFB, 0xEF, 0xFF] * 7)
        payload = ga_payload(ga_account(secret=secret))
        data = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        batch = parse_migration_uri("otpauth-migration://offline?data=" + data)
        self.assertEqual(only_account(batch).secret, secret)

    def test_rejections(self) -> None:
        data = urllib.parse.quote(base64.b64encode(ga_payload(ga_account())).decode())
        cases = {
            "otpauth://offline?data=" + data: "not an otpauth-migration",
            "otpauth-migration://online?data=" + data: "host must be",
            "otpauth-migration://offline?foo=1": "exactly one data",
            f"otpauth-migration://offline?data={data}&data={data}": "exactly one data",
            "otpauth-migration://offline?data=a+b-c": "mixes base64",
            "otpauth-migration://offline?data=!!!!": "not valid base64",
            "otpauth-migration://offline?data=%ZZ": "invalid percent escape",
        }
        for uri, message in cases.items():
            with self.subTest(message=message), self.assertRaises(MigratorError) as caught:
                parse_migration_uri(uri)
            self.assertIn(message, str(caught.exception))


class BatchTests(unittest.TestCase):
    def batch(self, index: int, size: int = 3, batch_id: int = 9) -> MigrationBatch:
        payload = ga_payload(
            ga_account(name=f"user{index}".encode()),
            batch_size=size,
            batch_index=index,
            batch_id=batch_id,
        )
        return parse_migration_payload(payload)

    def test_complete_export_in_any_order(self) -> None:
        check_batches_complete([self.batch(2), self.batch(0), self.batch(1)])

    def test_missing_qr_code(self) -> None:
        with self.assertRaises(MigratorError) as caught:
            check_batches_complete([self.batch(0), self.batch(2)])
        self.assertIn("expected QR codes 1-3 exactly once, got 1, 3", str(caught.exception))

    def test_repeated_qr_code(self) -> None:
        with self.assertRaises(MigratorError):
            check_batches_complete([self.batch(0), self.batch(0), self.batch(1), self.batch(2)])

    def test_size_disagreement(self) -> None:
        with self.assertRaises(MigratorError):
            check_batches_complete([self.batch(0, size=2), self.batch(1, size=3)])

    def test_huge_declared_size_fails_without_allocating(self) -> None:
        with self.assertRaises(MigratorError):
            check_batches_complete([self.batch(0, size=2**31 - 1)])

    def test_separate_exports_are_checked_separately(self) -> None:
        check_batches_complete(
            [self.batch(0, size=1, batch_id=1), self.batch(0, size=1, batch_id=2)]
        )

    def test_single_qr_exports_without_an_id_do_not_collide(self) -> None:
        check_batches_complete([self.batch(0, size=1, batch_id=0)] * 2)


if __name__ == "__main__":
    unittest.main()
