import unittest

from tests.fixtures import RFC_SEEDS
from totp_migrator.model import TotpAccount
from totp_migrator.totp import current_code, hotp, totp

# RFC 6238 Appendix B: (unix time, algorithm) -> 8-digit code.
RFC6238_VECTORS = {
    (59, "SHA1"): "94287082",
    (59, "SHA256"): "46119246",
    (59, "SHA512"): "90693936",
    (1111111109, "SHA1"): "07081804",
    (1111111109, "SHA256"): "68084774",
    (1111111109, "SHA512"): "25091201",
    (1111111111, "SHA1"): "14050471",
    (1111111111, "SHA256"): "67062674",
    (1111111111, "SHA512"): "99943326",
    (1234567890, "SHA1"): "89005924",
    (1234567890, "SHA256"): "91819424",
    (1234567890, "SHA512"): "93441116",
    (2000000000, "SHA1"): "69279037",
    (2000000000, "SHA256"): "90698825",
    (2000000000, "SHA512"): "38618901",
    (20000000000, "SHA1"): "65353130",
    (20000000000, "SHA256"): "77737706",
    (20000000000, "SHA512"): "47863826",
}

# RFC 4226 Appendix D: counter -> 6-digit HOTP code for the SHA1 seed.
RFC4226_VECTORS = [
    "755224",
    "287082",
    "359152",
    "969429",
    "338314",
    "254676",
    "287922",
    "162583",
    "399871",
    "520489",
]


class TotpTests(unittest.TestCase):
    def test_rfc6238_appendix_b(self) -> None:
        for (timestamp, algorithm), expected in RFC6238_VECTORS.items():
            with self.subTest(timestamp=timestamp, algorithm=algorithm):
                code = totp(RFC_SEEDS[algorithm], timestamp, digits=8, algorithm=algorithm)
                self.assertEqual(code, expected)

    def test_rfc4226_appendix_d(self) -> None:
        for counter, expected in enumerate(RFC4226_VECTORS):
            with self.subTest(counter=counter):
                self.assertEqual(hotp(RFC_SEEDS["SHA1"], counter), expected)

    def test_current_code_uses_account_parameters(self) -> None:
        account = TotpAccount("rfc", "RFC6238", RFC_SEEDS["SHA512"], "SHA512", 8, 30)
        self.assertEqual(current_code(account, 59), "90693936")

    def test_period_changes_the_counter(self) -> None:
        # With a 60 s period, t=119 is counter 1, which is t=59 at 30 s.
        self.assertEqual(
            totp(RFC_SEEDS["SHA1"], 119, digits=8, period=60),
            RFC6238_VECTORS[(59, "SHA1")],
        )

    def test_leading_zeros_are_kept(self) -> None:
        self.assertEqual(totp(RFC_SEEDS["SHA1"], 1111111109, digits=8), "07081804")


if __name__ == "__main__":
    unittest.main()
