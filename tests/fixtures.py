"""Synthetic test data. No real account or secret appears in this repository.

The only fixed secrets are the published RFC 6238 Appendix B seeds.
"""

from __future__ import annotations

import base64
import hashlib
import urllib.parse

from totp_migrator.protobuf import encode_field

RFC_SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}

# A random-looking secret, so redaction tests are not fooled by the printable
# RFC seeds. Derived from a fixed phrase so anyone can see it is not a real key.
SYNTHETIC_SECRET = hashlib.sha1(b"totp-migrator synthetic secret").digest()


def ga_account(
    *,
    secret: bytes = SYNTHETIC_SECRET,
    name: bytes = b"alice@example.test",
    issuer: bytes = b"Example",
    algorithm: int = 1,
    digits: int = 1,
    otp_type: int = 2,
    extra: bytes = b"",
) -> bytes:
    """Encode one OtpParameters message. Pass 0 to omit an enum field."""
    parts = [encode_field(1, secret), encode_field(2, name)]
    if issuer:
        parts.append(encode_field(3, issuer))
    for number, value in ((4, algorithm), (5, digits), (6, otp_type)):
        if value:
            parts.append(encode_field(number, value))
    return b"".join(parts) + extra


def ga_payload(
    *accounts: bytes,
    version: int = 1,
    batch_size: int = 1,
    batch_index: int = 0,
    batch_id: int = 4242,
) -> bytes:
    """Encode a MigrationPayload. Zero values are omitted, as proto3 does."""
    parts = [encode_field(1, account) for account in accounts]
    for number, value in ((2, version), (3, batch_size), (4, batch_index), (5, batch_id)):
        if value:
            parts.append(encode_field(number, value))
    return b"".join(parts)


def ga_uri(payload: bytes) -> str:
    data = base64.b64encode(payload).decode("ascii")
    return "otpauth-migration://offline?data=" + urllib.parse.quote(data, safe="")


def secret_forms(secret: bytes) -> list[str]:
    """Encodings a leak could take. Tests assert none of them is printed."""
    b32 = base64.b32encode(secret).decode("ascii").rstrip("=")
    return [b32, b32.lower(), secret.hex(), base64.b64encode(secret).decode("ascii").rstrip("=")]
