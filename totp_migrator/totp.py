"""HOTP (RFC 4226) and TOTP (RFC 6238) code generation.

Used to show current codes under ``--reveal`` so a migration can be
checked against the old authenticator before it is deleted.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from .model import TotpAccount

_HASHES = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def hotp(secret: bytes, counter: int, *, digits: int = 6, algorithm: str = "SHA1") -> str:
    if counter < 0:
        raise ValueError("counter must not be negative")
    digest = hmac.new(secret, struct.pack(">Q", counter), _HASHES[algorithm]).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 10**digits).zfill(digits)


def totp(
    secret: bytes,
    timestamp: int,
    *,
    digits: int = 6,
    algorithm: str = "SHA1",
    period: int = 30,
) -> str:
    return hotp(secret, timestamp // period, digits=digits, algorithm=algorithm)


def current_code(account: TotpAccount, timestamp: int) -> str:
    return totp(
        account.secret,
        timestamp,
        digits=account.digits,
        algorithm=account.algorithm,
        period=account.period,
    )
