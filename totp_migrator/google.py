"""Google Authenticator ``otpauth-migration://`` payloads.

There is no official schema. Field numbers were checked against two
independent reverse-engineered descriptions, which agree: Aegis
``google_auth.proto`` and qistoph ``OtpMigration.proto``.

    MigrationPayload: 1 otp_parameters (repeated), 2 version,
                      3 batch_size, 4 batch_index, 5 batch_id
    OtpParameters:    1 secret, 2 name, 3 issuer, 4 algorithm,
                      5 digits, 6 type, 7 counter
    Algorithm:        1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
    DigitCount:       1 six, 2 eight
    OtpType:          1 HOTP, 2 TOTP

The payload carries no period, so every account gets the 30-second default
that Google Authenticator itself uses. The parser is strict: anything it
does not recognise stops the run instead of being guessed at.
"""

from __future__ import annotations

import base64
import binascii
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass

from . import protobuf
from .errors import MigratorError, UnsupportedAccount
from .model import TotpAccount, split_label

SCHEME = "otpauth-migration"
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_ACCOUNTS_PER_PAYLOAD = 100
SUPPORTED_VERSIONS = (1, 2)

_ALGORITHMS = {1: "SHA1", 2: "SHA256", 3: "SHA512"}
_DIGITS = {1: 6, 2: 8}
_TOTP = 2
_ACCOUNT_FIELDS = range(1, 8)
_BYTES_FIELDS = (1, 2, 3)
_PAYLOAD_SCALARS = range(2, 6)


@dataclass(frozen=True)
class MigrationBatch:
    """One QR code's worth of a Google Authenticator export."""

    accounts: tuple[TotpAccount, ...]
    skipped: tuple[UnsupportedAccount, ...]
    version: int
    batch_size: int
    batch_index: int
    batch_id: int


def is_migration_uri(text: str) -> bool:
    return text.lower().startswith(SCHEME + ":")


def parse_migration_uri(uri: str) -> MigrationBatch:
    """Decode an ``otpauth-migration://offline?data=...`` URI."""
    if len(uri) > MAX_PAYLOAD_BYTES * 2:
        raise MigratorError("migration URI is too large")
    scheme, separator, rest = uri.partition("://")
    if scheme.lower() != SCHEME or not separator:
        raise MigratorError("not an otpauth-migration:// URI")
    host, _, query = rest.partition("?")
    if host.lower() != "offline":
        raise MigratorError("migration URI host must be 'offline'")
    values = [part[5:] for part in query.split("&") if part.startswith("data=")]
    if len(values) != 1 or not values[0]:
        raise MigratorError("migration URI must have exactly one data parameter")
    # unquote, not unquote_plus: '+' is a base64 character, not a space.
    return parse_migration_payload(_decode_base64(urllib.parse.unquote(values[0])))


def parse_migration_payload(payload: bytes) -> MigrationBatch:
    """Decode the protobuf bytes from the URI's ``data`` parameter."""
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise MigratorError("migration payload is too large")
    raw_accounts: list[bytes] = []
    scalars: dict[int, int] = {}
    for field in protobuf.parse_fields(payload):
        if field.number == 1 and field.wire_type == protobuf.LENGTH_DELIMITED:
            assert isinstance(field.value, bytes)
            raw_accounts.append(field.value)
        elif field.number in _PAYLOAD_SCALARS and field.wire_type == protobuf.VARINT:
            assert isinstance(field.value, int)
            if field.number in scalars:
                raise MigratorError(f"migration payload repeats field {field.number}")
            scalars[field.number] = protobuf.as_int32(field.value)
        elif field.number == 1 or field.number in _PAYLOAD_SCALARS:
            raise MigratorError(f"migration payload field {field.number} has the wrong wire type")
        else:
            raise MigratorError(f"migration payload has unknown field {field.number}")
    if len(raw_accounts) > MAX_ACCOUNTS_PER_PAYLOAD:
        raise MigratorError("migration payload has too many accounts")

    # proto3 omits zero values on the wire, so a missing field means 0.
    version = scalars.get(2, 0)
    batch_size = scalars.get(3, 0)
    batch_index = scalars.get(4, 0)
    if version not in SUPPORTED_VERSIONS:
        raise MigratorError(f"migration payload version {version} is not supported")
    if batch_size < 1 or not 0 <= batch_index < batch_size:
        raise MigratorError("migration payload has an invalid batch position")

    accounts: list[TotpAccount] = []
    skipped: list[UnsupportedAccount] = []
    for raw in raw_accounts:
        try:
            accounts.append(_parse_account(raw))
        except UnsupportedAccount as unsupported:
            skipped.append(unsupported)
    return MigrationBatch(
        accounts=tuple(accounts),
        skipped=tuple(skipped),
        version=version,
        batch_size=batch_size,
        batch_index=batch_index,
        batch_id=scalars.get(5, 0),
    )


def check_batches_complete(batches: list[MigrationBatch]) -> None:
    """Fail unless every multi-QR export is present exactly once.

    Google Authenticator splits large exports across several QR codes that
    share a batch id. Importing only some of them would silently lose
    accounts, so a gap or a repeat is an error.
    """
    groups: dict[int, list[MigrationBatch]] = defaultdict(list)
    for batch in batches:
        groups[batch.batch_id].append(batch)
    for batch_id, group in groups.items():
        sizes = {batch.batch_size for batch in group}
        if len(sizes) != 1:
            raise MigratorError(f"export {batch_id}: QR codes disagree on the batch size")
        size = sizes.pop()
        indexes = sorted(batch.batch_index for batch in group)
        if indexes != list(range(size)):
            have = ", ".join(str(index + 1) for index in indexes)
            raise MigratorError(
                f"export {batch_id}: expected QR codes 1-{size} exactly once, got {have}"
            )


def _parse_account(raw: bytes) -> TotpAccount:
    blobs: dict[int, bytes] = {}
    ints: dict[int, int] = {}
    for field in protobuf.parse_fields(raw):
        if field.number not in _ACCOUNT_FIELDS:
            raise MigratorError(f"account has unknown field {field.number}")
        if field.number in blobs or field.number in ints:
            raise MigratorError(f"account repeats field {field.number}")
        if field.number in _BYTES_FIELDS and field.wire_type == protobuf.LENGTH_DELIMITED:
            assert isinstance(field.value, bytes)
            blobs[field.number] = field.value
        elif field.number not in _BYTES_FIELDS and field.wire_type == protobuf.VARINT:
            assert isinstance(field.value, int)
            ints[field.number] = protobuf.as_int32(field.value)
        else:
            raise MigratorError(f"account field {field.number} has the wrong wire type")

    issuer, name = split_label(_text(blobs.get(2, b"")), _text(blobs.get(3, b"")))
    label = f"{issuer}:{name}" if issuer else name
    algorithm = _ALGORITHMS.get(ints.get(4, 0))
    digits = _DIGITS.get(ints.get(5, 0))
    if ints.get(6, 0) != _TOTP:
        raise UnsupportedAccount(
            label, "only TOTP accounts are supported (this is HOTP or unknown)"
        )
    if algorithm is None:
        raise UnsupportedAccount(label, "unsupported or missing hash algorithm")
    if digits is None:
        raise UnsupportedAccount(label, "unsupported or missing digit count")
    return TotpAccount(
        name=name,
        issuer=issuer,
        secret=blobs.get(1, b""),
        algorithm=algorithm,
        digits=digits,
    )


def _decode_base64(text: str) -> bytes:
    text = text.strip()
    if any(char in text for char in "-_"):
        if any(char in text for char in "+/"):
            raise MigratorError("migration data mixes base64 alphabets")
        text = text.replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except binascii.Error:
        raise MigratorError("migration data is not valid base64") from None


def _text(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        raise MigratorError("account name or issuer is not valid UTF-8") from None
