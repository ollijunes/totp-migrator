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
from collections import defaultdict
from dataclasses import dataclass

from . import protobuf
from .errors import MigratorError
from .model import SkippedAccount, TotpAccount, make_account, split_label
from .urltext import strict_unquote

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
    """One QR code's worth of a Google Authenticator export.

    ``entries`` keeps payload order; each is an account or a skipped one.
    """

    entries: tuple[TotpAccount | SkippedAccount, ...]
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
    # '+' is a base64 character here, not an encoded space.
    data = strict_unquote(values[0], plus_is_space=False)
    return parse_migration_payload(_decode_base64(data))


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

    entries = []
    for number, raw in enumerate(raw_accounts, start=1):
        try:
            entries.append(_parse_account(raw))
        except MigratorError as error:
            raise MigratorError(f"account {number}: {error}") from None
    return MigrationBatch(
        entries=tuple(entries),
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
        # A single-QR export is complete on its own. Grouping it would make two
        # unrelated exports that both omitted the id (0) look like a repeat.
        if batch.batch_size > 1:
            groups[batch.batch_id].append(batch)
    for batch_id, group in groups.items():
        sizes = {batch.batch_size for batch in group}
        if len(sizes) != 1:
            raise MigratorError(f"export {batch_id}: QR codes disagree on the batch size")
        size = sizes.pop()
        indexes = sorted(batch.batch_index for batch in group)
        # Compare counts first: the declared size is untrusted and may be huge.
        if len(indexes) != size or indexes != list(range(len(indexes))):
            have = ", ".join(str(index + 1) for index in indexes)
            raise MigratorError(
                f"export {batch_id}: expected QR codes 1-{size} exactly once, got {have}"
            )


def _parse_account(raw: bytes) -> TotpAccount | SkippedAccount:
    blobs: dict[int, bytes] = {}
    ints: dict[int, int] = {}
    for field in protobuf.parse_fields(raw):
        if field.number not in _ACCOUNT_FIELDS:
            raise MigratorError(f"unknown field {field.number}")
        if field.number in blobs or field.number in ints:
            raise MigratorError(f"repeated field {field.number}")
        if field.number in _BYTES_FIELDS and field.wire_type == protobuf.LENGTH_DELIMITED:
            assert isinstance(field.value, bytes)
            blobs[field.number] = field.value
        elif field.number not in _BYTES_FIELDS and field.wire_type == protobuf.VARINT:
            assert isinstance(field.value, int)
            ints[field.number] = field.value
        else:
            raise MigratorError(f"field {field.number} has the wrong wire type")

    issuer, name = split_label(_text(blobs.get(2, b"")), _text(blobs.get(3, b"")))
    secret = blobs.get(1, b"")
    # Enums are int32 on the wire. Field 7, the int64 HOTP counter, is not
    # read: only TOTP accounts are migrated.
    otp_type = protobuf.as_int32(ints.get(6, 0))
    algorithm = _ALGORITHMS.get(protobuf.as_int32(ints.get(4, 0)))
    digits = _DIGITS.get(protobuf.as_int32(ints.get(5, 0)))
    if otp_type != _TOTP:
        return SkippedAccount(name, issuer, "only TOTP accounts are supported", secret)
    if algorithm is None:
        return SkippedAccount(name, issuer, "unsupported or missing hash algorithm", secret)
    if digits is None:
        return SkippedAccount(name, issuer, "unsupported or missing digit count", secret)
    return make_account(name, issuer, secret, algorithm=algorithm, digits=digits)


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
        raise MigratorError("name or issuer is not valid UTF-8") from None
