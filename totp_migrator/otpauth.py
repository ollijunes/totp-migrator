"""Standard ``otpauth://totp/...`` URIs (the Google "Key Uri Format").

https://github.com/google/google-authenticator/wiki/Key-Uri-Format
"""

from __future__ import annotations

import base64
import binascii
import urllib.parse

from .errors import MigratorError
from .model import (
    ALGORITHMS,
    DEFAULT_PERIOD,
    SkippedAccount,
    TotpAccount,
    make_account,
    split_label,
)
from .urltext import parse_query, strict_unquote

SCHEME = "otpauth"
MAX_URI_LENGTH = 4096


def is_otpauth_uri(text: str) -> bool:
    return text.lower().startswith(SCHEME + "://")


def parse_otpauth_uri(uri: str) -> TotpAccount | SkippedAccount:
    if len(uri) > MAX_URI_LENGTH:
        raise MigratorError("otpauth URI is too long")
    try:
        parts = urllib.parse.urlsplit(uri)
    except ValueError:
        raise MigratorError("otpauth URI is malformed") from None
    if parts.scheme.lower() != SCHEME:
        raise MigratorError("not an otpauth:// URI")
    params = parse_query(parts.query)
    issuer, name = split_label(
        strict_unquote(parts.path.removeprefix("/"), plus_is_space=False),
        params.get("issuer", ""),
    )
    secret = _decode_base32(params.get("secret", ""))

    if parts.netloc.lower() != "totp":
        return SkippedAccount(name, issuer, "only TOTP accounts are supported", secret)
    algorithm = params.get("algorithm", "SHA1").upper()
    if algorithm not in ALGORITHMS:
        return SkippedAccount(name, issuer, "unsupported hash algorithm", secret)
    return make_account(
        name,
        issuer,
        secret,
        algorithm=algorithm,
        digits=_positive_int(params, "digits", 6),
        period=_positive_int(params, "period", DEFAULT_PERIOD),
    )


def build_otpauth_uri(account: TotpAccount) -> str:
    """Build a URI with every parameter explicit, so no app has to guess."""
    label = urllib.parse.quote(account.name, safe="@")
    if account.issuer:
        label = urllib.parse.quote(account.issuer, safe="") + ":" + label
    query = urllib.parse.urlencode(
        {
            "secret": account.secret_base32,
            "issuer": account.issuer,
            "algorithm": account.algorithm,
            "digits": account.digits,
            "period": account.period,
        },
        quote_via=urllib.parse.quote,
    )
    return f"otpauth://totp/{label}?{query}"


def _decode_base32(text: str) -> bytes:
    cleaned = text.replace(" ", "").replace("-", "").upper().rstrip("=")
    if not cleaned:
        raise MigratorError("otpauth URI has no secret")
    try:
        return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except binascii.Error:
        raise MigratorError("otpauth secret is not valid base32") from None


def _positive_int(params: dict[str, str], key: str, default: int) -> int:
    raw = params.get(key)
    if raw is None:
        return default
    if not (raw.isascii() and raw.isdigit()) or len(raw) > 9:
        raise MigratorError(f"otpauth '{key}' must be a positive integer")
    return int(raw)
