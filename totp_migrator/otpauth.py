"""Standard ``otpauth://totp/...`` URIs (the Google "Key Uri Format").

https://github.com/google/google-authenticator/wiki/Key-Uri-Format
"""

from __future__ import annotations

import base64
import binascii
import urllib.parse

from .errors import MigratorError, UnsupportedAccount
from .model import ALGORITHMS, DEFAULT_PERIOD, DIGITS, TotpAccount, split_label

SCHEME = "otpauth"
MAX_URI_LENGTH = 4096


def is_otpauth_uri(text: str) -> bool:
    return text.lower().startswith(SCHEME + "://")


def parse_otpauth_uri(uri: str) -> TotpAccount:
    if len(uri) > MAX_URI_LENGTH:
        raise MigratorError("otpauth URI is too long")
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme.lower() != SCHEME:
        raise MigratorError("not an otpauth:// URI")
    params = _query_params(parts.query)
    issuer, name = split_label(
        urllib.parse.unquote(parts.path.removeprefix("/")),
        params.get("issuer", ""),
    )
    label = f"{issuer}:{name}" if issuer else name

    otp_type = parts.netloc.lower()
    if otp_type != "totp":
        raise UnsupportedAccount(label, f"only TOTP is supported (this is {otp_type or 'unknown'})")
    algorithm = params.get("algorithm", "SHA1").upper()
    if algorithm not in ALGORITHMS:
        raise UnsupportedAccount(label, "unsupported hash algorithm")
    digits = _positive_int(params, "digits", 6)
    if digits not in DIGITS:
        raise UnsupportedAccount(label, f"{digits}-digit codes are not supported")
    return TotpAccount(
        name=name,
        issuer=issuer,
        secret=_decode_base32(params.get("secret", "")),
        algorithm=algorithm,
        digits=digits,
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


def _query_params(query: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        key = key.lower()
        if key in params:
            raise MigratorError(f"otpauth URI repeats the '{key}' parameter")
        params[key] = value
    return params


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
    if not (raw.isascii() and raw.isdigit()):
        raise MigratorError(f"otpauth '{key}' must be a positive integer")
    return int(raw)
