"""The internal account model shared by every parser and exporter."""

from __future__ import annotations

import base64
import unicodedata
from dataclasses import dataclass, field

from .errors import MigratorError, UnsupportedValue

ALGORITHMS = ("SHA1", "SHA256", "SHA512")
DIGITS = (6, 7, 8)
DEFAULT_PERIOD = 30
MAX_PERIOD = 3600
# 80 bits: the shortest secret in common use, and long enough that the
# redaction guard can recognise every encoding of it.
MIN_SECRET_BYTES = 10
MAX_SECRET_BYTES = 256
MAX_TEXT_LENGTH = 256

# Control, format (bidi overrides, zero-width), line/paragraph separators,
# private-use and surrogate characters. They can rewrite what a terminal
# shows, so a crafted QR code could make one account look like another.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs"})


@dataclass(frozen=True)
class TotpAccount:
    """One TOTP credential.

    The secret is excluded from repr() so that an account can never leak
    through a log line, a traceback, or an assertion message.
    """

    name: str
    issuer: str
    secret: bytes = field(repr=False)
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = DEFAULT_PERIOD

    def __post_init__(self) -> None:
        check_label_text(self.name, self.issuer)
        if not self.name.strip():
            raise UnsupportedValue("account has no name")
        if ":" in self.issuer:
            # The Key Uri Format forbids this; a colon would split the label wrongly.
            raise UnsupportedValue("issuer contains ':'")
        if not MIN_SECRET_BYTES <= len(self.secret) <= MAX_SECRET_BYTES:
            raise UnsupportedValue(
                f"secret must be {MIN_SECRET_BYTES}-{MAX_SECRET_BYTES} bytes long"
            )
        if self.algorithm not in ALGORITHMS:
            raise UnsupportedValue("unsupported hash algorithm")
        if self.digits not in DIGITS:
            raise UnsupportedValue("codes must have 6, 7 or 8 digits")
        if not 1 <= self.period <= MAX_PERIOD:
            raise UnsupportedValue(f"period must be 1-{MAX_PERIOD} seconds")

    @property
    def label(self) -> str:
        """The otpauth-style label, for example ``GitHub:octocat``."""
        return _label(self.issuer, self.name)

    @property
    def title(self) -> str:
        """A human-friendly item title for password managers."""
        return f"{self.issuer} ({self.name})" if self.issuer else self.name

    @property
    def secret_base32(self) -> str:
        """The secret as unpadded RFC 4648 base32, the form every app accepts."""
        return base64.b32encode(self.secret).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class SkippedAccount:
    """A well-formed account that this tool will not migrate, and why.

    The secret is kept only so the redaction guard can recognise it.
    """

    name: str
    issuer: str
    reason: str
    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        check_label_text(self.name, self.issuer)

    @property
    def label(self) -> str:
        return _label(self.issuer, self.name)


def make_account(
    name: str,
    issuer: str,
    secret: bytes,
    *,
    algorithm: str,
    digits: int,
    period: int = DEFAULT_PERIOD,
) -> TotpAccount | SkippedAccount:
    """Build an account, or a SkippedAccount if a value is unsupported."""
    try:
        return TotpAccount(name, issuer, secret, algorithm, digits, period)
    except UnsupportedValue as unsupported:
        return SkippedAccount(name, issuer, str(unsupported), secret)


def split_label(label: str, issuer: str) -> tuple[str, str]:
    """Split an ``Issuer:name`` label into (issuer, name).

    ``issuer`` is the explicit issuer, if the source has one. It wins over
    the label prefix. When the prefix disagrees with it, the label is kept
    whole as the name so no information is lost.
    """
    issuer = issuer.strip()
    prefix, separator, rest = label.partition(":")
    if not separator:
        return issuer, label.strip()
    prefix, rest = prefix.strip(), rest.strip()
    if not issuer:
        return prefix, rest
    if prefix == issuer:
        return issuer, rest
    return issuer, label.strip()


def check_label_text(name: str, issuer: str) -> None:
    """Reject names and issuers that are huge or could spoof a terminal."""
    _check_text("name", name)
    _check_text("issuer", issuer)


def _check_text(what: str, value: str) -> None:
    if len(value) > MAX_TEXT_LENGTH:
        raise MigratorError(f"account {what} is longer than {MAX_TEXT_LENGTH} characters")
    if any(unicodedata.category(char) in _FORBIDDEN_CATEGORIES for char in value):
        raise MigratorError(f"account {what} contains control or invisible characters")


def _label(issuer: str, name: str) -> str:
    return ":".join(part for part in (issuer, name) if part) or "unnamed"
