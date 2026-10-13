"""The last line of defence: refuse to print anything that holds a secret.

Normal output is built from metadata only. This check runs on every piece
of text the CLI shows without ``--reveal``, so a bug that pulls a secret
into a message fails loudly instead of leaking quietly.

Every secret is matched in each common encoding (base32, hex, both base64
alphabets, and the raw bytes when they are printable), three ways:

* exactly, ignoring case;
* with separators removed, so spaced, hyphenated, padded or
  backslash-escaped spellings match;
* reduced to letters and digits, so any other punctuation pushed into an
  alphanumeric encoding still matches.

Secrets are at least ``model.MIN_SECRET_BYTES`` long, so the needles are
long enough not to match ordinary text by accident.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterable

from .errors import MigratorError

_URI_MARKERS = ("otpauth://", "otpauth-migration://")
_SEPARATORS = re.compile(r"[\s\-_=\\]")
_NOT_ALPHANUMERIC = re.compile(r"[^0-9a-z]")
# A reduced needle shorter than this could match ordinary text.
_MIN_REDUCED_LENGTH = 8


class Redactor:
    """Checks output text against every secret seen in one run."""

    def __init__(self, secrets: Iterable[bytes]) -> None:
        self._exact: set[str] = set(_URI_MARKERS)
        self._stripped: set[str] = set()
        self._compact: set[str] = set()
        for secret in set(secrets):
            for encoding in _encodings(secret):
                self._exact.add(encoding)
                stripped = _SEPARATORS.sub("", encoding)
                if len(stripped) >= _MIN_REDUCED_LENGTH:
                    self._stripped.add(stripped)
                compact = _NOT_ALPHANUMERIC.sub("", encoding)
                if len(compact) >= _MIN_REDUCED_LENGTH:
                    self._compact.add(compact)

    def contains_secret(self, text: str) -> bool:
        lowered = text.lower()
        stripped = _SEPARATORS.sub("", lowered)
        compact = _NOT_ALPHANUMERIC.sub("", lowered)
        return (
            any(needle in lowered for needle in self._exact)
            or any(needle in stripped for needle in self._stripped)
            or any(needle in compact for needle in self._compact)
        )

    def ensure_redacted(self, text: str) -> str:
        """Return ``text`` unchanged, or raise if it contains secret material."""
        if self.contains_secret(text):
            raise MigratorError("refusing to print output that contains secret material")
        return text


def _encodings(secret: bytes) -> list[str]:
    encodings = [
        base64.b32encode(secret).decode("ascii"),
        secret.hex(),
        base64.b64encode(secret).decode("ascii"),
        base64.urlsafe_b64encode(secret).decode("ascii"),
    ]
    if secret.isascii() and secret.decode("ascii").isprintable():
        encodings.append(secret.decode("ascii"))
    return [encoding.lower() for encoding in encodings]
