"""The last line of defence: refuse to print anything that holds a secret.

Normal output is built from metadata only. This check runs on every piece
of text the CLI shows without ``--reveal``, so a future bug that pulls a
secret into a message fails loudly instead of leaking quietly.

Matching ignores case and every non-alphanumeric character on both sides.
That catches secrets spelled with spaces or hyphens, split by JSON escapes,
or in any base64 alphabet.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable

from .errors import MigratorError

# Every accepted secret is at least 10 bytes, so its base32 form alone is
# 16 characters. Shorter fragments would match ordinary text.
_MIN_NEEDLE_LENGTH = 8
_URI_MARKERS = ("otpauth://", "otpauth-migration://")
_NOT_ALPHANUMERIC = re.compile(r"[^0-9a-z]")


def ensure_redacted(text: str, secrets: Iterable[bytes]) -> str:
    """Return ``text`` unchanged, or raise if it contains secret material."""
    lowered = text.lower()
    compact = _compact(lowered)
    secrets = list(secrets)
    if (
        any(marker in lowered for marker in _URI_MARKERS)
        or any(needle in compact for needle in _compact_needles(secrets))
        or any(needle in lowered for needle in _raw_needles(secrets))
    ):
        raise MigratorError("refusing to print output that contains secret material")
    return text


def _compact_needles(secrets: list[bytes]) -> set[str]:
    needles = set()
    for secret in secrets:
        encodings = [
            base64.b32encode(secret).decode("ascii"),
            secret.hex(),
            base64.b64encode(secret).decode("ascii"),
            base64.urlsafe_b64encode(secret).decode("ascii"),
        ]
        if _printable(secret):
            encodings.append(secret.decode("ascii"))
        needles.update(_compact(encoding.lower()) for encoding in encodings)
    return {needle for needle in needles if len(needle) >= _MIN_NEEDLE_LENGTH}


def _raw_needles(secrets: list[bytes]) -> set[str]:
    """Printable secrets made mostly of punctuation, as written and JSON-escaped."""
    needles = set()
    for secret in secrets:
        if _printable(secret):
            raw = secret.decode("ascii").lower()
            needles.update({raw, json.dumps(raw)[1:-1]})
    return {needle for needle in needles if len(needle) >= _MIN_NEEDLE_LENGTH}


def _printable(secret: bytes) -> bool:
    return secret.isascii() and secret.decode("ascii").isprintable()


def _compact(text: str) -> str:
    return _NOT_ALPHANUMERIC.sub("", text)
