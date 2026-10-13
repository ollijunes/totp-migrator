"""The last line of defence: refuse to print anything that holds a secret.

Normal output is built from metadata only. This check runs on every piece
of text the CLI shows without ``--reveal``, so a future bug that pulls a
secret into a message fails loudly instead of leaking quietly.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable

from .errors import MigratorError
from .model import TotpAccount

# Shorter encodings would match ordinary text and are too weak to matter.
_MIN_NEEDLE_LENGTH = 8
_URI_MARKERS = ("otpauth://", "otpauth-migration://")


def secret_needles(accounts: Iterable[TotpAccount]) -> set[str]:
    """Every common text encoding of every secret, lower-cased."""
    needles = set(_URI_MARKERS)
    for account in accounts:
        secret = account.secret
        encodings = [
            account.secret_base32,
            secret.hex(),
            base64.b64encode(secret).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(secret).decode("ascii").rstrip("="),
        ]
        if secret.isascii() and secret.decode("ascii").isprintable():
            encodings.append(secret.decode("ascii"))
        needles.update(
            encoding.lower() for encoding in encodings if len(encoding) >= _MIN_NEEDLE_LENGTH
        )
    return needles


def ensure_redacted(text: str, accounts: Iterable[TotpAccount]) -> str:
    """Return ``text`` unchanged, or raise if it contains secret material."""
    haystack = text.lower()
    if any(needle in haystack for needle in secret_needles(accounts)):
        raise MigratorError("refusing to print output that contains secret material")
    return text
