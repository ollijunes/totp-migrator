"""Strict percent-decoding for URI components.

``urllib.parse`` silently replaces bad UTF-8 and keeps malformed escapes
such as ``%ZZ``. That would migrate an account under a quietly altered
name, so both are errors here.
"""

from __future__ import annotations

import re
import urllib.parse

from .errors import MigratorError

_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def strict_unquote(text: str, *, plus_is_space: bool) -> str:
    if _BAD_ESCAPE.search(text):
        raise MigratorError("URI has an invalid percent escape")
    if plus_is_space:
        text = text.replace("+", " ")
    try:
        return urllib.parse.unquote(text, errors="strict")
    except UnicodeDecodeError:
        raise MigratorError("URI is not valid UTF-8 after percent-decoding") from None


def parse_query(query: str) -> dict[str, str]:
    """Parse ``key=value&...`` with lower-cased keys; repeated keys are errors."""
    params: dict[str, str] = {}
    for part in query.split("&"):
        if not part:
            continue
        raw_key, _, raw_value = part.partition("=")
        key = strict_unquote(raw_key, plus_is_space=True).lower()
        if key in params:
            raise MigratorError("URI repeats a query parameter")
        params[key] = strict_unquote(raw_value, plus_is_space=True)
    return params
