"""Exporters: pure functions from accounts to the text of an import file.

Every output here contains secrets. Writing it anywhere is the CLI's job.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Sequence

from .model import TotpAccount
from .otpauth import build_otpauth_uri

Exporter = Callable[[Sequence[TotpAccount]], str]

# Fixed namespace so Aegis entry UUIDs are stable across runs.
_AEGIS_NAMESPACE = uuid.UUID("5b0f6e3c-7a51-4b8e-9d0a-2f3c1e4d6a70")


def export_otpauth(accounts: Sequence[TotpAccount]) -> str:
    """One otpauth:// URI per line, for any app that accepts them."""
    return "".join(build_otpauth_uri(account) + "\n" for account in accounts)


def export_json(accounts: Sequence[TotpAccount]) -> str:
    """This tool's own structured format: explicit fields plus the URI."""
    document = {
        "format": "totp-migrator",
        "version": 1,
        "accounts": [
            {
                "issuer": account.issuer,
                "name": account.name,
                "type": "totp",
                "secret": account.secret_base32,
                "algorithm": account.algorithm,
                "digits": account.digits,
                "period": account.period,
                "uri": build_otpauth_uri(account),
            }
            for account in accounts
        ],
    }
    return _dump(document)


def export_aegis(accounts: Sequence[TotpAccount]) -> str:
    """An unencrypted Aegis vault (Import > Aegis, plain JSON)."""
    entries = [
        {
            "type": "totp",
            "uuid": str(uuid.uuid5(_AEGIS_NAMESPACE, f"{index}:{account.label}")),
            "name": account.name,
            "issuer": account.issuer,
            "note": "",
            "favorite": False,
            "icon": None,
            "info": {
                "secret": account.secret_base32,
                "algo": account.algorithm,
                "digits": account.digits,
                "period": account.period,
            },
        }
        for index, account in enumerate(accounts)
    ]
    document = {
        "version": 1,
        "header": {"slots": None, "params": None},
        "db": {"version": 2, "entries": entries},
    }
    return _dump(document)


def export_bitwarden(accounts: Sequence[TotpAccount]) -> str:
    """An unencrypted Bitwarden JSON export, which Vaultwarden also imports."""
    items = [
        {
            "type": 1,  # Login
            "name": account.title,
            "notes": None,
            "favorite": False,
            "reprompt": 0,
            "fields": [],
            "login": {
                "uris": [],
                "username": account.name,
                "password": None,
                "totp": build_otpauth_uri(account),
                "fido2Credentials": [],
            },
            "folderId": None,
            "organizationId": None,
            "collectionIds": None,
        }
        for account in accounts
    ]
    return _dump({"encrypted": False, "folders": [], "items": items})


def export_1password(accounts: Sequence[TotpAccount]) -> str:
    """1Password item templates, one JSON object per line.

    Pipe each line to ``op item create --vault <vault> -`` so the secret
    travels over stdin and never appears in argv or shell history.
    """
    lines = []
    for account in accounts:
        item = {
            "title": account.title,
            "category": "LOGIN",
            "fields": [
                {
                    "id": "username",
                    "type": "STRING",
                    "purpose": "USERNAME",
                    "label": "username",
                    "value": account.name,
                },
                {
                    "id": "one-time-password",
                    "type": "OTP",
                    "label": "one-time password",
                    "value": build_otpauth_uri(account),
                },
            ],
        }
        lines.append(json.dumps(item, ensure_ascii=False) + "\n")
    return "".join(lines)


EXPORTERS: dict[str, Exporter] = {
    "1password": export_1password,
    "bitwarden": export_bitwarden,
    "aegis": export_aegis,
    "otpauth": export_otpauth,
    "json": export_json,
}


def _dump(document: object) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"
