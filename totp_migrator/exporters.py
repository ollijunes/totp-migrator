"""Exporters: functions from accounts to the text of an import file.

They have no side effects. Only the Aegis exporter is not deterministic:
it draws fresh entry UUIDs unless a generator is passed in.

Every output here contains secrets. Writing it anywhere is the CLI's job.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Sequence

from .model import TotpAccount
from .otpauth import build_otpauth_uri

Exporter = Callable[[Sequence[TotpAccount]], str]


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


def export_aegis(
    accounts: Sequence[TotpAccount],
    new_uuid: Callable[[], uuid.UUID] = uuid.uuid4,
) -> str:
    """An unencrypted Aegis vault (Import > Aegis, plain JSON).

    Every entry gets a fresh random UUID, as Aegis does for new entries, so
    an import never collides with an entry that is already in the vault.
    """
    entries = [
        {
            "type": "totp",
            "uuid": str(new_uuid()),
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
        for account in accounts
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
