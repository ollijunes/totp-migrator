"""Exporters: functions from accounts to the text of an import file.

They have no side effects. Only the Aegis exporter is not deterministic:
it draws fresh entry UUIDs unless a generator is passed in.

Every output here contains secrets. Writing it anywhere is the CLI's job.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import Callable, Sequence

from .model import DEFAULT_PERIOD, TotpAccount
from .otpauth import build_otpauth_uri

Exporter = Callable[[Sequence[TotpAccount]], str]
# Returns why a format cannot hold an account, or None if it can.
Limit = Callable[[TotpAccount], str | None]


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
    """An unencrypted Aegis vault, as documented in Aegis's docs/vault.md.

    Null header slots and params mark the vault as not encrypted.

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
            "icon_mime": None,
            "icon_hash": None,
            "info": {
                "secret": account.secret_base32,
                "algo": account.algorithm,
                "digits": account.digits,
                "period": account.period,
            },
            "groups": [],
        }
        for account in accounts
    ]
    document = {
        "version": 1,
        "header": {"slots": None, "params": None},
        "db": {"version": 3, "entries": entries, "groups": []},
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
                    "id": "otp",
                    "type": "OTP",
                    "label": "one-time password",
                    "value": build_otpauth_uri(account),
                },
            ],
        }
        lines.append(json.dumps(item, ensure_ascii=False) + "\n")
    return "".join(lines)


LASTPASS_COLUMNS = ("url", "username", "password", "totp", "extra", "name", "grouping", "fav")


def export_lastpass(accounts: Sequence[TotpAccount]) -> str:
    """LastPass generic CSV, with the TOTP secret key in the ``totp`` column.

    LastPass takes the bare base32 secret key, not an otpauth:// URI, so the
    algorithm, digits and period cannot be carried. ``lastpass_limit`` keeps
    out every account that does not use the defaults.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(LASTPASS_COLUMNS)
    for account in accounts:
        writer.writerow(["", account.name, "", account.secret_base32, "", account.title, "", "0"])
    return buffer.getvalue()


# Spreadsheets read a cell that starts with one of these as a formula. The
# CSV files are meant for a password manager, not Excel, but a crafted QR
# label should not be able to run anything if someone opens one there. The
# name is not rewritten (that would change it in the vault too); the account
# is left out instead.
_FORMULA_PREFIXES = ("=", "+", "-", "@")
_FORMULA_REASON = "name starts with a character spreadsheets treat as a formula; add it by hand"


def lastpass_limit(account: TotpAccount) -> str | None:
    if (account.algorithm, account.digits, account.period) != ("SHA1", 6, DEFAULT_PERIOD):
        return "LastPass stores only SHA1, 6-digit, 30-second codes"
    return _formula_limit(account)


# The header row of Proton's own template, pass.proton.me/assets/protonpass-import.csv.
PROTONPASS_COLUMNS = ("name", "url", "email", "username", "password", "note", "totp", "vault")


def export_protonpass(accounts: Sequence[TotpAccount]) -> str:
    """Proton Pass generic CSV, with a full otpauth:// URI in the ``totp`` column.

    Proton Pass parses the URI (packages/pass/lib/otp/otp.ts in ProtonMail/
    WebClients), so algorithm, digits and period survive. The ``vault``
    column is left empty; the web app asks which vault to import into.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(PROTONPASS_COLUMNS)
    for account in accounts:
        writer.writerow(
            [account.title, "", "", account.name, "", "", build_otpauth_uri(account), ""]
        )
    return buffer.getvalue()


def protonpass_limit(account: TotpAccount) -> str | None:
    return _formula_limit(account)


def _formula_limit(account: TotpAccount) -> str | None:
    if account.name.startswith(_FORMULA_PREFIXES) or account.title.startswith(_FORMULA_PREFIXES):
        return _FORMULA_REASON
    return None


EXPORTERS: dict[str, Exporter] = {
    "1password": export_1password,
    "bitwarden": export_bitwarden,
    "aegis": export_aegis,
    "lastpass": export_lastpass,
    "protonpass": export_protonpass,
    "otpauth": export_otpauth,
    "json": export_json,
}

# Formats that cannot represent every valid account.
LIMITS: dict[str, Limit] = {"lastpass": lastpass_limit, "protonpass": protonpass_limit}


def _dump(document: object) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"
