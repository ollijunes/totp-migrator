"""Turn input text (one URI per line) into accounts."""

from __future__ import annotations

from dataclasses import dataclass

from . import google, otpauth
from .errors import MigratorError, UnsupportedAccount
from .model import TotpAccount


@dataclass(frozen=True)
class ReadResult:
    accounts: tuple[TotpAccount, ...]
    skipped: tuple[UnsupportedAccount, ...]
    qr_batches: int
    duplicates_removed: int


def read_accounts(text: str) -> ReadResult:
    """Parse every non-empty, non-comment line.

    Lines may be ``otpauth-migration://`` (Google Authenticator export) or
    ``otpauth://`` URIs, mixed freely. A repeated line is read once, since
    scanning the same QR code twice is common. Error messages name the line
    number, never the line content.
    """
    accounts: list[TotpAccount] = []
    skipped: list[UnsupportedAccount] = []
    batches: list[google.MigrationBatch] = []
    seen_lines: set[str] = set()
    repeated_lines = 0

    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        if line in seen_lines:
            repeated_lines += 1
            continue
        seen_lines.add(line)
        try:
            if google.is_migration_uri(line):
                batch = google.parse_migration_uri(line)
                batches.append(batch)
                accounts.extend(batch.accounts)
                skipped.extend(batch.skipped)
            elif otpauth.is_otpauth_uri(line):
                accounts.append(otpauth.parse_otpauth_uri(line))
            else:
                raise MigratorError("expected an otpauth:// or otpauth-migration:// URI")
        except UnsupportedAccount as unsupported:
            skipped.append(unsupported)
        except MigratorError as error:
            raise MigratorError(f"line {number}: {error}") from None

    google.check_batches_complete(batches)
    unique = tuple(dict.fromkeys(accounts))
    return ReadResult(
        accounts=unique,
        skipped=tuple(skipped),
        qr_batches=len(batches),
        duplicates_removed=repeated_lines + len(accounts) - len(unique),
    )
