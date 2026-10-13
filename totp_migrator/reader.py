"""Turn input text (one URI per line) into accounts."""

from __future__ import annotations

from dataclasses import dataclass

from . import google, otpauth
from .errors import MigratorError
from .model import SkippedAccount, TotpAccount


@dataclass(frozen=True)
class SkippedEntry:
    location: str  # "line 3", "line 3, account 2" or "for lastpass"
    account: SkippedAccount


@dataclass(frozen=True)
class ReadResult:
    accounts: tuple[TotpAccount, ...]
    skipped: tuple[SkippedEntry, ...]
    qr_codes: int
    repeated_lines: int  # identical input lines, read once
    duplicate_accounts: int  # identical accounts from different lines, kept once

    @property
    def secrets(self) -> tuple[bytes, ...]:
        """Every secret seen, including skipped accounts, for the redaction guard."""
        return tuple(account.secret for account in self.accounts) + tuple(
            entry.account.secret for entry in self.skipped
        )


def read_accounts(text: str) -> ReadResult:
    """Parse every non-empty, non-comment line.

    Lines may be ``otpauth-migration://`` (Google Authenticator export) or
    ``otpauth://`` URIs, mixed freely. A repeated line is read once, since
    scanning the same QR code twice is common. Error messages name the line
    number, never the line content.
    """
    accounts: list[TotpAccount] = []
    skipped: list[SkippedEntry] = []
    batches: list[google.MigrationBatch] = []
    seen_lines: set[str] = set()
    repeated_lines = 0

    for number, line in enumerate(text.splitlines(), start=1):
        # A BOM can start any line when files from a Windows editor are concatenated.
        line = line.lstrip("﻿").strip()
        if not line or line.startswith("#"):
            continue
        if line in seen_lines:
            repeated_lines += 1
            continue
        seen_lines.add(line)
        location = f"line {number}"
        try:
            if google.is_migration_uri(line):
                batch = google.parse_migration_uri(line)
                batches.append(batch)
                entries = [
                    (f"{location}, account {index}", entry)
                    for index, entry in enumerate(batch.entries, start=1)
                ]
            elif otpauth.is_otpauth_uri(line):
                entries = [(location, otpauth.parse_otpauth_uri(line))]
            else:
                raise MigratorError("expected an otpauth or otpauth-migration URI")
        except MigratorError as error:
            raise MigratorError(f"{location}: {error}") from None
        for entry_location, entry in entries:
            if isinstance(entry, SkippedAccount):
                skipped.append(SkippedEntry(entry_location, entry))
            else:
                accounts.append(entry)

    google.check_batches_complete(batches)
    unique = tuple(dict.fromkeys(accounts))
    return ReadResult(
        accounts=unique,
        skipped=tuple(skipped),
        qr_codes=len(batches),
        repeated_lines=repeated_lines,
        duplicate_accounts=len(accounts) - len(unique),
    )
