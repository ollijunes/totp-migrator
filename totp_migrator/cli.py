"""Command-line interface.

Rules that hold everywhere in this module:

* Without ``--reveal`` nothing secret reaches stdout or stderr. Every
  message about accounts passes the ``Redactor`` on its way out, and
  error messages carry only positions and fixed descriptions. Nothing the
  user typed is printed back: not argument values, not the output path.
* URIs are read from a file or a pipe, never from argv (shell history,
  process listings) and never from an interactive terminal (echo,
  scrollback).
* ``export`` validates every message it will print before it creates the
  file, so a refused message never leaves a half-finished run behind.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import time
from collections.abc import Sequence
from typing import NoReturn

from . import __version__
from .errors import MigratorError
from .exporters import EXPORTERS
from .model import TotpAccount
from .otpauth import build_otpauth_uri
from .reader import ReadResult, read_accounts
from .redaction import Redactor
from .totp import current_code

MAX_INPUT_BYTES = 1024 * 1024

REVEAL_WARNING = (
    "warning: --reveal prints TOTP secrets. Anyone who sees them, or the "
    "scrollback, can generate your codes."
)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(_looks_like_uri(arg) for arg in argv):
        _error(
            "pass URIs in a file or through a pipe, not as arguments "
            "(arguments end up in shell history and process listings)"
        )
        return 2
    args = _build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except MigratorError as error:
        _error(str(error))
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception as error:  # noqa: BLE001 - never echo unknown messages
        _error(f"unexpected {type(error).__name__}; details hidden to protect secrets")
        return 1


def _looks_like_uri(arg: str) -> bool:
    return "://" in arg or arg.lower().startswith(("otpauth:", "otpauth-migration:"))


class _Parser(argparse.ArgumentParser):
    """argparse quotes the offending value in its error messages.

    A secret pasted as an argument by mistake would be printed back, so
    usage errors show the usage line and a fixed message instead.
    """

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(
            2,
            f"{self.prog}: error: invalid or missing arguments; values are not shown "
            "in case one is a secret. See --help.\n",
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="totp-migrator",
        description=(
            "Move TOTP accounts out of Google Authenticator or otpauth:// URIs "
            "into 1Password, Bitwarden/Vaultwarden, Aegis, or plain URIs. "
            "Offline only. Secrets stay hidden unless you pass --reveal."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    decode = commands.add_parser(
        "decode",
        help="list the accounts in the input without showing secrets",
    )
    _add_common_arguments(decode)
    decode.add_argument("--json", action="store_true", help="print JSON instead of a table")
    decode.set_defaults(handler=_run_decode)

    export = commands.add_parser("export", help="write an import file for another app")
    _add_common_arguments(export)
    export.add_argument(
        "-f", "--format", required=True, choices=sorted(EXPORTERS), help="target format"
    )
    export.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="new file to create (owner-only on Linux and macOS); never overwrites",
    )
    export.add_argument(
        "--skip-unsupported",
        action="store_true",
        help="export the supported accounts and leave out HOTP and other unsupported ones",
    )
    export.set_defaults(handler=_run_export)
    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        metavar="INPUT",
        help="file with one URI per line; '-' or omitted reads a pipe",
    )
    parser.add_argument(
        "--reveal",
        action="store_true",
        help="allow secrets in the output (off by default)",
    )


def _run_decode(args: argparse.Namespace) -> int:
    result = _read(args.input)
    redactor = Redactor(result.secrets)
    notes = _notes(result, redactor, reveal=args.reveal)
    if args.reveal:
        _error(REVEAL_WARNING)
    now = int(time.time())
    rows = [_describe(account, reveal=args.reveal, now=now) for account in result.accounts]
    text = json.dumps(rows, ensure_ascii=False, indent=2) + "\n" if args.json else _table(rows)
    sys.stdout.write(text if args.reveal else redactor.ensure_redacted(text))
    _write_notes(notes)
    return 0


def _run_export(args: argparse.Namespace) -> int:
    to_stdout = args.output in (None, "-")
    if to_stdout and not args.reveal:
        raise MigratorError(
            "refusing to write secrets to the terminal: use --output FILE, "
            "or add --reveal to write to stdout"
        )
    result = _read(args.input)
    redactor = Redactor(result.secrets)
    notes = _notes(result, redactor, reveal=args.reveal)
    if result.skipped and not args.skip_unsupported:
        _write_notes(_skipped_notes(result, redactor))
        raise MigratorError(
            f"{len(result.skipped)} account(s) cannot be exported; "
            "pass --skip-unsupported to export the rest"
        )
    if not result.accounts:
        _write_notes(_skipped_notes(result, redactor))
        raise MigratorError("no accounts to export")

    content = EXPORTERS[args.format](result.accounts)
    if to_stdout:
        _error(REVEAL_WARNING)
        sys.stdout.write(content)
    else:
        _create_private_file(args.output, content)
        access = "readable only by you" if os.name == "posix" else "permissions follow its folder"
        notes.append(
            f"Wrote the {args.format} import file ({access}). It holds your secrets: "
            "import it, check the codes, then delete it."
        )
    _write_notes(notes)
    return 0


def _read(source: str) -> ReadResult:
    if source == "-":
        if sys.stdin.isatty():
            raise MigratorError(
                "refusing to read URIs from the terminal, where they would be echoed "
                "on screen; pass a file, or pipe them in (for example from the clipboard)"
            )
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    else:
        try:
            with open(source, "rb") as handle:
                raw = handle.read(MAX_INPUT_BYTES + 1)
        except OSError as error:
            raise MigratorError(f"cannot read the input file: {error.strerror}") from None
    if len(raw) > MAX_INPUT_BYTES:
        raise MigratorError(f"input is larger than {MAX_INPUT_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise MigratorError("input is not valid UTF-8") from None
    return read_accounts(text)


def _create_private_file(path: str, content: str) -> None:
    """Create ``path`` exclusively, owner-only on POSIX. Windows ignores the mode."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)  # POSIX: never write through a symlink
    flags |= getattr(os, "O_BINARY", 0)  # Windows: keep "\n" as written
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise MigratorError("the output file already exists; refusing to overwrite it") from None
    except OSError as error:
        raise MigratorError(f"cannot create the output file: {error.strerror}") from None
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    except OSError as error:
        # Never leave a half-written secret file behind.
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise MigratorError(f"cannot write the output file: {error.strerror}") from None


def _describe(account: TotpAccount, *, reveal: bool, now: int) -> dict[str, object]:
    row: dict[str, object] = {
        "issuer": account.issuer,
        "name": account.name,
        "algorithm": account.algorithm,
        "digits": account.digits,
        "period": account.period,
    }
    if reveal:
        row["code"] = current_code(account, now)
        row["secret"] = account.secret_base32
        row["uri"] = build_otpauth_uri(account)
    return row


def _table(rows: list[dict[str, object]]) -> str:
    if not rows:
        return ""
    columns = [column for column in rows[0] if column != "uri"]
    cells = [[column.upper() for column in columns]]
    cells += [[str(row[column]) for column in columns] for row in rows]
    widths = [max(len(line[i]) for line in cells) for i in range(len(columns))]
    return "".join(
        "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        + "\n"
        for line in cells
    )


def _notes(result: ReadResult, redactor: Redactor, *, reveal: bool) -> list[str]:
    """Every stderr line about the run, each already checked by the redactor."""
    summary = f"{len(result.accounts)} account(s)"
    if result.qr_codes:
        summary += f" from {result.qr_codes} Google Authenticator QR code(s)"
    if result.repeated_lines:
        summary += f", {result.repeated_lines} repeated line(s) read once"
    if result.duplicate_accounts:
        summary += f", {result.duplicate_accounts} duplicate account(s) kept once"
    notes = [redactor.ensure_redacted(summary + "."), *_skipped_notes(result, redactor)]
    if not reveal:
        notes.append("Secrets are hidden. Add --reveal to show them.")
    return notes


def _skipped_notes(result: ReadResult, redactor: Redactor) -> list[str]:
    """Name each skipped account, unless its label itself contains a secret."""
    notes = []
    for entry in result.skipped:
        named = f"skipped {entry.location} ({entry.account.label}): {entry.account.reason}"
        if redactor.contains_secret(named):
            named = f"skipped {entry.location} (name hidden): {entry.account.reason}"
        notes.append(redactor.ensure_redacted(named))
    return notes


def _write_notes(notes: list[str]) -> None:
    sys.stderr.write("".join(note + "\n" for note in notes))


def _error(message: str) -> None:
    sys.stderr.write(f"totp-migrator: {message}\n")
