"""Command-line interface.

Two rules hold everywhere in this module:

* Without ``--reveal`` nothing secret reaches stdout or stderr, and every
  message passes through ``ensure_redacted`` on its way out.
* URIs are read from stdin or a file, never from argv, because arguments end
  up in shell history and in other users' process listings.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Sequence
from typing import TextIO

from . import __version__
from .errors import MigratorError
from .exporters import EXPORTERS
from .model import TotpAccount
from .otpauth import build_otpauth_uri
from .reader import ReadResult, read_accounts
from .redaction import ensure_redacted
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
            "pass URIs on stdin or in a file, not as arguments "
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
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
        help="new file to create with mode 0600; never overwrites an existing file",
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
        help="file with one URI per line; '-' or omitted reads stdin",
    )
    parser.add_argument(
        "--reveal",
        action="store_true",
        help="allow secrets in the output (off by default)",
    )


def _run_decode(args: argparse.Namespace) -> int:
    result = _read(args.input)
    if args.reveal:
        _error(REVEAL_WARNING)
    now = int(time.time())
    rows = [_describe(account, reveal=args.reveal, now=now) for account in result.accounts]
    text = json.dumps(rows, ensure_ascii=False, indent=2) + "\n" if args.json else _table(rows)
    _write(sys.stdout, text, result.accounts, reveal=args.reveal)
    _report(result, reveal=args.reveal)
    return 0


def _run_export(args: argparse.Namespace) -> int:
    to_stdout = args.output in (None, "-")
    if to_stdout and not args.reveal:
        raise MigratorError(
            "refusing to write secrets to the terminal: use --output FILE, "
            "or add --reveal to write to stdout"
        )
    result = _read(args.input)
    if result.skipped and not args.skip_unsupported:
        _report_skipped(result)
        raise MigratorError(
            f"{len(result.skipped)} account(s) cannot be exported; "
            "pass --skip-unsupported to export the rest"
        )
    if not result.accounts:
        raise MigratorError("no accounts to export")

    content = EXPORTERS[args.format](result.accounts)
    if to_stdout:
        _error(REVEAL_WARNING)
        sys.stdout.write(content)
    else:
        _create_private_file(args.output, content)
    _report(result, reveal=args.reveal)
    if not to_stdout:
        _note(
            f"Wrote {args.format} import file {args.output} (mode 0600). It holds your "
            "secrets: import it, check the codes, then delete it.",
            result.accounts,
        )
    return 0


def _read(source: str) -> ReadResult:
    if source == "-":
        if sys.stdin.isatty():
            _error("Paste URIs, one per line, then press Ctrl-D.")
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    else:
        try:
            with open(source, "rb") as handle:
                raw = handle.read(MAX_INPUT_BYTES + 1)
        except OSError as error:
            raise MigratorError(f"cannot read {source}: {error.strerror}") from None
    if len(raw) > MAX_INPUT_BYTES:
        raise MigratorError(f"input is larger than {MAX_INPUT_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise MigratorError("input is not valid UTF-8") from None
    return read_accounts(text)


def _create_private_file(path: str, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise MigratorError(f"{path} already exists; refusing to overwrite it") from None
    except OSError as error:
        raise MigratorError(f"cannot create {path}: {error.strerror}") from None
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


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
        "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=False)).rstrip()
        + "\n"
        for line in cells
    )


def _report(result: ReadResult, *, reveal: bool) -> None:
    summary = f"{len(result.accounts)} account(s)"
    if result.qr_batches:
        summary += f" from {result.qr_batches} Google Authenticator QR code(s)"
    if result.duplicates_removed:
        summary += f", {result.duplicates_removed} duplicate(s) removed"
    _note(summary + ".", result.accounts)
    _report_skipped(result)
    if not reveal:
        _note("Secrets are hidden. Add --reveal to show them.", result.accounts)


def _report_skipped(result: ReadResult) -> None:
    for unsupported in result.skipped:
        _note(f"skipped {unsupported}", result.accounts)


def _write(stream: TextIO, text: str, accounts: Sequence[TotpAccount], *, reveal: bool) -> None:
    stream.write(text if reveal else ensure_redacted(text, accounts))


def _note(message: str, accounts: Sequence[TotpAccount]) -> None:
    _write(sys.stderr, message + "\n", accounts, reveal=False)


def _error(message: str) -> None:
    sys.stderr.write(f"totp-migrator: {message}\n")
