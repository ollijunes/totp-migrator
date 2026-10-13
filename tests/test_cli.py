"""End-to-end CLI tests, focused on the privacy guarantees."""

import ast
import io
import json
import os
import socket
import stat
import tempfile
import time
import unittest
import urllib.parse
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tests.fixtures import SYNTHETIC_SECRET, ga_account, ga_payload, ga_uri, secret_forms
from totp_migrator import cli
from totp_migrator.model import TotpAccount
from totp_migrator.otpauth import build_otpauth_uri, parse_otpauth_uri
from totp_migrator.totp import current_code

SECOND_SECRET = bytes(range(1, 21))
GA_URI = ga_uri(
    ga_payload(
        ga_account(name=b"alice@example.test"),
        ga_account(name=b"hotp-user", otp_type=1),
    )
)
OTPAUTH_URI = build_otpauth_uri(TotpAccount("bob", "Other", SECOND_SECRET, "SHA256", 8, 60))
INPUT = f"# comment\n\n{GA_URI}\n{OTPAUTH_URI}\n{OTPAUTH_URI}\n"
ALL_SECRETS = (SYNTHETIC_SECRET, SECOND_SECRET)


class Result:
    def __init__(self, code: int, stdout: str, stderr: str) -> None:
        self.code, self.stdout, self.stderr = code, stdout, stderr

    @property
    def everything(self) -> str:
        return self.stdout + self.stderr


def run(*argv: str, stdin: str = INPUT, tty: bool = False) -> Result:
    """Run the CLI in-process with sockets disabled, capturing all output."""
    fake_stdin = io.TextIOWrapper(io.BytesIO(stdin.encode("utf-8")))
    fake_stdin.isatty = lambda: tty  # type: ignore[method-assign]
    stdout, stderr = io.StringIO(), io.StringIO()

    def no_network(*args, **kwargs):
        raise AssertionError("network access attempted")

    with (
        mock.patch("sys.stdin", fake_stdin),
        mock.patch.object(socket, "socket", no_network),
        mock.patch.object(socket, "create_connection", no_network),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        try:
            code = cli.main(list(argv))
        except SystemExit as exit_:
            code = int(exit_.code or 0)
    return Result(code, stdout.getvalue(), stderr.getvalue())


class RedactionTestCase(unittest.TestCase):
    def assert_no_secrets(self, text: str) -> None:
        lowered = text.lower()
        for marker in ("otpauth://", "otpauth-migration://", "secret=", "data="):
            self.assertNotIn(marker, lowered, "URI leaked")
        for secret in ALL_SECRETS:
            for form in secret_forms(secret):
                self.assertNotIn(form.lower(), lowered, "secret leaked")
        now = int(time.time())
        for account in (
            TotpAccount("a", "", SYNTHETIC_SECRET),
            TotpAccount("b", "", SECOND_SECRET, "SHA256", 8, 60),
        ):
            for moment in (now - 60, now, now + 60):
                self.assertNotIn(current_code(account, moment), text, "code leaked")


class DecodeTests(RedactionTestCase):
    def test_table_shows_metadata_only(self) -> None:
        result = run("decode")
        self.assertEqual(result.code, 0)
        self.assertIn("alice@example.test", result.stdout)
        self.assertIn("Other", result.stdout)
        self.assertIn("SHA256", result.stdout)
        self.assertIn("2 account(s) from 1 Google Authenticator QR code(s)", result.stderr)
        self.assertIn("1 repeated line(s) read once", result.stderr)
        self.assertIn(
            "skipped line 3, account 2 (Example:hotp-user): only TOTP accounts are supported",
            result.stderr,
        )
        self.assertIn("Secrets are hidden", result.stderr)
        self.assert_no_secrets(result.everything)

    def test_json_shows_metadata_only(self) -> None:
        result = run("decode", "--json")
        rows = json.loads(result.stdout)
        self.assertEqual(
            rows[1],
            {"issuer": "Other", "name": "bob", "algorithm": "SHA256", "digits": 8, "period": 60},
        )
        self.assert_no_secrets(result.everything)

    def test_reveal_shows_secrets_with_warning(self) -> None:
        result = run("decode", "--json", "--reveal")
        self.assertEqual(result.code, 0)
        self.assertIn("warning: --reveal prints TOTP secrets", result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(rows[0]["secret"], secret_forms(SYNTHETIC_SECRET)[0])
        self.assertEqual(parse_otpauth_uri(rows[1]["uri"]).secret, SECOND_SECRET)
        self.assertRegex(rows[0]["code"], r"^\d{6}$")
        self.assertNotIn("secret=", result.stderr)

    def test_same_account_on_two_lines_is_kept_once(self) -> None:
        twin = OTPAUTH_URI.replace("algorithm=SHA256", "algorithm=sha256")
        result = run("decode", stdin=f"{OTPAUTH_URI}\n{twin}\n")
        self.assertEqual(result.code, 0)
        self.assertIn("1 account(s), 1 duplicate account(s) kept once.", result.stderr)
        self.assertEqual(result.stdout.count("bob"), 1)

    def test_bom_at_any_line_start_is_ignored(self) -> None:
        result = run("decode", stdin=f"\ufeff{GA_URI}\n\ufeff{OTPAUTH_URI}\n")
        self.assertEqual(result.code, 0, result.stderr)
        self.assertIn("2 account(s)", result.stderr)

    def test_reads_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "input.txt")
            path.write_text(INPUT, encoding="utf-8")
            result = run("decode", str(path), stdin="")
        self.assertEqual(result.code, 0)
        self.assertIn("bob", result.stdout)


class ExportTests(RedactionTestCase):
    def test_refuses_terminal_without_reveal(self) -> None:
        for extra in ([], ["-o", "-"]):
            with self.subTest(extra=extra):
                result = run("export", "-f", "otpauth", "--skip-unsupported", *extra)
                self.assertEqual(result.code, 1)
                self.assertIn("refusing to write secrets to the terminal", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_reveal_writes_stdout(self) -> None:
        result = run("export", "-f", "otpauth", "--skip-unsupported", "--reveal")
        self.assertEqual(result.code, 0)
        self.assertIn("warning: --reveal", result.stderr)
        accounts = [parse_otpauth_uri(line) for line in result.stdout.splitlines()]
        self.assertEqual({account.secret for account in accounts}, set(ALL_SECRETS))
        self.assertNotIn("secret=", result.stderr)

    def test_writes_private_file_and_stays_quiet(self) -> None:
        for name in ("1password", "aegis", "bitwarden", "json", "otpauth"):
            with self.subTest(format=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory, "out")
                result = run("export", "-f", name, "-o", str(path), "--skip-unsupported")
                self.assertEqual(result.code, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assert_no_secrets(result.everything)
                if os.name == "posix":
                    self.assertIn("readable only by you", result.stderr)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertIn(secret_forms(SECOND_SECRET)[0], path.read_text(encoding="utf-8"))

    def test_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "existing.json")
            path.write_text("keep me", encoding="utf-8")
            result = run("export", "-f", "json", "-o", str(path), "--skip-unsupported")
            self.assertEqual(result.code, 1)
            self.assertIn("already exists", result.stderr)
            self.assertEqual(path.read_text(encoding="utf-8"), "keep me")

    def test_unsupported_accounts_block_export_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "out.json")
            result = run("export", "-f", "json", "-o", str(path))
            self.assertEqual(result.code, 1)
            self.assertIn("(Example:hotp-user): only TOTP", result.stderr)
            self.assertIn("--skip-unsupported", result.stderr)
            self.assertFalse(path.exists())
            self.assert_no_secrets(result.everything)

    def test_empty_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run("export", "-f", "json", "-o", str(Path(directory, "x")), stdin="\n")
        self.assertEqual(result.code, 1)
        self.assertIn("no accounts to export", result.stderr)


class SafetyTests(RedactionTestCase):
    def test_uris_in_argv_are_refused(self) -> None:
        for argv in (["decode", OTPAUTH_URI], ["decode", "--json", GA_URI], ["x://y"]):
            with self.subTest(argv=argv[-1][:12]):
                result = run(*argv)
                self.assertEqual(result.code, 2)
                self.assertIn("not as arguments", result.stderr)
                self.assert_no_secrets(result.everything)

    def test_parse_errors_name_the_line_not_the_content(self) -> None:
        broken = OTPAUTH_URI.replace("secret=", "secret=1") + "\n"
        result = run("decode", stdin=f"{GA_URI}\n{broken}")
        self.assertEqual(result.code, 1)
        self.assertIn("line 2:", result.stderr)
        self.assert_no_secrets(result.everything)

    def test_junk_line_is_not_echoed(self) -> None:
        secret_like = secret_forms(SECOND_SECRET)[0]
        result = run("decode", stdin=secret_like + "\n")
        self.assertEqual(result.code, 1)
        self.assertIn("line 1: expected an otpauth", result.stderr)
        self.assertNotIn(secret_like, result.everything)

    def test_incomplete_google_export(self) -> None:
        first_of_two = ga_uri(ga_payload(ga_account(), batch_size=2, batch_index=0))
        result = run("decode", stdin=first_of_two)
        self.assertEqual(result.code, 1)
        self.assertIn("expected QR codes 1-2 exactly once, got 1", result.stderr)

    def test_unexpected_errors_hide_details(self) -> None:
        with mock.patch.object(cli, "read_accounts", side_effect=ValueError(OTPAUTH_URI)):
            result = run("decode")
        self.assertEqual(result.code, 1)
        self.assertIn("unexpected ValueError; details hidden", result.stderr)
        self.assert_no_secrets(result.everything)

    def test_redaction_guard_blocks_a_leaking_bug(self) -> None:
        leaky = mock.patch.object(
            cli, "_table", return_value=secret_forms(SYNTHETIC_SECRET)[0] + "\n"
        )
        with leaky:
            result = run("decode")
        self.assertEqual(result.code, 1)
        self.assertIn("refusing to print output that contains secret material", result.stderr)
        self.assert_no_secrets(result.everything)

    def test_terminal_input_is_refused_because_it_echoes(self) -> None:
        result = run("decode", tty=True)
        self.assertEqual(result.code, 1)
        self.assertIn("refusing to read URIs from the terminal", result.stderr)

    def test_argparse_errors_hide_mistyped_values(self) -> None:
        secret_like = secret_forms(SECOND_SECRET)[0]
        for argv in (["export", "-f", secret_like], ["decode", f"--bogus={secret_like}"]):
            with self.subTest(argv=argv[1]):
                result = run(*argv)
                self.assertEqual(result.code, 2)
                self.assertIn("<hidden>", result.stderr)
                self.assert_no_secrets(result.everything)

    def test_uri_hidden_in_a_label_is_not_printed(self) -> None:
        # Codex review repro: the label is a whole percent-encoded URI, and the
        # account is skipped (period=0), so its label would be printed.
        secret = secret_forms(SECOND_SECRET)[0]
        label = urllib.parse.quote(OTPAUTH_URI, safe="")
        uri = f"otpauth://totp/{label}?secret={secret}&period=0"
        result = run("decode", stdin=uri + "\n")
        self.assertEqual(result.code, 0)
        self.assertIn("skipped line 1 (name hidden): period must be", result.stderr)
        self.assert_no_secrets(result.everything)

    def test_skipped_label_holding_its_own_secret_is_hidden(self) -> None:
        secret = secret_forms(SECOND_SECRET)[0]
        uri = f"otpauth://hotp/Example:{secret}?secret={secret}"
        result = run("export", "-f", "json", "-o", "unused", stdin=uri + "\n")
        self.assertIn("(name hidden)", result.stderr)
        self.assert_no_secrets(result.everything)

    def test_respelled_secret_in_a_label_is_caught(self) -> None:
        secret = secret_forms(SECOND_SECRET)[0]
        hyphenated = "-".join(secret[i : i + 4] for i in range(0, len(secret), 4))
        uri = f"otpauth://totp/Example:{hyphenated}?secret={secret}"
        for argv in (["decode"], ["decode", "--json"]):
            with self.subTest(argv=argv):
                result = run(*argv, stdin=uri + "\n")
                self.assertEqual(result.code, 1)
                self.assertIn("refusing to print", result.stderr)
                self.assertNotIn(hyphenated, result.everything)

    def test_json_escaped_raw_secret_is_caught(self) -> None:
        raw = b'ab"cd\\efghijk'
        b32 = secret_forms(raw)[0]
        uri = f"otpauth://totp/Example:{urllib.parse.quote(raw)}?secret={b32}"
        result = run("decode", "--json", stdin=uri + "\n")
        self.assertEqual(result.code, 1)
        self.assertIn("refusing to print", result.stderr)
        self.assertNotIn("efghijk", result.everything)

    def test_package_imports_no_networking_modules(self) -> None:
        forbidden = {"socket", "ssl", "http", "urllib.request", "ftplib", "smtplib", "asyncio"}
        package = Path(cli.__file__).parent
        for source in package.glob("*.py"):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
                else:
                    continue
                for name in names:
                    with self.subTest(file=source.name, module=name):
                        self.assertNotIn(name, forbidden)
                        self.assertNotIn(name.split(".")[0], forbidden - {"urllib.request"})

    def test_account_repr_hides_the_secret(self) -> None:
        text = repr(TotpAccount("alice", "Example", SYNTHETIC_SECRET))
        self.assertIn("alice", text)
        self.assert_no_secrets(text)
        self.assertNotIn(repr(SYNTHETIC_SECRET), text)

    def test_invalid_utf8_input(self) -> None:
        fake_stdin = io.TextIOWrapper(io.BytesIO(b"\xff\xfe\n"))
        stderr = io.StringIO()
        with mock.patch("sys.stdin", fake_stdin), redirect_stderr(stderr):
            self.assertEqual(cli.main(["decode"]), 1)
        self.assertIn("not valid UTF-8", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
