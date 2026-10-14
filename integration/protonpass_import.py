"""Replays the Proton Pass generic CSV import with the packages Proton Pass uses.

    python integration/protonpass_import.py

Proton Pass has no CLI or self-hosted server to import into, so this test
runs its import path instead: the CSV is parsed with ``papaparse`` and the
``totp`` column with ``otpauth``, the same packages and versions pinned
below as in ProtonMail/WebClients (``packages/pass/package.json``). The
stored URI's parameters and code are compared with totp-migrator's own
RFC 6238 implementation for every synthetic account.

Needs Node and npm. The packages are installed into a temporary directory.
"""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from totp_migrator.model import TotpAccount  # noqa: E402
from totp_migrator.otpauth import build_otpauth_uri  # noqa: E402
from totp_migrator.totp import current_code  # noqa: E402

PACKAGES = ("otpauth@9.5.2", "papaparse@5.7.0")
READER = Path(__file__).with_name("protonpass_reader.mjs")


def synthetic_accounts() -> list[TotpAccount]:
    def secret() -> bytes:
        return secrets.token_bytes(20)

    return [
        TotpAccount("alice@example.org", "GitHub", secret()),
        TotpAccount('name, with "quotes"', "ACME, Inc.", secret()),
        TotpAccount("käyttäjä", "Ääkköset Oy", secret()),
        TotpAccount("ops", "Legacy VPN", secret(), "SHA256", 8, 60),
        TotpAccount("root", "Router", secret(), "SHA512", 6, 30),
        TotpAccount("seven", "", secret(), "SHA1", 7, 45),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--npm", default="npm")
    parser.add_argument("--node", default="node")
    args = parser.parse_args()

    accounts = synthetic_accounts()
    now = int(time.time())
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        input_path = work / "accounts.txt"
        input_path.write_text("".join(build_otpauth_uri(a) + "\n" for a in accounts))
        csv_path = work / "protonpass.csv"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "totp_migrator",
                "export",
                "-f",
                "protonpass",
                "-o",
                str(csv_path),
                str(input_path),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )

        package_dir = work / "reader"
        package_dir.mkdir()
        (package_dir / "package.json").write_text('{"private": true, "type": "module"}\n')
        subprocess.run(
            [args.npm, "install", "--silent", "--no-audit", "--no-fund", *PACKAGES],
            cwd=package_dir,
            check=True,
        )
        shutil.copy(READER, package_dir / READER.name)
        output = subprocess.run(
            [args.node, str(package_dir / READER.name), str(csv_path), str(now)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    rows = [json.loads(line) for line in output.splitlines()]
    failures = []
    if len(rows) != len(accounts):
        failures.append(f"imported {len(rows)} rows, expected {len(accounts)}")
    for account, row in zip(accounts, rows, strict=False):
        expected = {
            "name": account.title,
            "username": account.name,
            "issuer": account.issuer,
            "label": account.name,
            "algorithm": account.algorithm,
            "digits": account.digits,
            "period": account.period,
            "code": current_code(account, now),
        }
        if row != expected:
            failures.append(f"{account.title}: Proton Pass would store {row}, expected {expected}")
    for failure in failures:
        print("FAIL", failure)
    print(f"{len(rows) - len(failures)} of {len(accounts)} accounts match, packages {PACKAGES}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
