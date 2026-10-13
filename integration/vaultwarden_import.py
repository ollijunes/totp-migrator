"""End-to-end import test against a real Vaultwarden, using the official Bitwarden CLI.

    integration/start_vaultwarden.sh /tmp/vw 8443
    NODE_EXTRA_CA_CERTS=/tmp/vw/ssl/cert.pem \
        python integration/vaultwarden_import.py --server https://127.0.0.1:8443 --bw bw

1. Builds synthetic accounts (random secrets, never real ones) with default
   and non-default parameters.
2. Exports them with totp-migrator to Bitwarden JSON and LastPass CSV.
3. Registers a throwaway Vaultwarden user, logs in with `bw`, imports both
   files with Bitwarden's own importers (`bitwardenjson`, `lastpasscsv`).
4. Asks `bw get totp` for every imported item and compares the code with
   totp-migrator's own RFC 6238 implementation.

This script is for CI. It needs the `cryptography` package to create the
user the way Bitwarden clients do; totp-migrator itself has no dependencies.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import shlex
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from totp_migrator.model import TotpAccount  # noqa: E402
from totp_migrator.otpauth import build_otpauth_uri  # noqa: E402
from totp_migrator.totp import current_code  # noqa: E402

KDF_ITERATIONS = 600_000


def synthetic_accounts() -> list[TotpAccount]:
    def secret() -> bytes:
        return secrets.token_bytes(20)

    return [
        TotpAccount("alice@example.org", "GitHub", secret()),
        TotpAccount("admin", "Home Assistant", secret()),
        TotpAccount("käyttäjä", "Ääkköset Oy", secret()),
        TotpAccount("ops", "Legacy VPN", secret(), "SHA256", 8, 60),
        TotpAccount("root", "Router", secret(), "SHA512", 6, 30),
    ]


# --- Bitwarden client-side key setup -------------------------------------------------


def _enc_string(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> str:
    """Bitwarden "type 2" encryption: AES-256-CBC with HMAC-SHA256."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    parts = (base64.b64encode(value).decode() for value in (iv, ciphertext, mac))
    return "2." + "|".join(parts)


def _expand(key: bytes, info: bytes) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(key)


def register(server: str, email: str, password: str) -> None:
    master_key = hashlib.pbkdf2_hmac("sha256", password.encode(), email.encode(), KDF_ITERATIONS)
    password_hash = hashlib.pbkdf2_hmac("sha256", master_key, password.encode(), 1)
    stretched_enc, stretched_mac = _expand(master_key, b"enc"), _expand(master_key, b"mac")

    user_key = os.urandom(64)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # With mail disabled, Vaultwarden returns the verification token directly.
    token = _post(
        server,
        "/identity/accounts/register/send-verification-email",
        {
            "email": email,
            "name": "ci",
        },
    )
    _post(
        server,
        "/identity/accounts/register/finish",
        {
            "email": email,
            "emailVerificationToken": token,
            "masterPasswordHash": base64.b64encode(password_hash).decode(),
            "masterPasswordHint": None,
            "userSymmetricKey": _enc_string(stretched_enc, stretched_mac, user_key),
            "userAsymmetricKeys": {
                "publicKey": base64.b64encode(public_der).decode(),
                "encryptedPrivateKey": _enc_string(user_key[:32], user_key[32:], private_der),
            },
            "kdf": 0,
            "kdfIterations": KDF_ITERATIONS,
        },
    )


def _post(server: str, path: str, body: dict) -> object:
    request = urllib.request.Request(
        server.rstrip("/") + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    context = ssl.create_default_context(cafile=os.environ.get("NODE_EXTRA_CA_CERTS"))
    with urllib.request.urlopen(request, timeout=30, context=context) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


# --- Bitwarden CLI ------------------------------------------------------------------


class BitwardenCli:
    def __init__(self, command: str, data_dir: Path) -> None:
        self.command = shlex.split(command)
        self.env = {**os.environ, "BITWARDENCLI_APPDATA_DIR": str(data_dir)}

    def run(self, *args: str) -> str:
        proc = subprocess.run(
            [*self.command, *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            raise SystemExit(f"bw {args[0]} failed: {proc.stderr.strip()[:500]}")
        return proc.stdout.strip()


def item_ids(bw: BitwardenCli) -> set[str]:
    bw.run("sync")
    return {item["id"] for item in json.loads(bw.run("list", "items"))}


def check_codes(bw: BitwardenCli, label: str, expected: dict[str, TotpAccount], ids: set[str]):
    items = {item["id"]: item for item in json.loads(bw.run("list", "items"))}
    by_name = {items[item_id]["name"]: item_id for item_id in ids}
    failures = []
    for title, account in expected.items():
        item_id = by_name.get(title)
        if item_id is None:
            failures.append(f"{label}: {title}: not imported")
            continue
        before = int(time.time())
        code = bw.run("get", "totp", item_id)
        after = int(time.time())
        valid = {current_code(account, t) for t in (before, after)}
        if code not in valid:
            failures.append(f"{label}: {title}: code mismatch")
        else:
            print(
                f"ok  {label}: {title} ({account.algorithm}, {account.digits}, {account.period}s)"
            )
    if len(ids) != len(expected):
        failures.append(f"{label}: imported {len(ids)} items, expected {len(expected)}")
    return failures


def export(fmt: str, input_path: Path, output: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "totp_migrator",
            "export",
            "-f",
            fmt,
            "-o",
            str(output),
            "--skip-unsupported",
            str(input_path),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--bw", default="bw", help="command that runs the Bitwarden CLI")
    args = parser.parse_args()

    accounts = synthetic_accounts()
    email = f"ci-{secrets.token_hex(4)}@example.org"
    password = secrets.token_urlsafe(24)

    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        input_path = work / "accounts.txt"
        input_path.write_text("".join(build_otpauth_uri(a) + "\n" for a in accounts))
        export("bitwarden", input_path, work / "vault.json")
        export("lastpass", input_path, work / "lastpass.csv")

        register(args.server, email, password)
        bw = BitwardenCli(args.bw, work / "bw")
        bw.run("config", "server", args.server)
        bw.env["BW_PASSWORD"] = password
        bw.env["BW_SESSION"] = bw.run("login", email, "--passwordenv", "BW_PASSWORD", "--raw")
        print("bw", bw.run("--version"), "against", args.server)

        failures = []
        before = item_ids(bw)
        bw.run("import", "bitwardenjson", str(work / "vault.json"))
        after_json = item_ids(bw)
        expected = {account.title: account for account in accounts}
        failures += check_codes(bw, "bitwarden", expected, after_json - before)

        bw.run("import", "lastpasscsv", str(work / "lastpass.csv"))
        after_csv = item_ids(bw)
        defaults = {
            account.title: account
            for account in accounts
            if (account.algorithm, account.digits, account.period) == ("SHA1", 6, 30)
        }
        failures += check_codes(bw, "lastpass csv", defaults, after_csv - after_json)

    for failure in failures:
        print("FAIL", failure)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
