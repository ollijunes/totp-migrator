# totp-migrator

## Goal

A dependency-free, offline Python CLI that reads Google Authenticator export QR data (`otpauth-migration://`) and `otpauth://` URIs and writes import files for 1Password, Bitwarden/Vaultwarden, Aegis, LastPass and Proton Pass, for anyone who wants their 2FA secrets out of Google without pasting them into a website. A change is finished when the unit tests pass, the exported file imports into the target app, and no secret is printed without `--reveal`.

## Environments

Local only: `python3 -m totp_migrator` from a clone, or `pipx install git+https://github.com/ollijunes/totp-migrator`. CI runs the tests and ruff on GitHub Actions (`.github/workflows/ci.yml`); the `integration/` scripts start a throwaway Vaultwarden or Proton Pass reader locally.

## Manual checks

Import an exported file into the real target app (Bitwarden web vault, `op item create`, Aegis, LastPass, Proton Pass) and compare a few one-time codes between Google Authenticator and the new app; they must match for the same 30-second window. Check that terminal output, error messages and the demo never show a secret, a migration URI or a current code.
