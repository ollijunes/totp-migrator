"""Local-first TOTP migrator.

Reads Google Authenticator migration payloads and otpauth:// URIs, then
exports the accounts for 1Password, Bitwarden/Vaultwarden, Aegis, or as
plain otpauth:// URIs. Nothing leaves the machine.
"""

__version__ = "0.2.0"
