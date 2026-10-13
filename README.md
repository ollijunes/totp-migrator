# totp-migrator

Move your two-factor (TOTP) accounts out of Google Authenticator, or out of
any `otpauth://` URIs, into 1Password, Bitwarden/Vaultwarden, or Aegis,
without sending them anywhere.

- **Offline.** No network code. The tool reads a file or stdin and writes a file.
- **Secrets hidden by default.** Output shows issuer, account name and
  parameters. Secrets, URIs and current codes appear only with `--reveal`.
- **Strict.** An unknown protobuf field, a missing QR code from a multi-QR
  export, or a malformed URI stops the run instead of being guessed at.
- **No dependencies.** Python 3.10+ standard library only.

## Install

```sh
pipx install git+https://github.com/ollijunes/totp-migrator
```

Or run it from a clone without installing anything:

```sh
git clone https://github.com/ollijunes/totp-migrator
cd totp-migrator
python3 -m totp_migrator --help
```

## 1. Get the URIs

**Google Authenticator:** open the app, go to *Transfer accounts* →
*Export accounts*, and pick the accounts. The app shows one QR code, or
several for many accounts. Each QR code holds one `otpauth-migration://offline?data=...` URI.

Decode the QR codes on your own machine. For example, with
[zbar](https://github.com/mchehab/zbar) and a photo or screenshot of each code:

```sh
umask 077   # files created from here on are readable only by you
zbarimg --raw -q qr-1.png qr-2.png > accounts.txt
```

**Other apps:** many authenticators can export `otpauth://totp/...` URIs.
Put them in the same file, one per line. Both kinds can be mixed.

Images and text files of QR codes hold your secrets, just like the export
files below. Delete them when you are done.

## 2. Check what was read

```sh
totp-migrator decode accounts.txt
```

```
ISSUER   NAME                ALGORITHM  DIGITS  PERIOD
Example  alice@example.test  SHA1       6       30
GitLab   alice               SHA1       6       30
2 account(s) from 2 Google Authenticator QR code(s).
skipped Legacy:bob: only TOTP accounts are supported (this is HOTP or unknown)
Secrets are hidden. Add --reveal to show them.
```

Without a file argument, the tool reads a pipe, for example straight from
the clipboard:

```sh
pbpaste | totp-migrator decode            # macOS
wl-paste | totp-migrator decode           # Linux, Wayland
```

It refuses to read from an interactive terminal, because pasted URIs would
be echoed on screen and stay in the scrollback. It also refuses URIs as
command-line arguments, which end up in shell history.

## 3. Export

`export` writes a new file and never overwrites an existing one. On Linux
and macOS the file is readable only by you (mode `0600`); on Windows it
gets the permissions of its folder, so write it inside your user profile.
`export` refuses to write secrets to the terminal unless you add `--reveal`.

### 1Password

```sh
totp-migrator export -f 1password -o items.jsonl accounts.txt

while IFS= read -r item; do
  printf '%s\n' "$item" | op item create --vault Private -
done < items.jsonl
```

Each line is a 1Password item template (a Login with a one-time password
field). The 1Password CLI reads the template from stdin, so the secret never
appears in a process argument. Add `--dry-run` to the `op` command to preview
first.

### Bitwarden and Vaultwarden

```sh
totp-migrator export -f bitwarden -o bitwarden.json accounts.txt
```

In the web vault, open **Tools → Import data**, choose the format
**Bitwarden (json)**, and select `bitwarden.json`. This works the same for
a self-hosted Vaultwarden server. With the Bitwarden CLI:

```sh
bw import bitwardenjson bitwarden.json
```

Each account becomes a Login item with the username and an authenticator
key (a full `otpauth://` URI, so non-default digits, periods and algorithms
survive).

### Aegis

```sh
totp-migrator export -f aegis -o aegis.json accounts.txt
```

Copy the file to your phone, open Aegis's import screen (under
**Settings → Import & Export**), pick **Aegis** as the source app, and
select the file. It is an unencrypted Aegis vault.

### Plain URIs or JSON

```sh
totp-migrator export -f otpauth -o accounts.uris accounts.txt
totp-migrator export -f json -o accounts.json accounts.txt
```

`otpauth` writes one URI per line with every parameter spelled out, for any
app that accepts them. `json` writes issuer, name, base32 secret, algorithm,
digits, period and URI for each account, for your own scripts.

### After the import

1. Compare a few codes in the new app with the old one. `decode --reveal`
   prints the current code for each account if you want a third opinion.
2. Delete the export file and the QR images or URI file.
3. Only then remove the accounts from the old app.

## What is supported

| Input | Notes |
|---|---|
| `otpauth-migration://offline?data=...` | Google Authenticator export, versions 1 and 2, single or multi-QR. All QR codes of a multi-QR export must be present. |
| `otpauth://totp/...` | [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format): SHA1/SHA256/SHA512, 6-8 digits, any period up to an hour. |

Secrets must be 10-256 bytes (80 bits or more). HOTP (counter-based) accounts, MD5, shorter secrets
and other unusual parameters are reported as unsupported, with the
account's position and name. `export` stops when it finds one. Pass
`--skip-unsupported` to export the rest and move those accounts by hand.

Google Authenticator's export carries no period, so those accounts get
30 seconds, which is what the app itself uses.

The output formats follow each app's own unencrypted export format. The
tests check their structure, not an import into every app version, so
compare a few codes after importing, and please open an issue if an app
rejects a file.

The Google export format has no published schema. The field numbers here
match two independent reverse-engineered descriptions: Aegis's
`google_auth.proto` and qistoph's `OtpMigration.proto`.

## Privacy model

Read [SECURITY.md](SECURITY.md) for the full list. In short:

- No network access. A test fails if any module imports a networking
  library, and the CLI tests run with sockets disabled.
- Without `--reveal`, every line the tool prints first passes a check that
  refuses output containing any secret in base32, hex, base64 or raw form
  (ignoring case, spaces, hyphens and escapes), or any `otpauth` URI. A bug
  that pulled a secret into a message would fail instead of printing it.
- Error messages give the line and account number and a fixed reason,
  never input text. Mistyped argument values are hidden too.
- Account names with control, bidi-override or zero-width characters are
  rejected, so a crafted QR code can't disguise one account as another.
- Account objects hide the secret from `repr()`, so it cannot appear in a
  traceback or log line. Unexpected exceptions print only their type.
- Export files are created with `O_EXCL`, and with mode `0600` on Linux
  and macOS.

What the tool cannot protect: the export files themselves, the QR images,
your terminal scrollback after `--reveal`, and the apps you import into.

## Development

```sh
python3 -m unittest          # all tests, standard library only
```

Tests use only synthetic secrets and the published RFC 4226 and RFC 6238
test vectors. Never commit a real QR code, URI or export file, not even in
an issue. If you need to report a parsing bug, describe the field layout or
build a synthetic payload with `tests/fixtures.py`.

## License

MIT
