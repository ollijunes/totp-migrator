# Security

## What this tool promises

1. **No network.** The package imports no networking modules, and a test
   enforces that. The CLI tests also run with `socket.socket` disabled.
2. **Nothing secret on screen by default.** Without `--reveal`, stdout and
   stderr carry only issuer, account name, algorithm, digits and period.
   Every line passes `redaction.ensure_redacted`, which refuses output that
   contains any secret seen in the input (including skipped accounts) in
   base32, hex, base64 or raw form, ignoring case and separators, or an
   `otpauth` URI marker. A skipped account whose name trips the check is
   reported by position only.
3. **No secrets in argv or on an echoing terminal.** URIs are read from a
   file or a pipe. The CLI refuses arguments that look like URIs (shell
   history, process list), hides argument values in usage errors, and
   refuses to read from an interactive terminal (echo, scrollback).
4. **No secrets in errors.** Error messages give positions (line, account)
   and fixed reasons, never input text. Unexpected exceptions print only
   their type. `TotpAccount` and `SkippedAccount` omit the secret from
   `repr()`.
5. **Careful files.** Export files are created with `O_EXCL | O_NOFOLLOW`
   and never overwrite an existing file. On Linux and macOS they get mode
   `0600`. **On Windows the mode is ignored** and the file inherits its
   folder's permissions.
6. **No spoofed names.** Names and issuers with control, format (bidi
   override, zero-width), separator or private-use characters are rejected.
7. **Strict parsing.** Unknown or repeated protobuf fields, wrong wire types,
   overlong varints, invalid percent escapes or UTF-8, unknown payload
   versions and incomplete multi-QR exports are errors. Declared batch
   sizes are never used to allocate memory.
   Unsupported but well-formed accounts (HOTP, MD5) are listed by name and
   block `export` unless `--skip-unsupported` is given.

## What it cannot protect

- The export file, once written. It is plaintext by design, because that is
  what the target apps import. Import it, then delete it.
- QR images, screenshots or URI files you created to feed the tool.
- Terminal scrollback and logs after you use `--reveal`.
- A compromised machine. If malware runs as your user, it can read
  everything this tool reads.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). Do not open a public issue.

Never include a real QR code, URI, secret or export file in any report.
Describe the field layout, or build a synthetic payload with
`tests/fixtures.py`.
