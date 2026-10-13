# Security

## What this tool promises

1. **No network.** The package imports no networking modules, and a test
   enforces that. The CLI tests also run with `socket.socket` disabled.
2. **Nothing secret on screen by default.** Without `--reveal`, stdout and
   stderr carry only issuer, account name, algorithm, digits and period,
   plus fixed error and status text. Every line that mentions an account
   passes `redaction.Redactor`, which refuses output that
   contains any secret seen in the input (including skipped accounts) in
   base32, hex, base64 or raw form: matched exactly, with separators
   removed, and reduced to letters and digits. It also refuses `otpauth`
   URI markers. A skipped account whose name trips the check is reported
   by position only. The guard exists to catch the tool's own bugs and
   accidental label contents, such as an export whose name field holds
   the secret. Someone who crafts a QR code already knows its secret.
3. **No secrets in argv or on an echoing terminal.** URIs are read from a
   file or a pipe. The CLI refuses arguments that look like URIs (shell
   history, process list), replies to usage errors with the usage line
   instead of echoing the value, and refuses to read from an interactive
   terminal (echo, scrollback).
4. **No secrets in errors or notes.** Error messages give positions (line,
   account) and fixed reasons, never input text. The output path is not
   printed back. Unexpected exceptions print only their type. `TotpAccount` and `SkippedAccount` omit the secret from
   `repr()`.
5. **Careful files.** Export files are created with `O_EXCL | O_NOFOLLOW`
   and never overwrite an existing file. On Linux and macOS they get mode
   `0600`. **On Windows the mode is ignored** and the file inherits its
   folder's permissions.
6. **No spoofed names.** Names and issuers with control, format (bidi
   override, zero-width), separator or private-use characters are rejected.
7. **Strict parsing.** Unknown or repeated protobuf fields, wrong wire types,
   overlong varints, invalid percent escapes or UTF-8, unknown payload
   versions and incomplete multi-QR exports are errors, as are secrets
   shorter than 64 bits. Declared batch sizes are never used to allocate
   memory. `export` validates every message it will print before it
   creates the file.
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
