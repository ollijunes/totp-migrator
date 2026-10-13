# Security

## What this tool promises

1. **No network.** The package imports no networking modules, and a test
   enforces that. The CLI tests also run with `socket.socket` disabled.
2. **Nothing secret on screen by default.** Without `--reveal`, stdout and
   stderr carry only issuer, account name, algorithm, digits and period.
   Every line passes `redaction.ensure_redacted`, which refuses output that
   contains a secret in base32, hex, base64 or raw form, or an `otpauth`
   URI marker.
3. **No secrets in argv.** URIs are read from a file or stdin. The CLI
   refuses arguments that look like URIs, because arguments are visible in
   shell history and to other local users through the process list.
4. **No secrets in errors.** Error messages name a line number and a reason,
   never the input text. Unexpected exceptions print only their type.
   `TotpAccount.__repr__` omits the secret.
5. **Careful files.** Export files are created with `O_EXCL | O_NOFOLLOW`
   and mode `0600`. An existing file is never overwritten.
6. **Strict parsing.** Unknown or repeated protobuf fields, wrong wire types,
   unknown payload versions and incomplete multi-QR exports are errors.
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
