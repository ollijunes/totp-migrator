# Contributing

Thanks for helping. This tool handles people's 2FA secrets, so the bar for
changes is careful rather than fast.

## Never share real secrets

Do not paste a real QR code, `otpauth://` or `otpauth-migration://` URI,
secret or export file into an issue, a pull request, a test or a commit.
GitHub keeps edit history. To report a parsing problem, describe the
structure of the input, or build a synthetic payload with
`tests/fixtures.py`.

Security problems go through private vulnerability reporting, not public
issues. See [SECURITY.md](SECURITY.md).

## Setup

Python 3.10 or newer. There are no runtime or test dependencies.

```sh
git clone https://github.com/ollijunes/totp-migrator && cd totp-migrator
python3 -m unittest
```

CI also runs [ruff](https://docs.astral.sh/ruff/) for lint and formatting:

```sh
uvx ruff check . && uvx ruff format --check .
```

## What a good change looks like

- **No new dependencies.** The standard library is part of the privacy
  model: people should be able to read everything they run.
- **No network code.** A test enforces this.
- **Secrets stay out of output.** New messages about accounts go through
  the `Redactor`. Error messages use positions and fixed text, never input.
  Add a test that the new path does not print a secret.
- **Strict over clever.** If the input is not clearly understood, stop and
  say so. Don't guess.
- **New export formats** need a link to the target app's documented format
  in the docstring, and a test of the structure.
- Keep the code plain: small functions, clear names, comments only where
  they explain why.

If you change the CLI output, regenerate the README image with
`python3 docs/render_demo.py`.
