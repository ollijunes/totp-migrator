# T1 README: link the blog post; keep ledger tooling out of language stats

- Status: doing
- Lane: docs/blog-link-language-20261020
- Evidence: —

## Plan

Goal: people who land on the repository can find the project story, and GitHub shows the project as Python.

- Add a short line near the top of README.md linking https://ollijunes.com/totp-migrator-google-authenticator/ (English) and https://ollijunes.com/fi/totp-migrator-google-authenticator-siirto/ (Finnish).
- Mark `ledger/**` as `linguist-vendored` in .gitattributes. The ledger tooling (`ledger/scripts/records.mjs`, ~380 KB of JavaScript) currently makes GitHub report the repository as JavaScript, although the package is Python.

Checks: both URLs return 200; `python3 -m unittest` still passes; after merge the repository language shows Python.
