"""Render docs/demo.svg from a real run of the CLI on synthetic accounts.

    python3 docs/render_demo.py

Every line in the image is the tool's actual output. The accounts are
synthetic: random secrets generated here and never written to disk except
inside a temporary directory that is removed afterwards.
"""

from __future__ import annotations

import base64
import html
import os
import secrets
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from totp_migrator.protobuf import encode_field  # noqa: E402

FONT_SIZE = 14
LINE_HEIGHT = 21
# The viewer's monospace font decides the real width: Menlo is 8.4 px at
# 14 px, SF Mono up to 9.6. This leaves room for either.
CHAR_WIDTH = 9.2
PADDING_X = 22
TOP = 56
COLUMNS = 84

COLORS = {
    "background": "#0d1117",
    "chrome": "#161b22",
    "border": "#30363d",
    "text": "#e6edf3",
    "dim": "#8b949e",
    "prompt": "#3fb950",
    "warn": "#d29922",
    "header": "#79c0ff",
}


def ga_account(name: str, issuer: str, otp_type: int = 2) -> bytes:
    return b"".join(
        [
            encode_field(1, secrets.token_bytes(20)),
            encode_field(2, name.encode()),
            encode_field(3, issuer.encode()),
            encode_field(4, 1),
            encode_field(5, 1),
            encode_field(6, otp_type),
        ]
    )


def ga_uri(*accounts: bytes, index: int, size: int, batch_id: int) -> str:
    payload = b"".join(encode_field(1, account) for account in accounts)
    payload += encode_field(2, 1) + encode_field(3, size) + encode_field(5, batch_id)
    if index:
        payload += encode_field(4, index)
    data = base64.b64encode(payload).decode()
    return "otpauth-migration://offline?data=" + urllib.parse.quote(data, safe="")


def synthetic_input() -> str:
    return "\n".join(
        [
            ga_uri(
                ga_account("alice@example.org", "GitHub"),
                ga_account("alice", "Nextcloud"),
                index=0,
                size=2,
                batch_id=7,
            ),
            ga_uri(
                ga_account("admin", "Home Assistant"),
                ga_account("ops", "Legacy VPN", otp_type=1),
                index=1,
                size=2,
                batch_id=7,
            ),
        ]
    )


def run(args: list[str], stdin: str, cwd: Path) -> list[tuple[str, str]]:
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(
        [sys.executable, "-m", "totp_migrator", *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        check=True,
    )
    lines = [
        (line, "header" if line.startswith("ISSUER") else "text")
        for line in proc.stdout.splitlines()
    ]
    for line in proc.stderr.splitlines():
        lines.append((line, "warn" if line.startswith("skipped") else "dim"))
    return lines


def wrap(lines: list[tuple[str, str]]) -> list[tuple[str, str]]:
    wrapped = []
    for text, style in lines:
        while len(text) > COLUMNS:
            cut = text.rfind(" ", 0, COLUMNS)
            cut = cut if cut > 0 else COLUMNS
            wrapped.append((text[:cut], style))
            text = "  " + text[cut:].lstrip()
        wrapped.append((text, style))
    return wrapped


def transcript() -> list[tuple[str, str]]:
    commands = [
        ("pbpaste | totp-migrator decode", ["decode"]),
        (
            "pbpaste | totp-migrator export -f bitwarden -o vault.json --skip-unsupported",
            ["export", "-f", "bitwarden", "-o", "vault.json", "--skip-unsupported"],
        ),
    ]
    stdin = synthetic_input()
    lines: list[tuple[str, str]] = []
    with tempfile.TemporaryDirectory() as directory:
        for shown, args in commands:
            if lines:
                lines.append(("", "text"))
            lines.append((shown, "command"))
            lines.extend(run(args, stdin, Path(directory)))
    return wrap(lines)


ALT_TEXT = (
    "totp-migrator decoding a Google Authenticator export and writing "
    "a Bitwarden import file, with secrets hidden"
)
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
SANS = "ui-sans-serif, -apple-system, Segoe UI, sans-serif"


def render_line(text: str, style: str, y: int) -> str:
    escaped = html.escape(text)
    if style == "command":
        prompt = f'<tspan fill="{COLORS["prompt"]}">$</tspan>'
        command = f'<tspan fill="{COLORS["text"]}" font-weight="600">{escaped}</tspan>'
        return f'<text x="{PADDING_X}" y="{y}">{prompt} {command}</text>'
    weight = ' font-weight="600"' if style == "header" else ""
    return (
        f'<text x="{PADDING_X}" y="{y}" fill="{COLORS[style]}"{weight} '
        f'xml:space="preserve">{escaped}</text>'
    )


def render(lines: list[tuple[str, str]]) -> str:
    width = round(PADDING_X * 2 + COLUMNS * CHAR_WIDTH)
    height = TOP + LINE_HEIGHT * (len(lines) - 1) + 24
    rows = [
        render_line(text, style, TOP + LINE_HEIGHT * number)
        for number, (text, style) in enumerate(lines)
    ]
    dots = [
        f'<circle cx="{22 + 20 * i}" cy="18" r="6" fill="{color}"/>'
        for i, color in enumerate(("#ff5f57", "#febc2e", "#28c840"))
    ]
    title_bar = (
        f'<path d="M10 0.5h{width - 20}a9.5 9.5 0 0 1 9.5 9.5v26h-{width - 1}'
        f'v-26a9.5 9.5 0 0 1 9.5-9.5z" fill="{COLORS["chrome"]}"/>'
    )
    title = (
        f'<text x="{width / 2}" y="23" fill="{COLORS["dim"]}" font-family="{SANS}" '
        f'font-size="13" text-anchor="middle">totp-migrator</text>'
    )
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{ALT_TEXT}">',
        f'<rect width="{width}" height="{height}" rx="10" '
        f'fill="{COLORS["background"]}" stroke="{COLORS["border"]}"/>',
        title_bar,
        *dots,
        title,
        f'<g font-family="{MONO}" font-size="{FONT_SIZE}">',
        *rows,
        "</g>",
        "</svg>",
    ]
    return "\n".join(parts) + "\n"


if __name__ == "__main__":
    output = ROOT / "docs" / "demo.svg"
    output.write_text(render(transcript()), encoding="utf-8")
    print(f"wrote {output.relative_to(ROOT)}")
