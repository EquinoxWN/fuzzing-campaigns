"""Reader for AFL/libFuzzer dictionary files, so one file serves this engine and Atheris.

Each non-blank, non-comment line is ``name="token"`` or ``"token"``. Inside the quotes, ``\\\\``,
``\\"`` and ``\\xHH`` are escapes; every other byte must be printable ASCII.
"""

from __future__ import annotations

import re
from pathlib import Path

MAX_TOKEN = 128
MAX_TOKENS = 1000
MAX_FILE = 256 * 1024
_LINE = re.compile(r'(?:[A-Za-z0-9_]+\s*=\s*)?"(?P<body>.*)"')


class DictionaryError(ValueError):
    """A malformed dictionary file, with the line number."""


def parse_dictionary(text: str) -> list[bytes]:
    """Tokens of a dictionary, in file order, without duplicates."""
    tokens: list[bytes] = []
    seen: set[bytes] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _LINE.fullmatch(stripped)
        if m is None:
            raise DictionaryError(f'line {number}: expected name="token" or "token"')
        token = _unescape(m.group("body"), number)
        if not 1 <= len(token) <= MAX_TOKEN:
            raise DictionaryError(f"line {number}: token must be 1 to {MAX_TOKEN} bytes")
        if token not in seen:
            seen.add(token)
            tokens.append(token)
        if len(tokens) > MAX_TOKENS:
            raise DictionaryError(f"more than {MAX_TOKENS} tokens")
    return tokens


def _unescape(body: str, number: int) -> bytes:
    """Decode the escapes inside one quoted token."""
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if not (" " <= ch <= "~"):
            raise DictionaryError(f"line {number}: non-printable or non-ASCII character; use \\xHH")
        if ch == '"':
            raise DictionaryError(f'line {number}: unescaped " inside a token')
        if ch != "\\":
            out.append(ord(ch))
            i += 1
            continue
        nxt = body[i + 1 : i + 2]
        if nxt in ("\\", '"'):
            out.append(ord(nxt))
            i += 2
        elif nxt == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", body[i + 2 : i + 4]):
            out.append(int(body[i + 2 : i + 4], 16))
            i += 4
        else:
            raise DictionaryError(f'line {number}: bad escape (use \\\\, \\" or \\xHH)')
    return bytes(out)


def load_dictionary(path: Path) -> list[bytes]:
    """Read and parse a dictionary file, refusing files over MAX_FILE bytes."""
    size = path.stat().st_size
    if size > MAX_FILE:
        raise DictionaryError(f"{path}: {size} bytes is over the {MAX_FILE}-byte limit")
    try:
        text = path.read_bytes().decode("ascii")
    except UnicodeDecodeError as exc:
        raise DictionaryError(f"{path}: not ASCII (byte {exc.start}); use \\xHH escapes") from exc
    return parse_dictionary(text)
