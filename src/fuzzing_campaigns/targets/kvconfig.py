"""INI-style configuration parser: sections, keys, bare and quoted values with escapes.

Format::

    # comment (also ';')
    top = level          # keys before any section go to the "" section
    [server.http]
    port = 8080
    banner = "hello \\"world\\"\\n\\u00e9"

Duplicate sections and duplicate keys in a section are rejected, so a file has exactly one
meaning. ``dump`` writes the canonical form; ``fuzz_one`` checks that ``dump`` round-trips.
"""

from __future__ import annotations

import re

from fuzzing_campaigns.errors import InvariantError, ParseError

MAX_INPUT = 64 * 1024
_NAME = re.compile(r"[A-Za-z0-9_.-]+")
_ESCAPES = {"\\": "\\", '"': '"', "n": "\n", "t": "\t", "r": "\r"}
_REVERSE = {v: k for k, v in _ESCAPES.items()}

Config = dict[str, dict[str, str]]


def parse(text: str) -> Config:
    """Parse configuration text into {section: {key: value}}."""
    if len(text) > MAX_INPUT:
        raise ParseError(f"input longer than {MAX_INPUT} characters")
    config: Config = {"": {}}
    section = ""
    offset = 0
    for line in text.split("\n"):
        start = offset
        offset += len(line) + 1
        stripped = line.strip(" \t\r")
        if not stripped or stripped[0] in "#;":
            continue
        if stripped[0] == "[":
            section = _section_header(stripped, start)
            if section in config:
                raise ParseError(f"duplicate section [{section}]", start)
            config[section] = {}
            continue
        key, value = _key_value(stripped, start)
        if key in config[section]:
            raise ParseError(f"duplicate key {key!r} in section [{section}]", start)
        config[section][key] = value
    return config


def _section_header(line: str, pos: int) -> str:
    """Name inside a ``[section]`` line."""
    if not line.endswith("]"):
        raise ParseError("section header must end with ']'", pos)
    name = line[1:-1].strip(" \t")
    if not _NAME.fullmatch(name):
        raise ParseError("section name must match [A-Za-z0-9_.-]+", pos)
    return name


def _key_value(line: str, pos: int) -> tuple[str, str]:
    """Split one ``key = value`` line."""
    key, sep, rest = line.partition("=")
    if not sep:
        raise ParseError("expected 'key = value'", pos)
    key = key.strip(" \t")
    if not _NAME.fullmatch(key):
        raise ParseError("key must match [A-Za-z0-9_.-]+", pos)
    rest = rest.strip(" \t\r")
    if rest.startswith('"'):
        return key, _quoted(rest, pos)
    if '"' in rest:
        raise ParseError("quote inside a bare value", pos)
    return key, rest


def _quoted(raw: str, pos: int) -> str:
    """Decode a double-quoted value; nothing may follow the closing quote."""
    out: list[str] = []
    i = 1
    while i < len(raw):
        ch = raw[i]
        if ch == '"':
            if raw[i + 1 :].strip(" \t"):
                raise ParseError("text after closing quote", pos + i)
            return "".join(out)
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(raw):
            raise ParseError("unfinished escape", pos + i)
        esc = raw[i + 1]
        if esc in _ESCAPES:
            out.append(_ESCAPES[esc])
            i += 2
        elif esc == "u":
            digits = raw[i + 2 : i + 6]
            if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                raise ParseError("\\u needs four hex digits", pos + i)
            out.append(chr(int(digits, 16)))
            i += 6
        else:
            raise ParseError(f"unknown escape \\{esc}", pos + i)
    raise ParseError("unterminated quoted value", pos)


def dump(config: Config) -> str:
    """Canonical text for a parsed configuration (every value quoted)."""
    lines: list[str] = []
    for section, values in config.items():
        if section:
            lines.append(f"[{section}]")
        lines.extend(f'{key} = "{_escape(value)}"' for key, value in values.items())
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    """Escape a value so ``_quoted`` reads it back unchanged."""
    out: list[str] = []
    for ch in value:
        if ch in _REVERSE:
            out.append("\\" + _REVERSE[ch])
        elif ch < " " or ch == "\x7f":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def fuzz_one(data: bytes) -> None:
    """Harness: parse, and if accepted, check that dump/parse round-trips exactly."""
    config = parse(data.decode("utf-8", errors="replace"))
    again = parse(dump(config))
    if again != config:
        raise InvariantError(f"round trip changed the config: {config!r} -> {again!r}")
