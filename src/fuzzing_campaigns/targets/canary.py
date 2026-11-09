"""Benchmark target with one planted bug, used to measure how fast a campaign finds a crash.

This is not a parser anyone should use. It reads a tiny command packet::

    FCv1 PUT key=value; DEL key; CHK 3

and ``CHK`` takes the first digit in its argument as n and indexes a 4-entry table without a
bounds check, so n >= 4 raises ``IndexError``: the planted bug. Reaching it needs the ``FCv1`` magic (the seed corpus has it) and
the ``CHK`` keyword (only the dictionary has it), so it separates the effect of seeds and of
dictionaries on time-to-first-crash. The planted bug is kept on purpose; tests expect it.
"""

from __future__ import annotations

from fuzzing_campaigns.errors import ParseError

MAGIC = b"FCv1 "
MAX_PACKET = 4096
_CHECK_TABLE = (0x00, 0x5A, 0xA5, 0xFF)


def parse_packet(data: bytes) -> dict[str, bytes]:
    """Apply the packet's commands to an empty store and return it."""
    if len(data) > MAX_PACKET:
        raise ParseError(f"packet longer than {MAX_PACKET} bytes")
    if not data.startswith(MAGIC):
        raise ParseError("missing FCv1 magic", 0)
    store: dict[str, bytes] = {}
    for raw in data[len(MAGIC) :].split(b";"):
        cmd = raw.strip()
        if not cmd:
            continue
        verb, _, arg = cmd.partition(b" ")
        if verb == b"PUT":
            key, eq, value = arg.partition(b"=")
            if not eq or not key.isalnum():
                raise ParseError("PUT needs key=value with an alphanumeric key")
            store[key.decode("ascii")] = value
        elif verb == b"DEL":
            if not arg.isalnum():
                raise ParseError("DEL needs an alphanumeric key")
            store.pop(arg.decode("ascii"), None)
        elif verb == b"CHK":
            digit = next((chr(b) for b in arg if 0x30 <= b <= 0x39), None)
            if digit is None:
                raise ParseError("CHK needs a digit")
            store["check"] = bytes([_CHECK_TABLE[int(digit)]])  # planted bug: no bounds check
        else:
            raise ParseError(f"unknown command {verb[:16]!r}")
    return store


def fuzz_one(data: bytes) -> None:
    """Harness: run the packet parser; ParseError is a rejection, anything else a finding."""
    parse_packet(data)
