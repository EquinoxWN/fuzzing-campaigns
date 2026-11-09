"""Byte-level mutators in the style of libFuzzer and AFL havoc, driven by a seeded RNG.

The RNG is ``random.Random`` on purpose: fuzzing needs reproducible, fast pseudo-randomness,
not cryptographic randomness.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence

# Bytes that often matter to text parsers: boundaries, quotes, brackets, escapes, separators.
INTERESTING = b'\x00\x01\x7f\x80\xff\n\r\t "\\[](){}=,;.-+*?|^$#'
MAX_STACK = 4


class Mutator:
    """Produces mutated inputs from corpus entries; same seed, same sequence."""

    def __init__(self, rng: random.Random, dictionary: Sequence[bytes], max_len: int) -> None:
        """Keep the RNG, the dictionary tokens and the input length cap."""
        if max_len < 1:
            raise ValueError("max_len must be at least 1")
        self.rng = rng
        self.dictionary = list(dictionary)
        self.max_len = max_len
        self.ops: list[Callable[[bytearray], None]] = [
            self.flip_bit,
            self.set_interesting,
            self.set_random,
            self.delete_range,
            self.insert_random,
            self.duplicate_range,
        ]
        if self.dictionary:
            # Twice each, so a dictionary is tried about as often as libFuzzer's dictionary mutators.
            self.ops += [self.insert_token, self.overwrite_token] * 2

    def mutate(self, data: bytes, other: bytes | None = None) -> bytes:
        """Apply one to MAX_STACK stacked mutations (and maybe a splice with ``other``)."""
        buf = bytearray(data)
        if other is not None and self.rng.random() < 0.1:
            self.splice(buf, other)
        for _ in range(self.rng.randint(1, MAX_STACK)):
            self.rng.choice(self.ops)(buf)
        return bytes(buf[: self.max_len])

    def _pos(self, buf: bytearray, *, end_ok: bool = False) -> int:
        """A random index into buf (or its end when end_ok)."""
        return self.rng.randint(0, len(buf) if end_ok else len(buf) - 1)

    def flip_bit(self, buf: bytearray) -> None:
        """Flip one bit; on empty input insert a byte instead."""
        if not buf:
            self.insert_random(buf)
            return
        i = self._pos(buf)
        buf[i] ^= 1 << self.rng.randint(0, 7)

    def set_interesting(self, buf: bytearray) -> None:
        """Overwrite (or append to empty input) one byte with a parser-relevant byte."""
        byte = self.rng.choice(INTERESTING)
        if buf:
            buf[self._pos(buf)] = byte
        else:
            buf.append(byte)

    def set_random(self, buf: bytearray) -> None:
        """Overwrite one byte with a random printable ASCII byte."""
        byte = self.rng.randint(0x20, 0x7E)
        if buf:
            buf[self._pos(buf)] = byte
        else:
            buf.append(byte)

    def delete_range(self, buf: bytearray) -> None:
        """Remove 1 to 8 bytes."""
        if not buf:
            return
        i = self._pos(buf)
        del buf[i : i + self.rng.randint(1, 8)]

    def insert_random(self, buf: bytearray) -> None:
        """Insert 1 to 4 random printable bytes."""
        i = self._pos(buf, end_ok=True)
        buf[i:i] = bytes(self.rng.randint(0x20, 0x7E) for _ in range(self.rng.randint(1, 4)))

    def duplicate_range(self, buf: bytearray) -> None:
        """Copy a slice of up to 16 bytes to another place (repeats structure)."""
        if not buf:
            return
        i = self._pos(buf)
        chunk = buf[i : i + self.rng.randint(1, 16)]
        j = self._pos(buf, end_ok=True)
        buf[j:j] = chunk

    def insert_token(self, buf: bytearray) -> None:
        """Insert a dictionary token."""
        i = self._pos(buf, end_ok=True)
        buf[i:i] = self.rng.choice(self.dictionary)

    def overwrite_token(self, buf: bytearray) -> None:
        """Overwrite bytes with a dictionary token."""
        token = self.rng.choice(self.dictionary)
        i = self._pos(buf, end_ok=True)
        buf[i : i + len(token)] = token

    def splice(self, buf: bytearray, other: bytes) -> None:
        """Replace buf's tail with the tail of another corpus entry."""
        if not other:
            return
        i = self._pos(buf, end_ok=True)
        j = self.rng.randint(0, len(other) - 1)
        buf[i:] = other[j:]
