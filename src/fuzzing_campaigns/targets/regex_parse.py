"""Regular-expression parser for the subset a linear-time (Thompson NFA) engine supports.

Supported: literals, ``.``, ``^``, ``$``, groups ``( )``, alternation ``|``, quantifiers ``* + ?``
and ``{m}``, ``{m,}``, ``{m,n}`` (n <= 1000), character classes with ranges and negation, and the
escapes ``\\d \\D \\w \\W \\s \\S`` plus escaped punctuation. Everything else (backreferences,
lookaround, lazy or possessive quantifiers, ``(?`` extensions) is rejected with ``ParseError``.

Two oracles run in ``fuzz_one``: the printed pattern parses back to the same tree, and every
pattern this parser accepts is also accepted by Python's ``re`` (the stricter subset must never
accept something the reference rejects).
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass

from fuzzing_campaigns.errors import InvariantError, ParseError

MAX_PATTERN = 4096
MAX_DEPTH = 64
MAX_REPEAT = 1000
CLASS_ESCAPES = frozenset("dDwWsS")
_META = frozenset("\\.^$|()[]{}*+?")
_CLASS_META = frozenset("\\]^-[")
_QUANT = re.compile(r"\{(\d{1,4})(,(\d{0,4}))?\}")


@dataclass(frozen=True)
class Literal:
    """One literal character."""

    char: str


@dataclass(frozen=True)
class AnyChar:
    """The ``.`` wildcard."""


@dataclass(frozen=True)
class Anchor:
    """``^`` (start) or ``$`` (end)."""

    kind: str


@dataclass(frozen=True)
class Escape:
    """A shorthand class such as ``\\d``."""

    kind: str


@dataclass(frozen=True)
class CharClass:
    """``[...]``: items are single characters, (lo, hi) ranges or shorthand escapes."""

    negated: bool
    items: tuple[str | tuple[str, str] | Escape, ...]


@dataclass(frozen=True)
class Group:
    """A parenthesised sub-expression."""

    body: Node


@dataclass(frozen=True)
class Repeat:
    """``body{lo,hi}``; hi is None when unbounded."""

    body: Node
    lo: int
    hi: int | None


@dataclass(frozen=True)
class Concat:
    """A sequence of nodes (possibly empty)."""

    parts: tuple[Node, ...]


@dataclass(frozen=True)
class Alt:
    """Alternatives separated by ``|``."""

    options: tuple[Node, ...]


Node = Literal | AnyChar | Anchor | Escape | CharClass | Group | Repeat | Concat | Alt


class _Parser:
    """Recursive-descent parser with an explicit nesting limit."""

    def __init__(self, pattern: str) -> None:
        """Start at position 0 with depth 0."""
        self.src = pattern
        self.pos = 0
        self.depth = 0

    def peek(self) -> str | None:
        """Current character, or None at the end."""
        return self.src[self.pos] if self.pos < len(self.src) else None

    def parse_alt(self) -> Node:
        """alt := concat ('|' concat)*."""
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ParseError(f"nesting deeper than {MAX_DEPTH}", self.pos)
        options = [self.parse_concat()]
        while self.peek() == "|":
            self.pos += 1
            options.append(self.parse_concat())
        self.depth -= 1
        return options[0] if len(options) == 1 else Alt(tuple(options))

    def parse_concat(self) -> Node:
        """concat := repeat*, stopping at '|' or ')'."""
        parts: list[Node] = []
        while (ch := self.peek()) is not None and ch not in "|)":
            parts.append(self.parse_repeat())
        return parts[0] if len(parts) == 1 else Concat(tuple(parts))

    def parse_repeat(self) -> Node:
        """repeat := atom quantifier? ; a second quantifier is an error."""
        start = self.pos
        atom = self.parse_atom()
        bounds = self.quantifier()
        if bounds is None:
            return atom
        if isinstance(atom, Anchor):
            raise ParseError("nothing to repeat", start)
        nxt = self.peek()
        if nxt is not None and nxt in "*+?{":
            raise ParseError("multiple repeat (lazy and possessive forms are unsupported)", self.pos)
        return Repeat(atom, bounds[0], bounds[1])

    def quantifier(self) -> tuple[int, int | None] | None:
        """Parse ``* + ? {m} {m,} {m,n}`` if present."""
        ch = self.peek()
        simple = {"*": (0, None), "+": (1, None), "?": (0, 1)}
        if ch in simple:
            self.pos += 1
            return simple[ch]
        if ch != "{":
            return None
        m = _QUANT.match(self.src, self.pos)
        if m is None:
            raise ParseError("malformed {m,n} quantifier", self.pos)
        lo = int(m.group(1))
        hi: int | None = lo if m.group(2) is None else (int(m.group(3)) if m.group(3) else None)
        if lo > MAX_REPEAT or (hi is not None and hi > MAX_REPEAT):
            raise ParseError(f"repeat count above {MAX_REPEAT}", self.pos)
        if hi is not None and hi < lo:
            raise ParseError("min repeat greater than max repeat", self.pos)
        self.pos = m.end()
        return lo, hi

    def parse_atom(self) -> Node:
        """atom := literal | '.' | anchor | escape | class | group."""
        ch = self.peek()
        if ch is None:
            raise ParseError("unexpected end of pattern", self.pos)
        if ch in "*+?{":
            raise ParseError("nothing to repeat", self.pos)
        self.pos += 1
        if ch == ".":
            return AnyChar()
        if ch in "^$":
            return Anchor(ch)
        if ch == "\\":
            return self.escape(in_class=False)
        if ch == "[":
            return self.char_class()
        if ch == "(":
            if self.peek() == "?":
                raise ParseError("(? extensions are unsupported", self.pos)
            body = self.parse_alt()
            if self.peek() != ")":
                raise ParseError("missing ')'", self.pos)
            self.pos += 1
            return Group(body)
        if ch in ")]}":
            raise ParseError(f"unbalanced {ch!r}", self.pos - 1)
        return Literal(ch)

    def escape(self, *, in_class: bool) -> Literal | Escape:
        """After a backslash: a shorthand class or an escaped punctuation character."""
        ch = self.peek()
        if ch is None:
            raise ParseError("pattern ends with a backslash", self.pos)
        self.pos += 1
        if ch in CLASS_ESCAPES:
            return Escape(ch)
        if ch.isascii() and not ch.isalnum() and ch.isprintable():
            return Literal(ch)
        where = "class" if in_class else "pattern"
        raise ParseError(f"unsupported escape \\{ch} in {where}", self.pos - 1)

    def char_class(self) -> CharClass:
        """``[...]`` with ranges, negation and shorthand escapes; ']' first is an error."""
        negated = self.peek() == "^"
        if negated:
            self.pos += 1
        items: list[str | tuple[str, str] | Escape] = []
        while (ch := self.peek()) != "]":
            if ch is None:
                raise ParseError("unterminated character class", self.pos)
            first = self.class_atom()
            if self.peek() == "-" and self.pos + 1 < len(self.src) and self.src[self.pos + 1] != "]":
                self.pos += 1
                last = self.class_atom()
                if isinstance(first, Escape) or isinstance(last, Escape):
                    raise ParseError("bad character range", self.pos)
                if ord(last) < ord(first):
                    raise ParseError("range out of order", self.pos)
                items.append((first, last))
            else:
                items.append(first)
        if not items:
            raise ParseError("empty character class", self.pos)
        self.pos += 1
        return CharClass(negated, tuple(items))

    def class_atom(self) -> str | Escape:
        """One class member: a character or a backslash escape."""
        ch = self.src[self.pos]
        self.pos += 1
        if ch == "\\":
            esc = self.escape(in_class=True)
            return esc if isinstance(esc, Escape) else esc.char
        if ch == "[":
            raise ParseError("nested '[' in a class must be escaped", self.pos - 1)
        return ch


def parse(pattern: str) -> Node:
    """Parse a pattern into a tree, or raise ParseError."""
    if len(pattern) > MAX_PATTERN:
        raise ParseError(f"pattern longer than {MAX_PATTERN} characters")
    p = _Parser(pattern)
    tree = p.parse_alt()
    if p.pos != len(pattern):
        raise ParseError("unbalanced ')'", p.pos)
    return tree


def to_pattern(node: Node) -> str:
    """Print a tree back as a pattern that parses to the same tree."""
    if isinstance(node, Literal):
        return "\\" + node.char if node.char in _META else node.char
    if isinstance(node, AnyChar):
        return "."
    if isinstance(node, Anchor):
        return node.kind
    if isinstance(node, Escape):
        return "\\" + node.kind
    if isinstance(node, CharClass):
        return "[" + ("^" if node.negated else "") + "".join(map(_class_item, node.items)) + "]"
    if isinstance(node, Group):
        return "(" + to_pattern(node.body) + ")"
    if isinstance(node, Repeat):
        return to_pattern(node.body) + _bounds(node.lo, node.hi)
    if isinstance(node, Concat):
        return "".join(to_pattern(p) for p in node.parts)
    return "|".join(to_pattern(o) for o in node.options)


def _class_item(item: str | tuple[str, str] | Escape) -> str:
    """Print one class member."""
    if isinstance(item, Escape):
        return "\\" + item.kind
    if isinstance(item, tuple):
        return _class_char(item[0]) + "-" + _class_char(item[1])
    return _class_char(item)


def _class_char(ch: str) -> str:
    """Escape a character that is special inside a class."""
    return "\\" + ch if ch in _CLASS_META else ch


def _bounds(lo: int, hi: int | None) -> str:
    """Shortest quantifier text for (lo, hi)."""
    short = {(0, None): "*", (1, None): "+", (0, 1): "?"}
    if (lo, hi) in short:
        return short[(lo, hi)]
    if hi is None:
        return f"{{{lo},}}"
    return f"{{{lo}}}" if lo == hi else f"{{{lo},{hi}}}"


def fuzz_one(data: bytes) -> None:
    """Harness: parse; if accepted, check the print round trip and that ``re`` accepts it too."""
    pattern = data.decode("utf-8", errors="replace")
    tree = parse(pattern)
    printed = to_pattern(tree)
    if parse(printed) != tree:
        raise InvariantError(f"round trip changed the tree: {pattern!r} -> {printed!r}")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise InvariantError(f"accepted {pattern!r} but re rejects it: {exc}") from exc
