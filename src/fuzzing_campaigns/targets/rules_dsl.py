"""Pratt parser and printer for a pricing-rule expression language.

The grammar is a Python model of the one in rules-dsl-compiler, for example
``if customer.tier == "gold" then price * 0.9 else price``. Operators from loosest to tightest:
``if/then/else``, ``or``, ``and``, ``not``, comparisons and ``in`` (never chained), ``+ -``,
``* / %``, unary ``-``, then ``.field`` and calls. ``to_source`` prints the fewest parentheses
needed; ``fuzz_one`` checks that the printed text parses back to the same tree.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from fuzzing_campaigns.errors import InvariantError, ParseError

MAX_SOURCE = 16 * 1024
MAX_DEPTH = 100
KEYWORDS = frozenset({"if", "then", "else", "and", "or", "not", "in", "true", "false"})
_TOKEN = re.compile(
    r"""(?P<ws>[ \t\r\n]+|\#[^\n]*)
      | (?P<num>\d+(?:\.\d+)?)
      | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
      | (?P<str>")
      | (?P<op>==|!=|<=|>=|[<>+\-*/%().,\[\]])""",
    re.VERBOSE,
)
_STR_ESC = {"\\": "\\", '"': '"', "n": "\n", "t": "\t"}
_STR_UNESC = {v: k for k, v in _STR_ESC.items()}
COMPARISONS = frozenset({"==", "!=", "<", "<=", ">", ">=", "in"})
# Binding power of each infix operator; comparisons are 4 and never chain.
INFIX = {"or": 1, "and": 2, **dict.fromkeys(COMPARISONS, 4), "+": 5, "-": 5, "*": 6, "/": 6, "%": 6}
P_NOT, P_COMPARE, P_NEG, P_POSTFIX, P_ATOM = 3, 4, 7, 8, 9


@dataclass(frozen=True)
class Tok:
    """A token: kind is num, name, kw, str, op or eof."""

    kind: str
    text: str
    pos: int


@dataclass(frozen=True)
class Num:
    """A decimal literal, kept as written."""

    text: str


@dataclass(frozen=True)
class Str:
    """A string literal (decoded)."""

    value: str


@dataclass(frozen=True)
class Bool:
    """``true`` or ``false``."""

    value: bool


@dataclass(frozen=True)
class Var:
    """A variable reference."""

    name: str


@dataclass(frozen=True)
class Field:
    """``obj.name``."""

    obj: Expr
    name: str


@dataclass(frozen=True)
class Call:
    """``fn(args...)``; only plain names are callable."""

    fn: str
    args: tuple[Expr, ...]


@dataclass(frozen=True)
class ListLit:
    """``[a, b, ...]``."""

    items: tuple[Expr, ...]


@dataclass(frozen=True)
class Unary:
    """``-x`` or ``not x``."""

    op: str
    operand: Expr


@dataclass(frozen=True)
class Binary:
    """``left op right``."""

    op: str
    left: Expr
    right: Expr


@dataclass(frozen=True)
class If:
    """``if cond then a else b``."""

    cond: Expr
    then: Expr
    other: Expr


Expr = Num | Str | Bool | Var | Field | Call | ListLit | Unary | Binary | If


def tokenize(src: str) -> list[Tok]:
    """Split source into tokens, ending with an eof token."""
    toks: list[Tok] = []
    pos = 0
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if m is None:
            raise ParseError(f"unexpected character {src[pos]!r}", pos)
        kind = m.lastgroup or ""
        if kind == "str":
            value, pos = _string(src, pos)
            toks.append(Tok("str", value, m.start()))
            continue
        if kind != "ws":
            text = m.group()
            toks.append(Tok("kw" if text in KEYWORDS else kind, text, pos))
        pos = m.end()
    toks.append(Tok("eof", "", pos))
    return toks


def _string(src: str, start: int) -> tuple[str, int]:
    """Decode a string literal starting at the opening quote; return (value, end)."""
    out: list[str] = []
    i = start + 1
    while i < len(src):
        ch = src[i]
        if ch == '"':
            return "".join(out), i + 1
        if ch == "\n":
            raise ParseError("newline in string literal", i)
        if ch == "\\":
            esc = src[i + 1] if i + 1 < len(src) else ""
            if esc not in _STR_ESC:
                raise ParseError(f"unknown escape \\{esc}", i)
            out.append(_STR_ESC[esc])
            i += 2
            continue
        out.append(ch)
        i += 1
    raise ParseError("unterminated string", start)


class _Parser:
    """Pratt parser over a token list."""

    def __init__(self, toks: list[Tok]) -> None:
        """Start at the first token."""
        self.toks = toks
        self.i = 0
        self.depth = 0

    def peek(self) -> Tok:
        """Current token."""
        return self.toks[self.i]

    def take(self) -> Tok:
        """Consume and return the current token."""
        tok = self.toks[self.i]
        if tok.kind != "eof":
            self.i += 1
        return tok

    def expect(self, text: str) -> None:
        """Consume a specific operator or keyword."""
        tok = self.take()
        if tok.text != text or tok.kind not in ("op", "kw"):
            raise ParseError(f"expected {text!r}, found {tok.text or 'end of input'!r}", tok.pos)

    def expr(self, min_bp: int) -> Expr:
        """Parse an expression whose infix operators bind at least min_bp."""
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ParseError(f"expression nested deeper than {MAX_DEPTH}", self.peek().pos)
        left = self.prefix()
        while True:
            tok = self.peek()
            bp = INFIX.get(tok.text) if tok.kind in ("op", "kw") else None
            if bp is None or bp < min_bp:
                break
            self.take()
            if tok.text in COMPARISONS:
                left = Binary(tok.text, left, self.expr(P_COMPARE + 1))
                nxt = self.peek()
                if nxt.kind in ("op", "kw") and nxt.text in COMPARISONS:
                    raise ParseError("comparisons cannot be chained", nxt.pos)
            else:
                left = Binary(tok.text, left, self.expr(bp + 1))
        self.depth -= 1
        return left

    def prefix(self) -> Expr:
        """Literals, names, calls, lists, groups, unary operators and if; then postfix fields."""
        tok = self.take()
        node: Expr
        if tok.kind == "num":
            node = Num(tok.text)
        elif tok.kind == "str":
            node = Str(tok.text)
        elif tok.kind == "kw" and tok.text in ("true", "false"):
            node = Bool(tok.text == "true")
        elif tok.kind == "name":
            node = Call(tok.text, self.items(")")) if self._skip("(") else Var(tok.text)
        elif tok.text == "(" and tok.kind == "op":
            node = self.expr(0)
            self.expect(")")
        elif tok.text == "[" and tok.kind == "op":
            node = ListLit(self.items("]"))
        elif tok.text == "-" and tok.kind == "op":
            return Unary("-", self.expr(P_NEG))
        elif tok.text == "not" and tok.kind == "kw":
            return Unary("not", self.expr(P_NOT))
        elif tok.text == "if" and tok.kind == "kw":
            cond = self.expr(0)
            self.expect("then")
            then = self.expr(0)
            self.expect("else")
            return If(cond, then, self.expr(0))
        else:
            raise ParseError(f"unexpected {tok.text or 'end of input'!r}", tok.pos)
        while self._skip("."):
            name = self.take()
            if name.kind != "name":
                raise ParseError("expected a field name after '.'", name.pos)
            node = Field(node, name.text)
        return node

    def _skip(self, text: str) -> bool:
        """Consume an operator token if it matches."""
        tok = self.peek()
        if tok.kind == "op" and tok.text == text:
            self.i += 1
            return True
        return False

    def items(self, close: str) -> tuple[Expr, ...]:
        """Comma-separated expressions up to ``close`` (no trailing comma)."""
        out: list[Expr] = []
        if self._skip(close):
            return ()
        while True:
            out.append(self.expr(0))
            if self._skip(close):
                return tuple(out)
            self.expect(",")


def parse(src: str) -> Expr:
    """Parse one rule expression, or raise ParseError."""
    if len(src) > MAX_SOURCE:
        raise ParseError(f"source longer than {MAX_SOURCE} characters")
    p = _Parser(tokenize(src))
    tree = p.expr(0)
    tail = p.peek()
    if tail.kind != "eof":
        raise ParseError(f"unexpected {tail.text!r} after the expression", tail.pos)
    return tree


def _prec(node: Expr) -> int:
    """Binding power of a node's outermost operator."""
    if isinstance(node, If):
        return 0
    if isinstance(node, Binary):
        return INFIX[node.op]
    if isinstance(node, Unary):
        return P_NOT if node.op == "not" else P_NEG
    if isinstance(node, Field | Call):
        return P_POSTFIX
    return P_ATOM


def _wrap(node: Expr, need: int) -> str:
    """Print a child, in parentheses if it binds looser than ``need``."""
    text = to_source(node)
    return f"({text})" if _prec(node) < need else text


def to_source(node: Expr) -> str:
    """Print a tree with the fewest parentheses that keep its meaning."""
    if isinstance(node, Num):
        return node.text
    if isinstance(node, Str):
        return '"' + "".join("\\" + _STR_UNESC[c] if c in _STR_UNESC else c for c in node.value) + '"'
    if isinstance(node, Bool):
        return "true" if node.value else "false"
    if isinstance(node, Var):
        return node.name
    if isinstance(node, Field):
        return _wrap(node.obj, P_POSTFIX) + "." + node.name
    if isinstance(node, Call):
        return node.fn + "(" + ", ".join(to_source(a) for a in node.args) + ")"
    if isinstance(node, ListLit):
        return "[" + ", ".join(to_source(a) for a in node.items) + "]"
    if isinstance(node, Unary):
        sep = " " if node.op == "not" else ""
        return node.op + sep + _wrap(node.operand, _prec(node))
    if isinstance(node, Binary):
        bp = INFIX[node.op]
        left_need = bp + 1 if node.op in COMPARISONS else bp
        return f"{_wrap(node.left, left_need)} {node.op} {_wrap(node.right, bp + 1)}"
    return f"if {to_source(node.cond)} then {to_source(node.then)} else {to_source(node.other)}"


def fuzz_one(data: bytes) -> None:
    """Harness: parse; if accepted, check that the printed source parses to the same tree."""
    tree = parse(data.decode("utf-8", errors="replace"))
    printed = to_source(tree)
    if parse(printed) != tree:
        raise InvariantError(f"round trip changed the tree: {printed!r}")
