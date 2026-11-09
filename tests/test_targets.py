"""Parsers behind the fuzz targets: accepted inputs, documented rejections and the oracles."""

from __future__ import annotations

import random
import re

import pytest

from fuzzing_campaigns.corpus import packaged_seeds
from fuzzing_campaigns.errors import InvariantError, ParseError
from fuzzing_campaigns.targets import TARGETS, canary, get_target, kvconfig, regex_parse, rules_dsl


# kvconfig ---------------------------------------------------------------------------------------
def test_kvconfig_parses_sections_quotes_and_escapes() -> None:
    cfg = kvconfig.parse('top = 1\n[a.b]\n; c\nx = "q\\"\\n\\u00e9"\ny = bare value  \n')
    assert cfg == {"": {"top": "1"}, "a.b": {"x": 'q"\né', "y": "bare value"}}


@pytest.mark.parametrize(
    "text",
    [
        "[a]\n[a]\n",
        "k = 1\nk = 2\n",
        "[a\n",
        "[]\n",
        "no equals\n",
        "bad key! = 1\n",
        'k = "open\n',
        'k = "x" trailing\n',
        'k = "\\q"\n',
        'k = "\\u12g4"\n',
        'k = "\\',
        'k = a"b\n',
        "k = " + "x" * kvconfig.MAX_INPUT,
    ],
)
def test_kvconfig_rejects_malformed_input(text: str) -> None:
    with pytest.raises(ParseError):
        kvconfig.parse(text)


def test_kvconfig_dump_round_trips_control_characters() -> None:
    cfg = {"": {"k": 'a\x01\x7f\r\t"\\'}, "s": {}}
    assert kvconfig.parse(kvconfig.dump(cfg)) == cfg


def test_kvconfig_dump_is_printable_one_line_per_key() -> None:
    text = kvconfig.dump({"": {"k": "a\x01b\x7f\x1b"}})
    assert text == 'k = "a\\u0001b\\u007f\\u001b"\n'
    assert all(c == "\n" or " " <= c < "\x7f" for c in text)


def test_kvconfig_oracle_reports_a_broken_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvconfig, "dump", lambda cfg: "")
    with pytest.raises(InvariantError):
        kvconfig.fuzz_one(b"[s]\nk = v\n")


# regex ------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "pattern",
    ["", "a(b|c)*d", "^[^\\s,]+$", "[a-z\\d_-]{2,5}", "x{0}y{3,}z?", "\\.\\(\\)", "()|a", "[\\--a]", "[a-]"],
)
def test_regex_accepts_the_subset_and_python_agrees(pattern: str) -> None:
    tree = regex_parse.parse(pattern)
    assert regex_parse.parse(regex_parse.to_pattern(tree)) == tree
    re.compile(pattern)
    regex_parse.fuzz_one(pattern.encode())


@pytest.mark.parametrize(
    "pattern",
    [
        "a**",
        "a*?",
        "x{3}{2}",
        "^*",
        "*a",
        "(a",
        "a)",
        "[]",
        "[^]",
        "[z-a]",
        "[\\d-z]",
        "a{2,1}",
        "a{1001}",
        "a{",
        "(?:a)",
        "\\b",
        "\\",
        "[a",
        "[[]",
        "]",
    ],
)
def test_regex_rejects_outside_the_subset(pattern: str) -> None:
    with pytest.raises(ParseError):
        regex_parse.parse(pattern)


def test_regex_nesting_limit_is_a_parse_error_not_a_recursion_error() -> None:
    deep = "(" * (regex_parse.MAX_DEPTH + 1) + ")" * (regex_parse.MAX_DEPTH + 1)
    with pytest.raises(ParseError, match="nesting"):
        regex_parse.parse(deep)
    ok = "(" * (regex_parse.MAX_DEPTH - 1) + "a" + ")" * (regex_parse.MAX_DEPTH - 1)
    regex_parse.fuzz_one(ok.encode())


def test_regex_differential_oracle_fires_when_re_disagrees(monkeypatch: pytest.MonkeyPatch) -> None:
    class RefusingRe:
        """Stand-in for the re module that rejects every pattern."""

        error = re.error

        @staticmethod
        def compile(pattern: str) -> None:
            """Always refuse."""
            raise re.error("refused for the test")

    monkeypatch.setattr(regex_parse, "re", RefusingRe)
    with pytest.raises(InvariantError, match="re rejects"):
        regex_parse.fuzz_one(b"abc")


# rules ------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("src", "printed"),
    [
        ("a + b * c", "a + b * c"),
        ("(a + b) * c", "(a + b) * c"),
        ("a - (b - c)", "a - (b - c)"),
        ("(a - b) - c", "a - b - c"),
        ("not a and b", "not a and b"),
        ("not (a and b)", "not (a and b)"),
        ("(not a) == b", "(not a) == b"),
        ("-(a.b)", "-a.b"),
        ("(-a).b", "(-a).b"),
        ("(if a then b else c) + 1", "(if a then b else c) + 1"),
        ('x in [1, "s\\"", true]', 'x in [1, "s\\"", true]'),
        ("max( a , 0 ) # note", "max(a, 0)"),
    ],
)
def test_rules_prints_minimal_parentheses(src: str, printed: str) -> None:
    tree = rules_dsl.parse(src)
    assert rules_dsl.to_source(tree) == printed
    assert rules_dsl.parse(printed) == tree


@pytest.mark.parametrize(
    "src",
    [
        "",
        "a ==",
        "a == b == c",
        "a < b > c",
        "if a then b",
        "f(a,)",
        "a.if",
        "a.1",
        '"open',
        '"\\q"',
        '"line\nbreak"',
        "a $ b",
        "(a",
        "a b",
        "[1, 2",
    ],
)
def test_rules_rejects_malformed_source(src: str) -> None:
    with pytest.raises(ParseError):
        rules_dsl.parse(src)


def test_rules_depth_limit_is_a_parse_error() -> None:
    with pytest.raises(ParseError, match="nested"):
        rules_dsl.parse("-" * (rules_dsl.MAX_DEPTH + 5) + "x")


def test_rules_round_trip_holds_on_random_generated_trees() -> None:
    rng = random.Random(7)

    def gen(depth: int) -> rules_dsl.Expr:
        leaves: list[rules_dsl.Expr] = [
            rules_dsl.Num("1.5"),
            rules_dsl.Var("v"),
            rules_dsl.Str('a"\n'),
            rules_dsl.Bool(True),
        ]
        if depth == 0:
            return rng.choice(leaves)
        kind = rng.randrange(6)
        if kind == 0:
            return rules_dsl.Binary(rng.choice(list(rules_dsl.INFIX)), gen(depth - 1), gen(depth - 1))
        if kind == 1:
            return rules_dsl.Unary(rng.choice(["-", "not"]), gen(depth - 1))
        if kind == 2:
            return rules_dsl.If(gen(depth - 1), gen(depth - 1), gen(depth - 1))
        if kind == 3:
            return rules_dsl.Field(gen(depth - 1), "f")
        if kind == 4:
            return rules_dsl.Call("g", (gen(depth - 1),))
        return rng.choice(leaves)

    for _ in range(400):
        tree = gen(4)
        text = rules_dsl.to_source(tree)
        assert rules_dsl.parse(text) == tree, text


# canary and registry ----------------------------------------------------------------------------
def test_canary_valid_packets_and_the_planted_bug() -> None:
    assert canary.parse_packet(b"FCv1 PUT a=1; PUT b=2; DEL a; CHK 3") == {"b": b"2", "check": b"\xff"}
    with pytest.raises(ParseError):
        canary.parse_packet(b"XXXX PUT a=1")
    with pytest.raises(IndexError):
        canary.fuzz_one(b"FCv1 CHK 4")


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_every_packaged_seed_is_accepted_by_its_target(name: str) -> None:
    seeds = packaged_seeds(name)
    assert seeds
    entry = get_target(name).entry()
    for seed in seeds:
        entry(seed)


def test_unknown_target_names_the_valid_ones() -> None:
    with pytest.raises(ValueError, match="kvconfig"):
        get_target("nope")
