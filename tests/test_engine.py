"""Engine, tracer, mutators, dictionaries and corpus storage."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from fuzzing_campaigns import coverage
from fuzzing_campaigns.corpus import (
    CorpusError,
    atomic_write,
    content_name,
    load_seeds,
    packaged_dictionary,
    packaged_seeds,
    save_input,
)
from fuzzing_campaigns.dictionary import DictionaryError, load_dictionary, parse_dictionary
from fuzzing_campaigns.engine import FuzzConfig, Fuzzer, replay, write_outputs
from fuzzing_campaigns.errors import Hang
from fuzzing_campaigns.mutate import Mutator
from fuzzing_campaigns.targets import TARGETS, get_target
from fuzzing_campaigns.targets import canary as canary_mod

BUG_LINE = next(
    n
    for n, line in enumerate(Path(canary_mod.__file__).read_text(encoding="utf-8").splitlines(), start=1)
    if "planted bug: no bounds check" in line
)
BUG_KEY = f"IndexError@canary.py:{BUG_LINE}"


# dictionary -------------------------------------------------------------------------------------
def test_dictionary_reads_names_escapes_comments_and_drops_duplicates() -> None:
    text = '# c\n\nkw="if"\n"\\x00\\xff"\nq="\\"\\\\"\ndup="if"\n'
    assert parse_dictionary(text) == [b"if", b"\x00\xff", b'"\\']


@pytest.mark.parametrize(
    "line", ["kw=if", '"', '""', '"a"b"', '"\\q"', '"\\x4"', '"é"', '"' + "a" * 129 + '"', "name = 'x'"]
)
def test_dictionary_rejects_malformed_lines_with_the_line_number(line: str) -> None:
    with pytest.raises(DictionaryError, match="line 2"):
        parse_dictionary(f'ok="a"\n{line}\n')


def test_dictionary_file_must_be_ascii(tmp_path: Path) -> None:
    path = tmp_path / "d.dict"
    path.write_bytes(b'x="\xc3\xa9"\n')
    with pytest.raises(DictionaryError, match="not ASCII"):
        load_dictionary(path)


def test_every_packaged_dictionary_loads() -> None:
    for name in TARGETS:
        assert packaged_dictionary(name)


# corpus -----------------------------------------------------------------------------------------
def test_seeds_load_sorted_and_limits_hold(tmp_path: Path) -> None:
    (tmp_path / "b").write_bytes(b"2")
    (tmp_path / "a").write_bytes(b"1")
    assert load_seeds(tmp_path) == [b"1", b"2"]
    (tmp_path / "big").write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(CorpusError, match="seed limit"):
        load_seeds(tmp_path)
    with pytest.raises(CorpusError, match="not a directory"):
        load_seeds(tmp_path / "missing")


def test_saving_is_atomic_and_idempotent(tmp_path: Path) -> None:
    first = save_input(tmp_path, b"abc")
    again = save_input(tmp_path, b"abc")
    assert first == again
    assert first.name == content_name(b"abc")
    assert [p.name for p in tmp_path.iterdir()] == [first.name]
    atomic_write(tmp_path / "f", b"1")
    atomic_write(tmp_path / "f", b"22")
    assert (tmp_path / "f").read_bytes() == b"22"
    assert not list(tmp_path.glob("*.tmp"))


def test_failed_atomic_write_leaves_no_temp_file(tmp_path: Path) -> None:
    target = tmp_path / "dir-in-the-way"
    target.mkdir()
    (target / "x").write_bytes(b"")
    with pytest.raises(OSError):  # noqa: PT011 - the OS picks the exact subclass
        atomic_write(target, b"data")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dir-in-the-way"]


# mutators ---------------------------------------------------------------------------------------
def test_mutator_is_deterministic_bounded_and_handles_empty_input() -> None:
    def run(seed: int) -> list[bytes]:
        m = Mutator(random.Random(seed), [b"TOKEN"], max_len=16)
        return [m.mutate(b"" if i % 3 == 0 else b"hello world", b"other") for i in range(300)]

    out = run(1)
    assert out == run(1)
    assert out != run(2)
    assert all(len(x) <= 16 for x in out)
    assert any(b"TOKEN" in x for x in out)
    with pytest.raises(ValueError, match="max_len"):
        Mutator(random.Random(0), [], max_len=0)


def test_without_a_dictionary_tokens_never_appear() -> None:
    m = Mutator(random.Random(3), [], max_len=64)
    assert not any(b"TOKEN" in m.mutate(b"abc") for _ in range(500))


# tracer -----------------------------------------------------------------------------------------
def test_tracer_records_only_target_edges_and_restores_the_previous_tracer() -> None:
    target = get_target("canary")
    tracer = coverage.EdgeTracer(target.source_files(), step_budget=10_000)
    edges_ok, exc = tracer.run(target.entry(), b"FCv1 PUT a=1")
    assert exc is None
    assert edges_ok
    assert {Path(f).name for f, _, _ in edges_ok} == {"canary.py"}
    edges_bad, exc = tracer.run(target.entry(), b"nope")
    assert type(exc).__name__ == "ParseError"
    assert edges_bad != edges_ok


def test_step_budget_turns_a_hang_into_a_finding() -> None:
    def spin(data: bytes) -> None:
        while True:
            pass

    tracer = coverage.EdgeTracer(frozenset({__file__}), step_budget=50)
    _, exc = tracer.run(spin, b"")
    assert isinstance(exc, Hang)
    with pytest.raises(ValueError, match="step_budget"):
        coverage.EdgeTracer(frozenset(), step_budget=0)


def test_executable_lines_cover_function_bodies_only() -> None:
    lines = coverage.executable_lines(canary_mod.__file__)
    src = Path(canary_mod.__file__).read_text(encoding="utf-8").splitlines()
    assert any("planted bug" in src[n - 1] for n in lines)
    assert not any(src[n - 1].startswith(("import", "from", "MAGIC")) for n in lines)


# engine -----------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "kwargs",
    [{"max_runs": 0}, {"max_seconds": 0}, {"max_len": 0}, {"step_budget": 0}, {"checkpoint_every": 0}],
)
def test_config_rejects_impossible_budgets(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="must be"):
        FuzzConfig(**kwargs)  # type: ignore[arg-type]


def _canary(seed: int, runs: int, *, seeds: bool, dictionary: bool) -> Fuzzer:
    """A canary campaign with or without seeds and dictionary."""
    return Fuzzer(
        get_target("canary"),
        FuzzConfig(max_runs=runs, seed=seed),
        packaged_seeds("canary") if seeds else [],
        packaged_dictionary("canary") if dictionary else [],
    )


def test_seeds_and_dictionary_find_the_planted_bug_and_bare_does_not() -> None:
    found = sum(bool(_canary(s, 4000, seeds=True, dictionary=True).run().findings) for s in range(3))
    bare = [_canary(s, 3000, seeds=False, dictionary=False).run() for s in range(2)]
    assert found == 3
    assert not any(r.findings for r in bare)
    assert all(r.edges < 10 for r in bare)


def test_findings_are_deduplicated_by_type_and_line() -> None:
    res = _canary(0, 5000, seeds=True, dictionary=True).run()
    assert list(res.findings) == [BUG_KEY]
    finding = res.findings[BUG_KEY]
    assert finding.count >= 1
    assert replay(get_target("canary"), finding.data) == f"finding: {BUG_KEY}"


def test_same_seed_same_campaign() -> None:
    a = _canary(5, 2000, seeds=True, dictionary=True).run()
    b = _canary(5, 2000, seeds=True, dictionary=True).run()
    assert (a.execs, a.edges, a.corpus, list(a.findings)) == (b.execs, b.edges, b.corpus, list(b.findings))
    assert a.execs == 2000
    assert a.timeline[-1] == (2000, a.edges)


def test_time_budget_stops_the_run_and_stop_on_first_finding_works() -> None:
    timed = Fuzzer(get_target("regex"), FuzzConfig(max_runs=10**9, max_seconds=0.5), [], []).run()
    assert 0 < timed.execs < 10**9
    assert timed.elapsed_s < 5
    first = Fuzzer(
        get_target("canary"),
        FuzzConfig(max_runs=10**6, stop_on_first_finding=True),
        [b"FCv1 CHK 9"],
        [],
    ).run()
    assert first.execs == 1
    assert len(first.findings) == 1


def test_rejected_inputs_with_new_edges_join_the_corpus_and_replay_reports_outcomes() -> None:
    res = Fuzzer(get_target("kvconfig"), FuzzConfig(max_runs=1), [b"[bad"], []).run()
    assert res.corpus == [b"[bad"]
    target = get_target("kvconfig")
    assert replay(target, b"k = v\n") == "ok"
    assert replay(target, b"[bad").startswith("rejected:")


def test_write_outputs_saves_corpus_crashes_and_stats(tmp_path: Path) -> None:
    res = Fuzzer(get_target("canary"), FuzzConfig(max_runs=5), [b"FCv1 PUT a=1", b"FCv1 CHK 8"], []).run()
    write_outputs(res, tmp_path)
    write_outputs(res, tmp_path)
    stats = json.loads((tmp_path / "stats.json").read_text(encoding="utf-8"))
    assert stats["execs"] == 5
    assert stats["findings"][0]["key"] == BUG_KEY
    crashes = list((tmp_path / "crashes").iterdir())
    assert len(crashes) == 1
    assert crashes[0].read_bytes() == b"FCv1 CHK 8"
    assert len(list((tmp_path / "corpus").iterdir())) == len(res.corpus)


@pytest.mark.parametrize("name", ["kvconfig", "regex", "rules"])
def test_short_campaigns_on_the_real_parsers_find_nothing_and_reach_most_lines(name: str) -> None:
    res = Fuzzer(get_target(name), FuzzConfig(max_runs=3000), packaged_seeds(name), packaged_dictionary(name)).run()
    assert not res.findings, [f.key for f in res.findings.values()]
    assert res.lines / res.total_lines > 0.85
