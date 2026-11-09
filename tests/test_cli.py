"""The fuzzcamp command line: list, run, replay, bench, and errors as exit code 2."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fuzzing_campaigns import atheris_harness
from fuzzing_campaigns.bench import aggregate, markdown, run_bench
from fuzzing_campaigns.cli import main
from fuzzing_campaigns.errors import ParseError


def test_list_names_every_target(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    for name in ("kvconfig", "regex", "rules", "canary"):
        assert name in out


def test_run_writes_outputs_and_fail_on_finding_sets_the_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "crash").write_bytes(b"FCv1 CHK 5")
    out = tmp_path / "out"
    code = main(["run", "canary", "--runs", "50", "--seeds-dir", str(seeds), "--out", str(out), "--fail-on-finding"])
    assert code == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["execs"] == 50
    assert summary["findings"]
    assert (out / "stats.json").is_file()
    crash = next((out / "crashes").iterdir())
    assert main(["replay", "canary", str(crash)]) == 1
    assert "finding: IndexError" in capsys.readouterr().out


def test_run_without_seeds_or_dictionary_finds_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "kvconfig", "--runs", "200", "--no-seeds", "--no-dict", "--fail-on-finding"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "nope"],
        ["run", "kvconfig", "--runs", "0"],
        ["run", "kvconfig", "--seconds", "-1"],
        ["run", "kvconfig", "--max-len", "x"],
        ["bench", "--seeds", "a,b"],
        ["bench", "--seeds", "-1"],
    ],
)
def test_invalid_arguments_exit_2(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_bad_files_are_reported_in_one_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.dict"
    bad.write_text("not a dictionary line\n", encoding="ascii")
    assert main(["run", "kvconfig", "--runs", "5", "--dict", str(bad)]) == 2
    assert main(["run", "kvconfig", "--runs", "5", "--seeds-dir", str(tmp_path / "missing")]) == 2
    assert main(["bench", "--targets", "nope"]) == 2
    err = capsys.readouterr().err
    assert err.count("fuzzcamp: error:") == 3


def test_bench_rows_aggregate_and_table(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rows = run_bench(["canary"], [0], 300)
    assert [r["setup"] for r in rows] == ["bare", "seeds", "seeds+dict"]
    table = aggregate(rows)
    assert table[0]["runs"] == 1
    assert table[0]["mean_edges"] < table[2]["mean_edges"]
    assert "| canary | seeds+dict |" in markdown(table, 300)
    with pytest.raises(ValueError, match="at least one"):
        run_bench([], [0], 10)
    out = tmp_path / "bench.json"
    assert main(["bench", "--targets", "canary", "--seeds", "0", "--runs", "100", "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["runs"] == 100
    assert "Budget: 100 executions" in capsys.readouterr().out


def test_atheris_flags_and_callback(tmp_path: Path) -> None:
    flags = atheris_harness.libfuzzer_args("regex", 15, tmp_path, 4096)
    assert "-max_total_time=15" in flags
    assert any(f.startswith("-dict=") and f.endswith("regex.dict") for f in flags)
    assert flags[-2] == str(tmp_path / "corpus")
    with pytest.raises(ValueError, match="at least 1"):
        atheris_harness.libfuzzer_args("regex", 0, tmp_path, 4096)

    def rejects(data: bytes) -> None:
        raise ParseError("no")

    def crashes(data: bytes) -> None:
        raise KeyError("bug")

    atheris_harness.wrap(rejects)(b"")
    with pytest.raises(KeyError):
        atheris_harness.wrap(crashes)(b"")
