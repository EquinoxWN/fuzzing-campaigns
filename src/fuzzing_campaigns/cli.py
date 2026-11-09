"""``fuzzcamp``: list targets, run a campaign, replay saved inputs, and run the seeds/dictionary bench."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from fuzzing_campaigns.bench import aggregate, markdown, run_bench
from fuzzing_campaigns.corpus import (
    MAX_SEED_BYTES,
    CorpusError,
    atomic_write,
    load_seeds,
    packaged_dictionary,
    packaged_seeds,
)
from fuzzing_campaigns.dictionary import DictionaryError, load_dictionary
from fuzzing_campaigns.engine import FuzzConfig, Fuzzer, replay, write_outputs
from fuzzing_campaigns.targets import TARGETS, get_target


def _positive_int(text: str) -> int:
    """argparse type: an integer >= 1."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {value}")
    return value


def _seconds(text: str) -> float:
    """argparse type: a positive number of seconds, at most one day."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not 0 < value <= 86_400:
        raise argparse.ArgumentTypeError(f"must be in (0, 86400], got {text}")
    return value


def _target(text: str) -> str:
    """argparse type: a registered target name."""
    if text not in TARGETS:
        raise argparse.ArgumentTypeError(f"unknown target {text!r}; choose from {', '.join(sorted(TARGETS))}")
    return text


def _int_list(text: str) -> list[int]:
    """argparse type: comma-separated non-negative integers."""
    try:
        values = [int(v) for v in text.split(",") if v.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected integers like 0,1,2, got {text!r}") from None
    if not values or any(v < 0 for v in values):
        raise argparse.ArgumentTypeError("need at least one non-negative integer")
    return values


def build_parser() -> argparse.ArgumentParser:
    """The command-line interface."""
    p = argparse.ArgumentParser(prog="fuzzcamp", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list fuzz targets")

    run = sub.add_parser("run", help="run one coverage-guided campaign")
    run.add_argument("target", type=_target)
    run.add_argument("--runs", type=_positive_int, default=10_000, help="execution budget (default 10000)")
    run.add_argument("--seconds", type=_seconds, help="time budget; whichever budget ends first stops")
    run.add_argument("--seed", type=int, default=0, help="RNG seed (default 0)")
    run.add_argument("--max-len", type=_positive_int, default=4096, help="input length cap in bytes")
    run.add_argument("--seeds-dir", type=Path, help="seed corpus folder (default: the packaged one)")
    run.add_argument("--dict", type=Path, dest="dict_file", help="dictionary file (default: the packaged one)")
    run.add_argument("--no-seeds", action="store_true", help="start from one empty input")
    run.add_argument("--no-dict", action="store_true", help="mutate without a dictionary")
    run.add_argument("--out", type=Path, help="save corpus/, crashes/ and stats.json here")
    run.add_argument("--fail-on-finding", action="store_true", help="exit 1 when anything is found")

    rep = sub.add_parser("replay", help="re-run saved inputs and print each outcome")
    rep.add_argument("target", type=_target)
    rep.add_argument("files", type=Path, nargs="+")

    bench = sub.add_parser("bench", help="compare bare, seeds and seeds+dict set-ups")
    bench.add_argument("--targets", default=",".join(TARGETS), help="comma-separated targets")
    bench.add_argument("--seeds", type=_int_list, default=[0, 1, 2], help="RNG seeds (default 0,1,2)")
    bench.add_argument("--runs", type=_positive_int, default=3000, help="executions per run (default 3000)")
    bench.add_argument("--out", type=Path, help="write rows and aggregate as JSON here")
    return p


def _cmd_run(args: argparse.Namespace) -> int:
    """Run one campaign and print its summary as JSON."""
    seeds = [] if args.no_seeds else (load_seeds(args.seeds_dir) if args.seeds_dir else packaged_seeds(args.target))
    if args.no_dict:
        dictionary: list[bytes] = []
    else:
        dictionary = load_dictionary(args.dict_file) if args.dict_file else packaged_dictionary(args.target)
    config = FuzzConfig(max_runs=args.runs, max_seconds=args.seconds, max_len=args.max_len, seed=args.seed)
    result = Fuzzer(get_target(args.target), config, seeds, dictionary).run()
    if args.out:
        write_outputs(result, args.out)
    summary = result.summary()
    summary.pop("timeline")
    print(json.dumps(summary, indent=2))
    return 1 if args.fail_on_finding and result.findings else 0


def _cmd_replay(args: argparse.Namespace) -> int:
    """Print the outcome of each saved input; exit 1 if any is a finding."""
    target = get_target(args.target)
    worst = 0
    for path in args.files:
        if path.stat().st_size > MAX_SEED_BYTES:
            raise CorpusError(f"{path}: larger than {MAX_SEED_BYTES} bytes")
        outcome = replay(target, path.read_bytes())
        print(f"{path}: {outcome}")
        worst = max(worst, int(outcome.startswith("finding")))
    return worst


def _cmd_bench(args: argparse.Namespace) -> int:
    """Run the bench and print the aggregate table."""
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    for t in targets:
        get_target(t)
    rows = run_bench(targets, args.seeds, args.runs)
    table = aggregate(rows)
    print(markdown(table, args.runs))
    if args.out:
        payload = {"runs": args.runs, "seeds": args.seeds, "aggregate": table, "rows": rows}
        atomic_write(args.out, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; user errors print one line and exit 2."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "list":
            for t in TARGETS.values():
                print(f"{t.name:10} {t.summary}")
            return 0
        if args.cmd == "run":
            return _cmd_run(args)
        if args.cmd == "replay":
            return _cmd_replay(args)
        return _cmd_bench(args)
    except (CorpusError, DictionaryError, ValueError, OSError) as exc:
        print(f"fuzzcamp: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
