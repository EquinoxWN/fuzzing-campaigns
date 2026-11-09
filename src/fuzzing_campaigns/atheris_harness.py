"""Run a target's harness under Atheris (libFuzzer for Python) with its seeds and dictionary.

Atheris publishes Linux and macOS wheels only, so this runs in CI on ubuntu. Usage::

    fuzzcamp-atheris kvconfig --seconds 20 --work .tmp/atheris/kvconfig

New corpus entries go to ``<work>/corpus`` and crash inputs to ``<work>/crash-<sha1>``; the
packaged seed folder is passed as a read-only second corpus directory.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from fuzzing_campaigns.corpus import campaign_dir
from fuzzing_campaigns.errors import ParseError
from fuzzing_campaigns.targets import TARGETS


def libfuzzer_args(target: str, seconds: int, work: Path, max_len: int) -> list[str]:
    """libFuzzer flags and corpus folders for one bounded run."""
    if seconds < 1 or max_len < 1:
        raise ValueError("seconds and max_len must be at least 1")
    camp = campaign_dir(target)
    return [
        f"-dict={camp / f'{target}.dict'}",
        f"-max_total_time={seconds}",
        f"-max_len={max_len}",
        "-timeout=10",
        "-rss_limit_mb=1024",
        f"-artifact_prefix={work.as_posix()}/",
        str(work / "corpus"),
        str(camp / "seeds"),
    ]


def wrap(entry: Callable[[bytes], None]) -> Callable[[bytes], None]:
    """Atheris callback: ParseError is a rejection; every other exception propagates as a crash."""

    def one_input(data: bytes) -> None:
        """Run the harness on one input."""
        try:
            entry(data)
        except ParseError:
            return

    return one_input


def main(argv: Sequence[str] | None = None) -> int:
    """Instrument the target module, then hand control to libFuzzer."""
    p = argparse.ArgumentParser(prog="fuzzcamp-atheris", description=__doc__)
    p.add_argument("target", choices=sorted(TARGETS))
    p.add_argument("--seconds", type=int, default=20)
    p.add_argument("--max-len", type=int, default=4096)
    p.add_argument("--work", type=Path, required=True, help="folder for the corpus and crash files")
    args = p.parse_args(argv)
    flags = libfuzzer_args(args.target, args.seconds, args.work, args.max_len)
    (args.work / "corpus").mkdir(parents=True, exist_ok=True)

    import atheris  # Linux/macOS only; installed in CI

    module = TARGETS[args.target].module
    with atheris.instrument_imports(include=[module]):
        entry = importlib.import_module(module).fuzz_one
    atheris.Setup([sys.argv[0], *flags], wrap(entry))
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
