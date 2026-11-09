"""Coverage-guided mutation fuzzer for pure-Python targets (runs anywhere Python does).

The loop mirrors libFuzzer: run the seeds, then repeatedly pick a corpus entry, mutate it, run it
under edge tracing, keep it if it reached a new edge, and record any exception other than
``ParseError`` as a finding, de-duplicated by exception type and the line it was raised from.
Atheris runs the same harnesses on Linux (see ``atheris_harness``).
"""

from __future__ import annotations

import json
import random
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fuzzing_campaigns.corpus import atomic_write, content_name, save_input
from fuzzing_campaigns.coverage import Edge, EdgeTracer, executable_lines, lines_of
from fuzzing_campaigns.errors import Hang, ParseError
from fuzzing_campaigns.mutate import Mutator
from fuzzing_campaigns.targets import Target


@dataclass(frozen=True)
class FuzzConfig:
    """Budget and knobs of one campaign run."""

    max_runs: int = 10_000
    max_seconds: float | None = None
    max_len: int = 4096
    seed: int = 0
    step_budget: int = 100_000
    checkpoint_every: int = 500
    stop_on_first_finding: bool = False

    def __post_init__(self) -> None:
        """Reject budgets that cannot work."""
        if self.max_runs < 1:
            raise ValueError("max_runs must be at least 1")
        if self.max_seconds is not None and not self.max_seconds > 0:
            raise ValueError("max_seconds must be positive")
        if not 1 <= self.max_len <= 1 << 20:
            raise ValueError("max_len must be between 1 and 1 MiB")
        if self.step_budget < 1 or self.checkpoint_every < 1:
            raise ValueError("step_budget and checkpoint_every must be at least 1")


@dataclass
class Finding:
    """One distinct bug: the first input that hit it and how often it was hit."""

    key: str
    kind: str
    message: str
    data: bytes
    first_exec: int
    count: int = 1


@dataclass
class FuzzResult:
    """What a campaign run did and found."""

    target: str
    seed: int
    execs: int = 0
    elapsed_s: float = 0.0
    edges: int = 0
    lines: int = 0
    total_lines: int = 0
    corpus: list[bytes] = field(default_factory=list)
    findings: dict[str, Finding] = field(default_factory=dict)
    timeline: list[tuple[int, int]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        """JSON-ready summary (inputs are referenced by content hash, not inlined)."""
        return {
            "target": self.target,
            "seed": self.seed,
            "execs": self.execs,
            "elapsed_s": round(self.elapsed_s, 3),
            "execs_per_s": round(self.execs / self.elapsed_s) if self.elapsed_s > 0 else None,
            "edges": self.edges,
            "lines": self.lines,
            "total_lines": self.total_lines,
            "line_coverage_pct": round(100 * self.lines / self.total_lines, 1) if self.total_lines else 0.0,
            "corpus_size": len(self.corpus),
            "findings": [
                {
                    "key": f.key,
                    "kind": f.kind,
                    "message": f.message[:200],
                    "first_exec": f.first_exec,
                    "count": f.count,
                    "input_sha1": content_name(f.data),
                }
                for f in self.findings.values()
            ],
            "timeline": self.timeline,
        }


class Fuzzer:
    """One campaign: a target, seeds, a dictionary and a budget."""

    def __init__(self, target: Target, config: FuzzConfig, seeds: list[bytes], dictionary: list[bytes]) -> None:
        """Prepare the tracer, mutator and RNG; nothing runs yet."""
        self.target = target
        self.config = config
        self.seeds = seeds
        self.entry = target.entry()
        self.files = target.source_files()
        self.tracer = EdgeTracer(self.files, config.step_budget)
        self.rng = random.Random(config.seed)  # noqa: S311 - reproducible fuzzing, not crypto
        self.mutator = Mutator(self.rng, dictionary, config.max_len)
        self.covered: set[Edge] = set()
        self.result = FuzzResult(target=target.name, seed=config.seed)

    def run(self) -> FuzzResult:
        """Run seeds, then mutate until the run or time budget is spent."""
        cfg = self.config
        start = time.monotonic()
        deadline = None if cfg.max_seconds is None else start + cfg.max_seconds
        for seed in self.seeds or [b""]:
            if self._done(deadline):
                break
            self._execute(seed[: cfg.max_len])
        if not self.result.corpus:
            # Every seed crashed; keep one so mutation has a parent.
            self.result.corpus.append((self.seeds or [b""])[0][: cfg.max_len])
        corpus = self.result.corpus
        while not self._done(deadline):
            parent = self.rng.choice(corpus)
            other = self.rng.choice(corpus)
            self._execute(self.mutator.mutate(parent, other))
        res = self.result
        res.elapsed_s = time.monotonic() - start
        res.edges = len(self.covered)
        res.lines = len(lines_of(self.covered))
        res.total_lines = sum(len(executable_lines(f)) for f in self.files)
        if not res.timeline or res.timeline[-1][0] != res.execs:
            res.timeline.append((res.execs, res.edges))
        return res

    def _done(self, deadline: float | None) -> bool:
        """True when a budget is spent or the first finding should stop the run."""
        res = self.result
        if res.execs >= self.config.max_runs:
            return True
        if self.config.stop_on_first_finding and res.findings:
            return True
        return deadline is not None and time.monotonic() >= deadline

    def _execute(self, data: bytes) -> None:
        """Run one input; grow the corpus on new edges, record findings."""
        edges, exc = self.tracer.run(self.entry, data)
        res = self.result
        res.execs += 1
        if exc is None or isinstance(exc, ParseError):
            if not edges <= self.covered:
                self.covered |= edges
                res.corpus.append(data)
        else:
            key = finding_key(exc, self.files, self.tracer.last_line)
            known = res.findings.get(key)
            if known is None:
                res.findings[key] = Finding(key, type(exc).__name__, str(exc), data, res.execs)
            else:
                known.count += 1
        if res.execs % self.config.checkpoint_every == 0:
            res.timeline.append((res.execs, len(self.covered)))


def finding_key(exc: BaseException, files: frozenset[str], last_line: tuple[str, int] | None) -> str:
    """De-duplication key: exception type and the innermost target line it came from."""
    where = last_line if isinstance(exc, Hang) else None
    if where is None:
        frames = traceback.extract_tb(exc.__traceback__)
        names = {Path(f).name for f in files}
        inside = [fr for fr in frames if Path(fr.filename).name in names] or frames
        if inside:
            where = (inside[-1].filename, inside[-1].lineno or 0)
    place = f"{Path(where[0]).name}:{where[1]}" if where else "unknown"
    return f"{type(exc).__name__}@{place}"


def replay(target: Target, data: bytes, step_budget: int = 100_000) -> str:
    """Run one saved input: 'ok', 'rejected: ...' or 'finding: <key>'."""
    files = target.source_files()
    tracer = EdgeTracer(files, step_budget)
    _, exc = tracer.run(target.entry(), data)
    if exc is None:
        return "ok"
    if isinstance(exc, ParseError):
        return f"rejected: {exc}"
    return f"finding: {finding_key(exc, files, tracer.last_line)}"


def write_outputs(result: FuzzResult, out_dir: Path) -> None:
    """Save the corpus, one file per finding and stats.json, each written atomically."""
    for data in result.corpus:
        save_input(out_dir / "corpus", data)
    for finding in result.findings.values():
        safe = "".join(c if c.isalnum() else "-" for c in finding.key)
        save_input(out_dir / "crashes", finding.data, prefix=f"{safe}-")
    stats = json.dumps(result.summary(), indent=2, sort_keys=True) + "\n"
    atomic_write(out_dir / "stats.json", stats.encode("utf-8"))
