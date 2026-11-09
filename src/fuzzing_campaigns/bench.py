"""Measure what seed corpora and dictionaries add: same target, same budget, three set-ups.

``bare`` starts from one empty input with no dictionary, ``seeds`` adds the packaged seed corpus,
``seeds+dict`` adds the packaged dictionary too. Each set-up runs with several RNG seeds and a
fixed execution budget, so the numbers are reproducible on any machine (only time varies).
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from typing import Any

from fuzzing_campaigns.corpus import packaged_dictionary, packaged_seeds
from fuzzing_campaigns.engine import FuzzConfig, Fuzzer
from fuzzing_campaigns.targets import get_target

SETUPS: dict[str, tuple[bool, bool]] = {
    "bare": (False, False),
    "seeds": (True, False),
    "seeds+dict": (True, True),
}


def run_one(target: str, setup: str, seed: int, runs: int) -> dict[str, Any]:
    """One campaign run of a target in one set-up; returns a result row."""
    use_seeds, use_dict = SETUPS[setup]
    fuzzer = Fuzzer(
        get_target(target),
        FuzzConfig(max_runs=runs, seed=seed),
        packaged_seeds(target) if use_seeds else [],
        packaged_dictionary(target) if use_dict else [],
    )
    res = fuzzer.run()
    first = min((f.first_exec for f in res.findings.values()), default=None)
    s = res.summary()
    return {
        "target": target,
        "setup": setup,
        "seed": seed,
        "execs": res.execs,
        "elapsed_s": s["elapsed_s"],
        "edges": res.edges,
        "line_coverage_pct": s["line_coverage_pct"],
        "corpus_size": len(res.corpus),
        "first_finding_exec": first,
        "findings": sorted(res.findings),
    }


def run_bench(targets: Sequence[str], seeds: Sequence[int], runs: int) -> list[dict[str, Any]]:
    """Every target x set-up x seed, in a fixed order."""
    if not targets or not seeds:
        raise ValueError("bench needs at least one target and one seed")
    return [run_one(t, setup, s, runs) for t in targets for setup in SETUPS for s in seeds]


def aggregate(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per target and set-up: mean edges and line coverage, how often and how soon a finding came."""
    out: list[dict[str, Any]] = []
    keys = list(dict.fromkeys((r["target"], r["setup"]) for r in rows))
    for target, setup in keys:
        group = [r for r in rows if r["target"] == target and r["setup"] == setup]
        firsts = [r["first_finding_exec"] for r in group if r["first_finding_exec"] is not None]
        out.append(
            {
                "target": target,
                "setup": setup,
                "runs": len(group),
                "mean_edges": round(statistics.fmean(r["edges"] for r in group), 1),
                "mean_line_coverage_pct": round(statistics.fmean(r["line_coverage_pct"] for r in group), 1),
                "found_finding": f"{len(firsts)}/{len(group)}",
                "median_execs_to_first_finding": statistics.median(firsts) if firsts else None,
                "execs_per_s": round(sum(r["execs"] for r in group) / max(sum(r["elapsed_s"] for r in group), 1e-9)),
            }
        )
    return out


def markdown(table: Sequence[dict[str, Any]], runs: int) -> str:
    """The aggregate as a Markdown table."""
    lines = [
        "| Target | Set-up | Mean edges | Mean line coverage | Finding found | Median execs to first finding | Execs/s |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in table:
        median = r["median_execs_to_first_finding"]
        lines.append(
            f"| {r['target']} | {r['setup']} | {r['mean_edges']} | {r['mean_line_coverage_pct']}% "
            f"| {r['found_finding']} | {'-' if median is None else f'{median:g}'} | {r['execs_per_s']} |"
        )
    lines.append(f"\nBudget: {runs} executions per run.")
    return "\n".join(lines)
