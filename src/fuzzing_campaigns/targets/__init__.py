"""Registry of fuzz targets: each one wraps a parser's entry point as ``fuzz_one(data: bytes)``.

A target's harness raises ``ParseError`` for a documented rejection; any other exception (or an
``InvariantError`` from an oracle) is a finding.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType


@dataclass(frozen=True)
class Target:
    """One fuzz target: a name, the module holding its parser and harness, and a summary."""

    name: str
    module: str
    summary: str

    def load(self) -> ModuleType:
        """Import the target module."""
        return importlib.import_module(self.module)

    def entry(self) -> Callable[[bytes], None]:
        """The harness entry point ``fuzz_one``."""
        fn: Callable[[bytes], None] = self.load().fuzz_one
        return fn

    def source_files(self) -> frozenset[str]:
        """Files whose execution counts as coverage for this target."""
        path = self.load().__file__
        if path is None:
            raise RuntimeError(f"target module {self.module} has no source file")
        return frozenset({str(Path(path).resolve())})


TARGETS: dict[str, Target] = {
    t.name: t
    for t in (
        Target("kvconfig", f"{__name__}.kvconfig", "INI-style config parser; dump/parse round trip"),
        Target("regex", f"{__name__}.regex_parse", "regex subset parser; print round trip and re differential"),
        Target("rules", f"{__name__}.rules_dsl", "pricing-rule Pratt parser; print round trip"),
        Target("canary", f"{__name__}.canary", "packet parser with one planted bug (benchmark only)"),
    )
}


def get_target(name: str) -> Target:
    """Look a target up by name, with the valid names in the error."""
    try:
        return TARGETS[name]
    except KeyError:
        raise ValueError(f"unknown target {name!r}; choose from {', '.join(sorted(TARGETS))}") from None
