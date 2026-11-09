"""Edge coverage for pure-Python targets via ``sys.settrace``, with a per-input step budget.

An edge is (file, previous line, line) inside one frame, the Python analogue of libFuzzer's
control-flow edges. Only the target's own files are traced, so the parser's coverage is not
diluted by the standard library. The step budget turns a hang into a reportable ``Hang``.
"""

from __future__ import annotations

import inspect
import os
import sys
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from fuzzing_campaigns.errors import Hang

Edge = tuple[str, int, int]
_TraceFn = Callable[[types.FrameType, str, Any], Any]


def _norm(path: str) -> str:
    """Comparable form of a file path."""
    return os.path.normcase(os.path.realpath(path))


class EdgeTracer:
    """Runs one call under tracing and returns the edges it took."""

    def __init__(self, files: frozenset[str], step_budget: int) -> None:
        """Trace only ``files``; raise Hang after ``step_budget`` traced lines per call."""
        if step_budget < 1:
            raise ValueError("step_budget must be at least 1")
        self.files = frozenset(_norm(f) for f in files)
        self.step_budget = step_budget
        self._match: dict[str, bool] = {}
        self._edges: set[Edge] = set()
        self._steps = 0
        self.last_line: tuple[str, int] | None = None

    def run(self, fn: Callable[[bytes], None], data: bytes) -> tuple[set[Edge], BaseException | None]:
        """Call fn(data) under tracing; return (edges, the exception raised or None)."""
        self._edges = set()
        self._steps = 0
        self.last_line = None
        previous = sys.gettrace()
        sys.settrace(self._global)
        try:
            fn(data)
        except BaseException as exc:
            if isinstance(exc, KeyboardInterrupt | SystemExit):
                raise
            return self._edges, exc
        finally:
            sys.settrace(previous)
        return self._edges, None

    def _global(self, frame: types.FrameType, event: str, arg: Any) -> _TraceFn | None:
        """Install the line tracer only on frames of the target's files."""
        name = frame.f_code.co_filename
        traced = self._match.get(name)
        if traced is None:
            traced = self._match[name] = _norm(name) in self.files
        if not traced:
            return None
        last = -frame.f_code.co_firstlineno  # negative: the edge into the function's first line

        def local(frame: types.FrameType, event: str, arg: Any) -> _TraceFn | None:
            """Record the edge from the previous line of this frame to the current one."""
            nonlocal last
            if event == "line":
                line = frame.f_lineno
                self._edges.add((name, last, line))
                last = line
                self.last_line = (name, line)
                self._steps += 1
                if self._steps > self.step_budget:
                    raise Hang(f"more than {self.step_budget} traced lines for one input")
            return local

        return local


def executable_lines(path: str) -> set[int]:
    """Lines inside function bodies of a source file (the denominator for line coverage).

    Module and class bodies run at import time, not per input, so they are left out, and so is
    each function's ``def`` line, which never fires a line event.
    """
    source = Path(path).read_text(encoding="utf-8")
    lines: set[int] = set()
    stack = [compile(source, path, "exec")]
    while stack:
        code = stack.pop()
        if code.co_flags & inspect.CO_OPTIMIZED:
            lines.update(line for _, _, line in code.co_lines() if line is not None and line != code.co_firstlineno)
        stack.extend(c for c in code.co_consts if isinstance(c, types.CodeType))
    return lines


def lines_of(edges: Iterator[Edge] | set[Edge]) -> set[tuple[str, int]]:
    """Lines reached by a set of edges."""
    return {(f, line) for f, _, line in edges}
