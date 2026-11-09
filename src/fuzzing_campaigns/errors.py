"""Exception types shared by the parsers, the harnesses and the fuzzing engine."""

from __future__ import annotations


class ParseError(ValueError):
    """Documented rejection of malformed input; never counted as a finding."""

    def __init__(self, message: str, position: int | None = None) -> None:
        """Message plus the offending position, when known."""
        self.position = position
        super().__init__(message if position is None else f"{message} at position {position}")


class InvariantError(AssertionError):
    """A harness oracle saw a wrong answer (a bug, not a rejection)."""


class Hang(BaseException):
    """Raised by the tracer when one input exceeds its step budget.

    It derives from BaseException so a parser's own ``except Exception`` cannot swallow it.
    """
