# ADR 0003: Oracles beyond crashes, and a planted canary to measure discovery

- **Status:** Accepted

## Context

A pure-Python parser rarely crashes in the memory-safety sense; its bugs are wrong answers: a
printer that drops a parenthesis, an escape decoded differently on the way back, a pattern
accepted that the real engine rejects. A crash-only target finds none of those. Separately, the
real parsers in this repo did not crash in any local run, so "bugs found" cannot measure whether
seeds and dictionaries help.

## Decision

- Every real target runs an oracle after a successful parse: `kvconfig` and `rules` check that
  printing and re-parsing gives the same result; `regex` also checks that Python's `re` compiles
  every pattern the parser accepts (a differential oracle in one direction, since the subset is
  meant to be stricter). A violated oracle raises `InvariantError`, which counts as a finding.
- A fourth target, `canary`, carries one planted, documented bug (`CHK` with a digit of 4 or more
  indexes past a 4-entry table). Reaching it needs the magic header, which only the seeds contain,
  and the `CHK` keyword, which only the dictionary contains. The bench reports how often and how
  soon each set-up finds it.

## Consequences

- The real targets can fail on wrong answers, not only exceptions, and tests prove each oracle
  fires (by breaking `dump` or `re.compile` in a test).
- The canary is a benchmark, not a bug to fix; its module says so, and its test expects the
  `IndexError`. Real bugs found by fuzzing are fixed and get a regression test (M2 adds a write-up
  per bug).
- The canary's numbers measure this engine on this target; they are evidence of the effect of
  seeds and dictionaries, not a general claim about fuzzers.
