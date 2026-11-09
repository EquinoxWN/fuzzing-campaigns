# ADR 0002: A small pure-Python engine next to Atheris, sharing targets, seeds and dictionaries

- **Status:** Accepted

## Context

Atheris (libFuzzer for Python) is the standard engine for Python targets, but it publishes wheels
for Linux and macOS only (atheris 3.1.0 has `cp312` manylinux wheels and none for Windows). The
author's machine is Windows 11 and Docker is not used locally. Without a local engine, every
fuzzing change could only be tried in CI, and the bench that shows the value of seeds and
dictionaries could not be measured locally.

## Decision

Write a small coverage-guided engine in plain Python (`engine.py`, `mutate.py`, `coverage.py`)
that follows libFuzzer's loop and reads the same on-disk formats: a folder of seed files and an
AFL/libFuzzer dictionary. Every target exposes one `fuzz_one(data: bytes)` used unchanged by both
engines. Atheris runs in CI on ubuntu (`fuzzcamp-atheris`), with the packaged dictionary passed as
`-dict=` and the packaged seeds as a read-only corpus folder.

## Consequences

- Targets, seeds and dictionaries are tested locally and on every push, and the bench runs
  anywhere Python 3.11+ runs, with execution counts that do not depend on the machine.
- The local engine is slower (thousands of executions per second, because of `sys.settrace`) and
  has only line-edge feedback, no comparison tracing. That is acceptable for short runs; long
  campaigns (M2) use Atheris.
- Two engines must agree on what a finding is. Both treat `ParseError` as a rejection and every
  other exception as a crash; `fuzzcamp replay` re-runs an Atheris crash file through the local
  engine, and CI checks that the canary crash Atheris finds replays to the expected key.
