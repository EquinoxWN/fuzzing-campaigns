# RFC 0001: fuzzing-campaigns design

- **Status:** Accepted (M1 implemented)
- **Author:** EquinoxWN
- **Created:** 2026

## Problem

Parsers are where untrusted bytes first meet code. Hand-written tests check the inputs a person
thinks of; the bugs that matter are in the ones nobody thinks of: an escape at the very end of a
line, a quantifier after an anchor, a printer that drops a needed parenthesis. Coverage-guided
fuzzing finds those by mutating inputs and keeping the ones that reach new code. Fuzzing only
works well when three things exist for each parser: a **fuzz target** that wraps the entry point
and says which failures are acceptable rejections, an **oracle** that can tell a wrong answer from
a right one (not only a crash), and a **seed corpus and dictionary** so the fuzzer starts from
valid structure instead of random bytes. This repo builds those for its own parsers and measures
what seeds and dictionaries are worth.

Users: developers who maintain parsers (config formats, query or rule languages, regex front
ends) and want a repeatable way to fuzz them, and students learning how coverage-guided fuzzing
works without a Linux machine.

## Critical-to-quality measures (Define)

| Measure | Target (M1) | How it is measured |
|---|---|---|
| Every target has a harness, an oracle beyond "no crash", seeds and a dictionary | 4 of 4 targets | `test_targets.py`, `test_every_packaged_*` tests |
| Seeds and dictionaries speed up discovery | seeds+dict reach more edges than bare on every target, and find the canary bug in at least 4 of 5 runs where bare finds it in 0 of 5 | `fuzzcamp bench` (fixed budget, 5 RNG seeds) |
| Findings are reproducible | same RNG seed gives the same corpus and findings; a saved crash replays to the same key | `test_same_seed_same_campaign`, `test_findings_are_deduplicated_by_type_and_line` |
| Short local runs | each campaign bounded by executions and seconds; tests under 2 minutes | `FuzzConfig`, pytest timing |
| No crash in the real parsers | 0 findings in a 60-second campaign per real parser | `make campaign` |

## Goals

- **Fuzz targets wrap each parser's entry point (M1).** A target is `fuzz_one(data: bytes)`:
  decode, parse, and run the oracle. `ParseError` is a documented rejection; any other exception
  or an `InvariantError` from the oracle is a finding.
- **Seed corpora and dictionaries speed up discovery (M1).** Each target ships `seeds/` and an
  AFL/libFuzzer dictionary that both engines read, and a bench shows the effect.
- Later: hour-long campaigns with crash minimization and de-duplication (M2), a root-cause
  write-up, fix and regression test per bug (M2), Jazzer targets for the Java repos
  (rules-dsl-compiler, regex-engine) (M2), coverage reports and fuzzing on every pull request (M3).

## Non-goals

- Fuzzing third-party software or remote services. Every target is code in this repository.
- Memory-safety bugs in C extensions; the M1 targets are pure Python, so findings are exceptions,
  hangs and wrong answers.
- Long campaigns on the author's machine: local runs last seconds to a minute.

## Proposed design

```
seeds/ + <target>.dict ─► engine (pure Python, sys.settrace edges)  ─┐
                       └► Atheris / libFuzzer (Linux, CI)            ─┤─► fuzz_one(data)
                                                                      │     parse ─► oracle
                                                                      └─► corpus/, crashes/, stats.json
```

| Part | M1 implementation |
|---|---|
| Targets | `kvconfig` (INI-style config parser; oracle: `dump` then `parse` gives the same config), `regex` (regex subset parser for a linear-time engine; oracles: print round trip, and every accepted pattern must also compile in Python's `re`), `rules` (Pratt parser modelled on rules-dsl-compiler; oracle: minimal-parentheses printer round trip), `canary` (one planted `IndexError` for measuring time-to-crash) |
| Engine | libFuzzer-style loop: run seeds, pick a corpus entry, apply 1 to 4 stacked mutations (bit flip, interesting byte, random byte, delete, insert, duplicate, dictionary insert or overwrite, splice), run under edge tracing, keep inputs that reach new edges |
| Coverage | `sys.settrace` on the target's own file only; an edge is (file, previous line, line) within a frame; a per-input step budget raises `Hang` |
| Findings | key = exception type + innermost target line; first input kept, hits counted; saved as `crashes/<key>-<sha1>` |
| Storage | content-addressed (`sha1`) corpus files, written by temp file and `os.replace`, so re-saving is a no-op and readers never see half a file |
| Atheris | `fuzzcamp-atheris` instruments the target module, passes the dictionary with `-dict=` and the seeds as a read-only corpus folder; CI runs it on ubuntu |
| Bench | `fuzzcamp bench`: per target, `bare` (empty start, no dictionary), `seeds`, `seeds+dict`, each for 5 RNG seeds at a fixed execution budget |

Inputs are bounded: 4,096 bytes per fuzz input by default, 64 KiB per seed file, 1,000 seeds,
1,000 dictionary tokens of at most 128 bytes, and each parser has its own size and nesting limit
so deep input is a `ParseError`, not a `RecursionError`.

## Alternatives considered

| Option | Why not (yet) |
|---|---|
| Atheris only | It is the right engine for long runs and native code, but it ships Linux and macOS wheels only; the author's machine is Windows. Keeping Atheris for CI and adding a small pure-Python engine lets the same targets run everywhere (ADR 0002). |
| Hypothesis (property-based testing) | Strong for generating structured values from strategies, but it is not coverage-guided over raw bytes and does not use libFuzzer corpora or dictionaries; it would need a second set of generators per parser. The round-trip oracles here would port to it easily. |
| Fuzz the Java repos with Jazzer in M1 | Needs a JVM build of rules-dsl-compiler and regex-engine inside this repo or a cross-repo checkout; deferred to M2, with Python models of both grammars as M1 targets. |
| Crash-only oracle | Cheaper, but a printer that drops parentheses or a parser that accepts what `re` rejects never crashes. Round-trip and differential oracles catch wrong answers (ADR 0003). |

## Measurement plan

- `make test`: every parser, oracle, the engine, corpus and dictionary handling and the CLI.
- `make bench`: 4 targets x 3 set-ups x 5 seeds x 10,000 executions; reports mean edges, mean line
  coverage of the target file, how many runs found a finding and the median executions to the
  first one. Execution counts are deterministic; time per run depends on the machine.
- `make campaign`: 60 seconds per real parser; any finding fails the command.
- CI: the same tests on Python 3.12, a canary bench, and Atheris runs (20 s per real parser, and the
  canary must crash and replay to the same finding key).

## Milestones

- **M1:** Fuzz targets wrap each parser's entry point. Seed corpora and dictionaries speed up discovery.
- **M2:** Fuzzers run for hours; crashes are minimized and de-duplicated. Each bug gets a root-cause write-up, a fix and a regression test.
- **M3:** Coverage reports show which code is still unexplored. CI runs short fuzz sessions on every PR.

## Risks and open questions

- `sys.settrace` made each execution of the seed inputs 10 to 21 times slower than an untraced
  call in a local measurement (`docs/results/m1.md`), so the local
  engine reaches thousands, not millions, of executions per second. It is enough for these
  parsers; long campaigns belong to Atheris.
- Line edges are coarser than libFuzzer's comparison tracing: a magic value checked in one
  `==` gives no gradient, which is exactly what dictionaries compensate for (the canary shows it).
- The differential oracle assumes Python's `re` is right where the subsets overlap. A disagreement
  is investigated, not automatically blamed on the parser.
