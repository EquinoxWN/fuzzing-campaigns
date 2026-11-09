# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/fuzzing-campaigns/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** A parser in `src/fuzzing_campaigns/targets/` that crashes, hangs or gives a wrong
  answer on some input (other than the documented, planted bug in `canary.py`); unbounded memory
  or time in the engine; unsafe handling of seed, dictionary or output files.
- **Out of scope:** Bugs in Atheris, libFuzzer or Python itself (report those upstream).

## What this repository does and does not do

- Every fuzz target is code in this repository. Nothing here fuzzes, scans or connects to other
  hosts; the engine makes no network calls.
- Inputs are bounded: 4,096 bytes per fuzz input by default, 64 KiB per seed file, 1,000 seeds,
  1,000 dictionary tokens, and size and nesting limits in each parser.
- Every GitHub Action is pinned to a full commit SHA; workflows run read-only without persisted
  credentials. Dependabot pull requests are paused (`open-pull-requests-limit: 0`) so the
  repository keeps a single `main` branch; CI runs `pip-audit` on every push.
