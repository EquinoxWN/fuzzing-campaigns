# Contributing

Thanks for helping. This is a Python project; issues and pull requests are welcome.

## Set up and check your change

Needs Python 3.11+. Atheris runs in CI (Linux wheels only). Caches and fuzzing output stay in
git-ignored folders inside the repo (`.tmp/`).

```bash
make setup     # install the package and dev tools
make lint      # ruff, ruff format, mypy --strict
make test      # full test suite (short fuzz runs included)
make campaign  # 60 seconds per real parser; fails on any finding
make audit     # known-vulnerability check (as in CI)
```

A pull request is ready when `make lint` and `make test` pass and CI is green.

## Adding a fuzz target

1. Put the parser in `src/fuzzing_campaigns/targets/<module>.py` with a `fuzz_one(data: bytes)`
   that raises `ParseError` for rejections and `InvariantError` when an oracle fails.
2. Register it in `targets/__init__.py`.
3. Add `campaigns/<name>/seeds/` (valid inputs) and `campaigns/<name>/<name>.dict`.
4. Add tests for accepted input, rejections and the oracle, and run `fuzzcamp bench --targets <name>`.

## Guidelines

- Fuzz only code in this repository; never point a target at a remote service.
- Every bug found by fuzzing gets a regression test with the input that found it.
- Significant design changes need an ADR in `docs/adr/` (copy `0001` for the format).
- Keep function comments to one short phrase; let names and tests explain the rest.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
