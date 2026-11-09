.PHONY: setup lint test bench campaign audit ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -e ".[dev]"

# ruff, ruff format and mypy --strict.
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy

# Parsers, oracles, engine, corpus, dictionaries and CLI (short fuzz runs included).
test:
	$(PY) -m pytest -q

# Seeds and dictionaries against a bare start: 4 targets x 3 set-ups x 5 RNG seeds, 10,000 executions each.
bench:
	fuzzcamp bench --runs 10000 --seeds 0,1,2,3,4 --out .tmp/bench.json

# A 60-second campaign per real parser; corpus, crashes and stats go to .tmp/.
campaign:
	for t in kvconfig regex rules; do fuzzcamp run $$t --runs 1000000 --seconds 60 --seed 11 --out .tmp/camp-$$t --fail-on-finding || exit 1; done

# Known vulnerabilities in the installed Python dependencies.
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

ci: setup lint test
