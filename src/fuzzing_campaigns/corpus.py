"""Seed corpora and campaign output on disk: bounded reads and atomic, idempotent writes."""

from __future__ import annotations

import hashlib
import os
import tempfile
from importlib import resources
from pathlib import Path

from fuzzing_campaigns.dictionary import load_dictionary

MAX_SEEDS = 1000
MAX_SEED_BYTES = 64 * 1024


class CorpusError(ValueError):
    """A seed corpus that breaks the size or count limits."""


def campaign_dir(target: str) -> Path:
    """Packaged campaign folder (seeds/ and <target>.dict) for a target."""
    root = resources.files("fuzzing_campaigns") / "campaigns" / target
    path = Path(str(root))
    if not path.is_dir():
        raise CorpusError(f"no packaged campaign for target {target!r}")
    return path


def load_seeds(directory: Path) -> list[bytes]:
    """Every file in a seed directory, sorted by name so runs are reproducible."""
    if not directory.is_dir():
        raise CorpusError(f"{directory} is not a directory")
    files = sorted(p for p in directory.iterdir() if p.is_file())
    if len(files) > MAX_SEEDS:
        raise CorpusError(f"{directory}: {len(files)} seeds is over the limit of {MAX_SEEDS}")
    seeds: list[bytes] = []
    for path in files:
        size = path.stat().st_size
        if size > MAX_SEED_BYTES:
            raise CorpusError(f"{path}: {size} bytes is over the {MAX_SEED_BYTES}-byte seed limit")
        seeds.append(path.read_bytes())
    return seeds


def packaged_seeds(target: str) -> list[bytes]:
    """The packaged seed corpus of a target."""
    return load_seeds(campaign_dir(target) / "seeds")


def packaged_dictionary(target: str) -> list[bytes]:
    """The packaged dictionary of a target."""
    return load_dictionary(campaign_dir(target) / f"{target}.dict")


def content_name(data: bytes) -> str:
    """Stable file name for an input: the SHA-1 of its bytes, as libFuzzer names them."""
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file in the same folder and rename, so readers never see half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def save_input(directory: Path, data: bytes, prefix: str = "") -> Path:
    """Store an input under its content name; saving the same bytes twice is a no-op."""
    path = directory / f"{prefix}{content_name(data)}"
    if not path.exists():
        atomic_write(path, data)
    return path
