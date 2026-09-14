"""Explicit file selection and budgets, independent of result-state vocabularies."""

from dataclasses import dataclass, field
import fnmatch
import glob
import os
from pathlib import Path
import stat
import time

from .patterns import detect, safe_location, wordlist


class Unavailable(Exception):
    """A fixed, content-free explanation of missing evidence."""


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 262144
    max_total_bytes: int = 1048576
    max_files: int = 8
    max_seconds: float = 5
    max_directory_entries: int = 128

    def __post_init__(self):
        for name, ceiling in (("max_file_bytes", 1048576), ("max_total_bytes", 8388608),
                              ("max_files", 64), ("max_directory_entries", 1024)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError("Invalid file budget")
        if type(self.max_seconds) not in (int, float) or not 0 < self.max_seconds <= 30:
            raise ValueError("Invalid time budget")


@dataclass(frozen=True)
class Read:
    data: bytes = field(repr=False)
    partial: bool
    mode: int
    uid: int


def read_regular(path, limit):
    """Scanner's O_NOFOLLOW/O_NONBLOCK/fstat read, with metadata from that fd."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Unavailable("Selected object is not a regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        fields = ("st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid")
        changed = any(getattr(before, key) != getattr(after, key) for key in fields)
        return Read(data[:limit], len(data) > limit or changed,
                    stat.S_IMODE(after.st_mode), after.st_uid)
    except OSError:
        raise Unavailable("File unavailable, symlink, or read failed") from None
    finally:
        if fd is not None:
            os.close(fd)


def select_files(pattern, max_entries=128):
    path = Path(pattern)
    if not path.is_absolute() or glob.has_magic(str(path.parent)) or "**" in path.name:
        raise Unavailable("Only absolute paths and a final nonrecursive glob are supported")
    if not glob.has_magic(path.name):
        return [str(path)], False
    selected, partial = [], False
    try:
        with os.scandir(path.parent) as entries:
            for count, entry in enumerate(entries):
                if count >= max_entries:
                    partial = True
                    break
                if fnmatch.fnmatchcase(entry.name, path.name):
                    selected.append(entry.path)
    except OSError:
        raise Unavailable("Directory selection unavailable") from None
    return sorted(selected), partial


class Budget:
    def __init__(self, limits=None):
        self.limits = limits or Limits()
        self.deadline = time.monotonic() + self.limits.max_seconds
        self.remaining = self.limits.max_total_bytes
        self.files = 0

    def read(self, path):
        if (self.remaining <= 0 or self.files >= self.limits.max_files
                or time.monotonic() >= self.deadline):
            raise Unavailable("File, byte, or time budget exhausted")
        self.files += 1
        result = read_regular(path, min(self.remaining, self.limits.max_file_bytes))
        self.remaining -= len(result.data)
        return result


def inspect_files(paths, limits=None):
    """Yield only metadata; inconclusive coverage stays separate from findings."""
    budget = Budget(limits)
    vocabulary = wordlist()
    seen = set()
    for pattern in paths:
        try:
            if time.monotonic() >= budget.deadline:
                raise Unavailable("Time budget exhausted")
            selected, partial = select_files(pattern, budget.limits.max_directory_entries)
            if partial or not selected:
                yield {"location": safe_location(pattern), "complete": False,
                       "reason": "Selection incomplete or empty", "counts": {}, "candidates": {}}
            for path in selected:
                if path in seen:
                    continue
                seen.add(path)
                result = budget.read(path)
                counts, candidates, timed_out = detect(
                    result.data.decode("utf-8", errors="replace"), vocabulary, budget.deadline)
                complete = not (result.partial or timed_out or time.monotonic() >= budget.deadline)
                yield {"location": safe_location(path), "complete": complete,
                       "counts": counts, "candidates": candidates}
        except Unavailable as error:
            yield {"location": safe_location(pattern), "complete": False,
                   "reason": str(error), "counts": {}, "candidates": {}}
