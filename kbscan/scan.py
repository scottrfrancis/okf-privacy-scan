"""Walk a corpus, detect, and join the result against the agent grants.

The join is the point. Every audit anyone runs is a per-system audit, and the failure
is in the joins between systems, because a join is not a thing anybody owns.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import detectors, locations
from .harnesses import Grant

__all__ = ["Exposure", "Result", "Diff", "assess", "diff"]

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
DEFAULT_MAX_BYTES = 512 * 1024 * 1024   # a safety cap, not a filter
DEFAULT_CHUNK = 1024 * 1024
_SNIFF = 8192
VALUELESS = {"declared-sensitive", "encrypted-location", "declared-location"}


@dataclass(frozen=True)
class Exposure:
    """One file that holds sensitive content, and who can reach it.

    `agents` and `egress` are stored rather than derived so that a result restored
    from a saved baseline carries the same answer as a live one. `grants` holds the
    live Grant objects when there are any and is never serialised.
    """

    path: str
    detectors: tuple[str, ...]
    fingerprints: tuple[str, ...]
    agents: tuple[str, ...] = ()
    egress: tuple[str, ...] = ()
    grants: list[Grant] = field(default_factory=list, compare=False, repr=False)

    @classmethod
    def build(cls, path: str, found, grants: list[Grant]) -> "Exposure":
        return cls(
            path=path,
            detectors=tuple(f.detector for f in found),
            fingerprints=tuple(sorted({f.fingerprint for f in found})),
            agents=tuple(sorted({g.agent for g in grants})),
            egress=tuple(sorted({e for g in grants for e in g.egress})),
            grants=list(grants),
        )

    @property
    def reachable(self) -> bool:
        return bool(self.agents)

    @property
    def key(self) -> tuple:
        return (self.path, self.fingerprints)


@dataclass
class Result:
    exposures: list[Exposure] = field(default_factory=list)
    copies_per_identifier: dict[str, int] = field(default_factory=dict)
    skipped_large: int = 0
    skipped_binary: int = 0
    scanned_files: int = 0

    @property
    def exposed_count(self) -> int:
        return sum(1 for e in self.exposures if e.reachable)

    @property
    def finding_count(self) -> int:
        return sum(len(e.detectors) for e in self.exposures)

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema": 1,
                "scanned_files": self.scanned_files,
                "skipped_large": self.skipped_large,
                "skipped_binary": self.skipped_binary,
                "copies_per_identifier": self.copies_per_identifier,
                "exposures": [
                    {
                        "path": e.path,
                        "detectors": list(e.detectors),
                        "fingerprints": list(e.fingerprints),
                        "agents": list(e.agents),
                        "egress": list(e.egress),
                    }
                    for e in self.exposures
                ],
            },
            indent=2,
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, blob: str) -> "Result":
        data = json.loads(blob)
        out = cls(
            copies_per_identifier=data.get("copies_per_identifier", {}),
            skipped_large=data.get("skipped_large", 0),
            skipped_binary=data.get("skipped_binary", 0),
            scanned_files=data.get("scanned_files", 0),
        )
        for e in data.get("exposures", []):
            out.exposures.append(Exposure(
                path=e["path"],
                detectors=tuple(e["detectors"]),
                fingerprints=tuple(e["fingerprints"]),
                agents=tuple(e.get("agents", ())),
                egress=tuple(e.get("egress", ())),
            ))
        return out


def _classify(path: Path, max_bytes: int) -> str | None:
    """Return a reason to skip, or None if the file should be scanned."""
    try:
        if path.stat().st_size > max_bytes:
            return "large"
        with path.open("rb") as fh:
            head = fh.read(_SNIFF)
    except OSError:
        return "unreadable"
    return "binary" if b"\x00" in head else None


def _chunks(path: Path, chunk_bytes: int):
    """Yield (text, lines_before) in line-aligned chunks.

    Every detector matches within a single line, so splitting on newlines cannot cut
    a match in half. Large files are streamed rather than skipped, because agent
    transcripts are routinely far over any sensible whole-file limit.
    """
    buf: list[str] = []
    size = 0
    before = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            buf.append(line)
            size += len(line)
            if size >= chunk_bytes:
                yield "".join(buf), before
                before += len(buf)
                buf, size = [], 0
    if buf:
        yield "".join(buf), before


def _walk(targets, max_bytes):
    """Yield (target, path) so that declared globs can be matched relative to a target."""
    for target in targets:
        target = Path(target)
        if target.is_file():
            yield target.parent, target
            continue
        for path in sorted(target.rglob("*")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and not path.is_symlink():
                yield target, path


def assess(targets, grants, salt: bytes, roster=None, max_bytes: int = DEFAULT_MAX_BYTES,
           chunk_bytes: int = DEFAULT_CHUNK, sensitive_globs=()) -> Result:
    result = Result()
    per_identifier: dict[str, set[str]] = {}
    grants = list(grants)

    files = list(_walk(targets, max_bytes))
    encrypted = locations.encrypted_paths(p for _, p in files)

    for target, path in files:
        why = _classify(path, max_bytes)
        if why == "large":
            result.skipped_large += 1
            continue
        if why in ("binary", "unreadable"):
            result.skipped_binary += 1
            continue
        result.scanned_files += 1

        found = []
        for i, (text, before) in enumerate(_chunks(path, chunk_bytes)):
            found += detectors.scan_text(text, salt=salt, roster=roster,
                                         front_matter=(i == 0), line_offset=before)

        if path.name not in locations.NOT_CONTENT:
            if path in encrypted:
                found.append(detectors.Finding(
                    "encrypted-location", 0, "location",
                    "plaintext in a path configured for encryption"))
            elif sensitive_globs and locations.matches_declared(path.relative_to(target), sensitive_globs):
                found.append(detectors.Finding(
                    "declared-location", 0, "location", "matches a declared sensitive path"))

        if not found:
            continue

        covering = [g for g in grants if _covers(g.root, path)]
        result.exposures.append(Exposure.build(str(path), found, covering))

        for f in found:
            if f.detector in VALUELESS:
                continue
            per_identifier.setdefault(f.fingerprint, set()).add(str(path))

    result.copies_per_identifier = {k: len(v) for k, v in per_identifier.items()}
    return result


def _covers(root: Path, path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(Path(root).resolve())
    except (OSError, ValueError):
        return False


@dataclass
class Diff:
    new: list[Exposure] = field(default_factory=list)
    resolved: list[Exposure] = field(default_factory=list)


def diff(baseline: Result, current: Result) -> Diff:
    before = {e.key: e for e in baseline.exposures}
    after = {e.key: e for e in current.exposures}
    return Diff(
        new=[after[k] for k in after.keys() - before.keys()],
        resolved=[before[k] for k in before.keys() - after.keys()],
    )
