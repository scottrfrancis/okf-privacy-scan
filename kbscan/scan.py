"""Walk a corpus, detect, and join the result against the agent grants.

The join is the point. Every audit anyone runs is a per-system audit, and the failure
is in the joins between systems, because a join is not a thing anybody owns.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import detectors
from .harnesses import Grant

__all__ = ["Exposure", "Result", "Diff", "assess", "diff"]

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
DEFAULT_MAX_BYTES = 1_000_000
VALUELESS = {"declared-sensitive"}


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


def _readable_text(path: Path, max_bytes: int) -> tuple[str | None, str | None]:
    try:
        if path.stat().st_size > max_bytes:
            return None, "large"
        raw = path.read_bytes()
    except OSError:
        return None, "unreadable"
    if b"\x00" in raw:
        return None, "binary"
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "binary"


def _walk(targets, max_bytes):
    for target in targets:
        target = Path(target)
        if target.is_file():
            yield target
            continue
        for path in sorted(target.rglob("*")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and not path.is_symlink():
                yield path


def assess(targets, grants, salt: bytes, roster=None, max_bytes: int = DEFAULT_MAX_BYTES) -> Result:
    result = Result()
    per_identifier: dict[str, set[str]] = {}
    grants = list(grants)

    for path in _walk(targets, max_bytes):
        text, why = _readable_text(path, max_bytes)
        if why == "large":
            result.skipped_large += 1
            continue
        if why in ("binary", "unreadable"):
            result.skipped_binary += 1
            continue
        result.scanned_files += 1

        found = detectors.scan_text(text, salt=salt, roster=roster)
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
