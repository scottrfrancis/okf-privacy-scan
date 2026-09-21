"""Sensitivity that comes from where a file sits rather than what it contains.

A path you configured for encryption is a path you consider sensitive. Transparent
encryption decrypts in the working tree, so a plaintext file in such a path is the
exact case where the control you set up protects the copy on somebody else's disk
and not the one an agent can open.

Git's own matching is used rather than a reimplementation, so nested .gitattributes
files are honoured. Those are the ones an audit from the root file alone misses.
"""

from __future__ import annotations

import fnmatch
import shutil
import subprocess
from pathlib import Path

__all__ = ["encrypted_paths", "matches_declared", "NOT_CONTENT"]

NOT_CONTENT = {".gitattributes", ".gitignore"}


def _repo_root(path: Path, cache: dict) -> Path | None:
    for parent in path.parents:
        if parent in cache:
            return cache[parent]
        if (parent / ".git").exists():
            cache[parent] = parent
            return parent
    return None


def encrypted_paths(files) -> set[Path]:
    """Files whose git `filter` attribute is git-crypt. Empty if git is unavailable.

    Without git there is no git-crypt, so there is no decrypted working tree to find,
    and an empty answer is correct rather than a gap.
    """
    if shutil.which("git") is None:
        return set()

    by_repo: dict[Path, list[Path]] = {}
    cache: dict = {}
    for f in files:
        root = _repo_root(Path(f), cache)
        if root is not None:
            by_repo.setdefault(root, []).append(Path(f))

    hits: set[Path] = set()
    for root, members in by_repo.items():
        rel = [m.relative_to(root).as_posix() for m in members]
        try:
            out = subprocess.run(
                ["git", "-C", str(root), "check-attr", "--stdin", "-z", "filter"],
                input="\0".join(rel) + "\0", capture_output=True, text=True, check=True,
            ).stdout
        except (subprocess.CalledProcessError, OSError):
            continue
        fields = out.split("\0")
        for i in range(0, len(fields) - 2, 3):
            path, _attr, value = fields[i:i + 3]
            if value == "git-crypt":
                hits.add(root / path)
    return hits


def matches_declared(relative: Path, globs) -> bool:
    """fnmatch semantics, where * also matches across directory separators."""
    rel = relative.as_posix()
    return any(fnmatch.fnmatch(rel, g) for g in globs)
