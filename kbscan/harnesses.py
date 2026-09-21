"""Which directories were handed to which agent, and what each one can reach.

The grant is made once, in a config file, for a reason that made sense at the time,
and then it is never looked at again while the directory underneath it grows. This
module reads those grants back out.

A config we cannot parse is reported as a gap rather than skipped. Unknown must not
read as clean.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Grant", "ConfigGap", "discover", "discover_with_gaps", "KNOWN_CONFIGS"]


@dataclass(frozen=True)
class Grant:
    agent: str
    root: Path
    source: Path
    models: str = "unknown"          # cloud | local | unknown
    egress: tuple[str, ...] = field(default_factory=tuple)
    kind: str = "declared"           # declared | implicit | assumed


@dataclass(frozen=True)
class ConfigGap:
    path: Path
    reason: str


KNOWN_CONFIGS = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".openclaw/openclaw.json",
)


def _load(path: Path) -> tuple[dict | None, str | None]:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON ({exc.msg})"
    except OSError as exc:
        return None, f"unreadable ({exc.strerror})"
    if not isinstance(data, dict):
        return None, "top level is not an object"
    return data, None


def _claude_code(data: dict, source: Path) -> list[Grant]:
    dirs = data.get("additionalDirectories")
    if dirs is None:
        dirs = (data.get("permissions") or {}).get("additionalDirectories")
    return [
        Grant("claude-code", Path(d), source, models="cloud", egress=("cloud-model",))
        for d in (dirs or [])
        if isinstance(d, str)
    ]


def _openclaw(data: dict, source: Path) -> list[Grant]:
    profiles = (data.get("auth") or {}).get("profiles") or {}
    models = "cloud" if profiles else "local"

    egress: list[str] = []
    if models == "cloud":
        egress.append("cloud-model")
    web = (data.get("tools") or {}).get("web") or {}
    if web.get("fetch") or web.get("search"):
        egress.append("web")
    if data.get("channels") or data.get("slack"):
        egress.append("chat-relay")

    workspace = data.get("workspace")
    if not isinstance(workspace, str):
        return []
    return [Grant("openclaw", Path(workspace), source, models=models, egress=tuple(egress))]


_ADAPTERS = {
    ".claude/settings.json": _claude_code,
    ".claude/settings.local.json": _claude_code,
    ".openclaw/openclaw.json": _openclaw,
}


_PRUNE = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox"}


def _project_claude_dirs(search_roots, home: Path):
    """Find .claude directories under the search roots.

    A .claude directory is evidence that an agent is launched in its parent, which
    makes the parent a working root even though no file records it as one. The
    global config at ~/.claude is excluded: it is configuration, not a launch site.
    """
    home = Path(home).resolve()
    for root in search_roots:
        root = Path(root)
        if not root.is_dir():
            continue
        for dirpath, dirnames, _ in os.walk(root):
            if ".claude" in dirnames:
                found = Path(dirpath) / ".claude"
                if Path(dirpath).resolve() != home:
                    yield found
                dirnames.remove(".claude")
            dirnames[:] = [d for d in dirnames if d not in _PRUNE]


def discover_with_gaps(home: Path, search_roots=(), assumed_roots=()) -> tuple[list[Grant], list[ConfigGap]]:
    grants: list[Grant] = []
    gaps: list[ConfigGap] = []

    def read(source: Path, adapter):
        data, problem = _load(source)
        if problem:
            gaps.append(ConfigGap(source, problem))
        else:
            grants.extend(adapter(data, source))

    for rel, adapter in _ADAPTERS.items():
        source = Path(home) / rel
        if source.exists():
            read(source, adapter)

    for claude_dir in _project_claude_dirs(search_roots, home):
        grants.append(Grant("claude-code", claude_dir.parent, claude_dir,
                            models="cloud", egress=("cloud-model",), kind="implicit"))
        for name in ("settings.json", "settings.local.json"):
            source = claude_dir / name
            if source.is_file():
                read(source, _claude_code)

    for root in assumed_roots:
        grants.append(Grant("assumed", Path(root), Path("--assume-root"),
                            models="unknown", kind="assumed"))

    return grants, gaps


def discover(home: Path) -> list[Grant]:
    return discover_with_gaps(home)[0]
