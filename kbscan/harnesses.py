"""Which directories were handed to which agent, and what each one can reach.

The grant is made once, in a config file, for a reason that made sense at the time,
and then it is never looked at again while the directory underneath it grows. This
module reads those grants back out.

A config we cannot parse is reported as a gap rather than skipped. Unknown must not
read as clean.
"""

from __future__ import annotations

import json
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


def discover_with_gaps(home: Path) -> tuple[list[Grant], list[ConfigGap]]:
    grants: list[Grant] = []
    gaps: list[ConfigGap] = []
    for rel, adapter in _ADAPTERS.items():
        source = Path(home) / rel
        if not source.exists():
            continue
        data, problem = _load(source)
        if problem:
            gaps.append(ConfigGap(source, problem))
            continue
        grants.extend(adapter(data, source))
    return grants, gaps


def discover(home: Path) -> list[Grant]:
    return discover_with_gaps(home)[0]
