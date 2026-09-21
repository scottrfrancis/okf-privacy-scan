"""The places ordinary tooling skips.

Secret scanners are pointed at repositories. The copies that matter are in the shell
history, the agent session directories, and folders that quietly replicate to a
vendor, because those are where a value lands after somebody used it once.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["derived_copy_targets", "sync_root", "SHELL_HISTORIES", "AGENT_SESSION_DIRS"]

SHELL_HISTORIES = (
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
    ".node_repl_history",
    ".sqlite_history",
)

AGENT_SESSION_DIRS = (
    ".claude/projects",
    ".factory/sessions",
    ".openclaw/state",
    ".cursor/chats",
    ".codex/sessions",
)

_SYNC_MARKERS = (
    ("OneDrive", "onedrive"),
    ("Dropbox", "dropbox"),
    ("GoogleDrive", "google-drive"),
    ("Google Drive", "google-drive"),
    ("Mobile Documents", "icloud"),
    ("com~apple~CloudDocs", "icloud"),
)


def derived_copy_targets(home: Path) -> list[Path]:
    home = Path(home)
    found = [home / h for h in SHELL_HISTORIES if (home / h).is_file()]
    found += [home / d for d in AGENT_SESSION_DIRS if (home / d).is_dir()]
    return found


def sync_root(path: Path) -> str | None:
    for part in Path(path).parts:
        for marker, name in _SYNC_MARKERS:
            if marker in part:
                return name
    return None
