"""Render a Result for a person.

The report never reads as clean while any agent config went unread. Unknown is not
the same as safe, and a detective control that says "clean" on partial coverage is
worse than one that says nothing.
"""

from __future__ import annotations

from .scan import Result

__all__ = ["render_text"]


def render_text(result: Result, gaps) -> str:
    reachable = [e for e in result.exposures if e.reachable]
    unreachable = [e for e in result.exposures if not e.reachable]
    lines: list[str] = []

    n = len(reachable)
    if n:
        noun = "file" if n == 1 else "files"
        lines.append(f"{n} {noun} with sensitive content reachable by an agent.")
    elif gaps:
        lines.append("0 files reachable by the agents whose configs could be read.")
    else:
        lines.append("No sensitive content reachable by any agent that was found.")

    if gaps:
        lines.append("")
        lines.append("Coverage is incomplete. These agent configs could not be read, so")
        lines.append("anything they grant is unknown rather than clear:")
        for g in gaps:
            lines.append(f"  {g.path}  ({g.reason})")

    worst = max(result.copies_per_identifier.values(), default=0)
    lines.append("")
    lines.append(
        f"Scanned {result.scanned_files} files. "
        f"{len(result.exposures)} hold sensitive content. "
        f"Most copies of a single identifier: {worst}."
    )
    if result.skipped_large or result.skipped_binary:
        lines.append(
            f"Skipped {result.skipped_large} oversized and {result.skipped_binary} binary or unreadable files."
        )

    if reachable:
        lines.append("")
        lines.append("Reachable by an agent:")
        for e in sorted(reachable, key=lambda e: e.path):
            egress = f"  egress: {', '.join(e.egress)}" if e.egress else ""
            lines.append(f"  {e.path}")
            lines.append(f"    {', '.join(sorted(set(e.detectors)))}  via {', '.join(e.agents)}{egress}")

    if unreachable:
        lines.append("")
        lines.append("Sensitive, not reachable by any agent found:")
        for e in sorted(unreachable, key=lambda e: e.path):
            lines.append(f"  {e.path}  ({', '.join(sorted(set(e.detectors)))})")

    return "\n".join(lines) + "\n"
