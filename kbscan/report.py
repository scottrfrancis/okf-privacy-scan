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

    lines.append("")
    lines.append("Directories passed to an agent on its command line appear in no file, so")
    lines.append("they cannot be discovered. Declare any you use with --assume-root PATH.")

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


def render_summary(result: Result, gaps) -> str:
    """Counts only. Safe to show an agent whose context leaves the perimeter.

    Paths are disclosure too: a filename can name a clinician, a relative, or a
    client. This view carries the numbers a detective control needs and nothing
    that locates a record.
    """
    from collections import Counter

    reachable = [e for e in result.exposures if e.reachable]
    by_detector = Counter(d for e in result.exposures for d in set(e.detectors))
    by_agent = Counter(a for e in reachable for a in e.agents)
    by_egress = Counter(x for e in reachable for x in e.egress)

    lines = [
        f"reachable: {len(reachable)}",
        f"sensitive_files: {len(result.exposures)}",
        f"scanned_files: {result.scanned_files}",
        f"max_copies_of_one_identifier: {max(result.copies_per_identifier.values(), default=0)}",
        f"config_gaps: {len(gaps)}",
        f"coverage: {'incomplete' if gaps else 'complete for the agents found'}",
        "launch_roots_visible: partial",
        "by_detector:",
        *[f"  {k}: {v}" for k, v in sorted(by_detector.items())],
        "reachable_by_agent:",
        *[f"  {k}: {v}" for k, v in sorted(by_agent.items())],
        "reachable_by_egress:",
        *[f"  {k}: {v}" for k, v in sorted(by_egress.items())],
    ]
    return "\n".join(lines) + "\n"
