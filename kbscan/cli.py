"""kbscan: find sensitive content an agent can reach.

    kbscan assess   [PATH ...]                 one-off assessment
    kbscan baseline [PATH ...] --out FILE      record the current state
    kbscan check    [PATH ...] --baseline FILE detective run, exits 1 on anything new
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

from . import harnesses, report, scan, targets

DEFAULT_CONFIG = Path("~/.config/kbscan").expanduser()


def _salt(config_dir: Path) -> bytes:
    """A persistent local salt. A fresh one would break every saved baseline."""
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = config_dir / "salt"
    if path.exists():
        return path.read_bytes()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    os.chmod(path, 0o600)
    return path.read_bytes()


def _roster(explicit: str | None, config_dir: Path) -> list[str]:
    path = Path(explicit) if explicit else config_dir / "roster.txt"
    if not path.is_file():
        return []
    return [ln.strip() for ln in path.read_text().splitlines() if ln.strip() and not ln.startswith("#")]


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kbscan", description="Find sensitive content an agent can reach.")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("paths", nargs="*", help="directories or files to scan")
        sp.add_argument("--home", default=str(Path.home()), help="home directory to read agent configs from")
        sp.add_argument("--config-dir", default=str(DEFAULT_CONFIG), help="where the salt and roster live")
        sp.add_argument("--roster", help="file of names to treat as identifiers, one per line")
        sp.add_argument("--no-derived", action="store_true",
                        help="skip shell history and agent session directories")
        sp.add_argument("--json", action="store_true", help="emit JSON instead of text")
        sp.add_argument("--assume-root", action="append", default=[], metavar="PATH",
                        help="a directory you launch agents in; repeatable")
        sp.add_argument("--sensitive-path", action="append", default=[], metavar="GLOB",
                        help="treat files matching GLOB, relative to a scanned path, as sensitive")
        sp.add_argument("--summary", action="store_true",
                        help="counts only, no paths; use this when an agent reads the output")

    common(sub.add_parser("assess", help="one-off assessment"))
    b = sub.add_parser("baseline", help="record current state for later checks")
    common(b)
    b.add_argument("--out", required=True)
    c = sub.add_parser("check", help="compare against a baseline; exit 1 on anything new")
    common(c)
    c.add_argument("--baseline", required=True)
    return p


def _run(args) -> tuple[scan.Result, list]:
    home = Path(args.home)
    config_dir = Path(args.config_dir)
    paths = [Path(p) for p in args.paths]
    grants, gaps = harnesses.discover_with_gaps(
        home, search_roots=paths, assumed_roots=[Path(p) for p in args.assume_root])
    if not args.no_derived:
        paths += targets.derived_copy_targets(home)
    result = scan.assess(paths, grants, salt=_salt(config_dir), roster=_roster(args.roster, config_dir),
                         sensitive_globs=args.sensitive_path)
    return result, gaps


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    result, gaps = _run(args)

    if args.command == "baseline":
        Path(args.out).write_text(result.to_json())
        print(f"baseline written: {args.out} ({len(result.exposures)} files with sensitive content)")
        return 0

    if args.command == "check":
        base = scan.Result.from_json(Path(args.baseline).read_text())
        d = scan.diff(base, result)
        for e in sorted(d.new, key=lambda e: e.path):
            where = f" via {', '.join(e.agents)}" if e.agents else ""
            print(f"NEW       {e.path}  ({', '.join(sorted(set(e.detectors)))}){where}")
        for e in sorted(d.resolved, key=lambda e: e.path):
            print(f"RESOLVED  {e.path}")
        if not d.new and not d.resolved:
            print("no change since baseline")
        return 1 if d.new else 0

    if args.summary:
        print(report.render_summary(result, gaps), end="")
    elif args.json:
        print(result.to_json())
    else:
        print(report.render_text(result, gaps), end="")
    return 1 if result.exposed_count else 0


if __name__ == "__main__":
    sys.exit(main())
