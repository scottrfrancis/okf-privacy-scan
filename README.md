# kbscan

Finds sensitive content in a knowledge base that an AI agent can reach.

Secret scanners tell you what is in your files. This tells you which of those files sit inside a
directory you handed to an agent, which agent, and where that agent's output goes. Each of those
facts is easy to check on its own. The exposure is in the combination, and nobody checks the
combination, because it belongs to no single system.

It is the companion to *You Have a Hole in Your Head*, a book about privacy for second brains. Chapter
1 describes finding 310 plaintext medical and financial records inside a directory granted to a
cloud-backed coding agent, and then finding the same property on a second machine whose agent had no
cloud model at all. This is the tool that would have found both.

## Run it once

```
python3 -m kbscan assess ~/notes ~/work --summary
```

That reads the agent configs in your home directory, finds every project directory an agent is
launched in, scans the paths you name plus your shell history and agent session directories, and
reports how many files holding sensitive content an agent can reach.

The first line is the number that matters. The target is zero.

Drop `--summary` to see the paths, **in a terminal whose output does not go to a model**. The full
report names files, and a filename can name a clinician, a relative or a client.

If you launch agents in a directory by passing it on the command line, that grant appears in no
file and cannot be discovered. Declare it:

```
python3 -m kbscan assess ~/notes --assume-root ~/work/client-a --summary
```

## Run it on a schedule

Once you have fixed what you mean to fix, record where things stand:

```
python3 -m kbscan baseline ~/notes ~/work --out ~/.config/kbscan/baseline.json
```

Then check against it regularly. The check exits 1 when something new appears, so any scheduler can
alert on it.

```
# crontab: every morning at 06:10
10 6 * * * python3 -m kbscan check ~/notes ~/work --baseline ~/.config/kbscan/baseline.json --summary
```

Keep `--summary` on anything scheduled. If your scheduler posts results to a chat service, that post
is a crossing, and the full report would carry paths into it.

## Running it through an agent

`skills/kb-privacy-scan/SKILL.md` is a Claude Code skill. Copy or link it into `~/.claude/skills/`.

The skill's first rule is the one worth reading even if you never use it. An agent running this scan
is itself a crossing, so the agent runs `--summary` only, never opens a file the scan flags, and
never writes the roster. Verifying a finding by reading the file is the disclosure the scan exists
to detect.

## What it finds

Government identifiers, checked for structural validity. Payment card numbers, which must carry a
real network prefix and pass Luhn, since Luhn alone passes one random digit string in ten.
Private key blocks. Connection strings with an inline password. Front matter that declares a file
sensitive. And names from a roster you supply, because the identifiers that leak are the ones
nobody thought to enumerate.

It also finds sensitivity that comes from where a file sits. A path you configured for encryption
is a path you consider sensitive, and transparent encryption decrypts in the working tree, so a
plaintext file in such a path is reported as `encrypted-location`. This uses git's own attribute
matching, so nested `.gitattributes` files and nested repositories are handled. For sensitive
locations you have not encrypted, pass `--sensitive-path GLOB`.

This matters more than the content detectors. On the knowledge base the tool was developed against,
two thirds of the plaintext files in encrypted paths carried no identifier and no declaration at
all, and would have been invisible without it.

For each file it also reports which agents can reach it and by what route: `cloud-model`, `web`, or
`chat-relay`. A local model reads as reassuring and says nothing about where the answer it wrote
ends up.

It counts how many places hold the same identifier, without storing the identifier. A number above
one means removing it in one place leaves it live elsewhere.

## What it does not catch

These limits are real, and the report states the ones it can detect.

It sees location only where you have said something about it, by encrypting the path or declaring
it with `--sensitive-path`. A medical folder that is neither, holding files with no identifier and
no declaration, is invisible to it.

It cannot see identity in prose. A clinical note or a client narrative that names nobody on the
roster and contains no structured identifier passes clean. Identity in narrative is spread across
the whole text, which is the same reason redaction fails on prose.

It reads configs for the agents it has adapters for, currently Claude Code and OpenClaw. An agent it
has no adapter for is absent from the report rather than flagged, so it cannot tell you about tools
it does not know exist.

It skips binary files, which includes PDFs and images.

It never reports a clean result while an agent config it recognises went unread. It cannot make the
same promise about configs it does not recognise.

## The salt and the roster

Both live in `~/.config/kbscan/`, which is created mode 0700, with the salt at 0600.

The salt makes fingerprints useless to anyone reading a report while letting two scans agree that a
value is the same one. **It must persist.** A new salt changes every fingerprint and turns every
saved baseline into a list of everything.

The roster is one name per line. It is a list of real people and it is sensitive in its own right.
Never commit it, and never let an agent write it for you.

## Requirements and tests

Python 3.10 or later, and nothing else. There are no dependencies to install, deliberately, so that
you can read the whole thing before you run it on your private files.

```
python3 -m unittest discover -s tests -t .
```

Every test was written before the code it covers. The three that guard the rules that matter most,
never emitting a matched value, never reporting clean on partial coverage, and counting a
local-model grant as exposure, were each checked by breaking the code and confirming the test
failed.
