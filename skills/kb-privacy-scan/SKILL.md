---
name: kb-privacy-scan
description: Assess and monitor privacy exposure in a knowledge base, notes store or second brain, meaning which sensitive files an AI agent can reach. Use when asked to audit a knowledge base for privacy risk, to find sensitive records reachable by coding agents, or to set up a recurring detective control.
---

# Knowledge base privacy scan

## The rule that governs everything below

You are an agent, and the model you run on probably sends its context off this machine. Running
this scan therefore makes you a crossing, and the scan's findings are exactly the material that
must not cross.

So, without exception:

- **Always run with `--summary`.** It emits counts and nothing that locates a record. A file path
  can name a clinician, a relative or a client, so paths are disclosure too.
- **Never open, read, `cat`, `grep`, `head` or summarise a file the scan flags**, and never rerun
  without `--summary` to find out which files they are. Verifying a finding by reading it is the
  disclosure the scan exists to detect.
- **Never write the roster file.** It lists real people's names. Tell the user to write it.
- **Path-level review belongs to the user**, run locally, in a terminal whose output does not go to
  a model.

If the user asks you to show them the flagged files, give them the command to run themselves
rather than running it.

## Run it once

1. Ask which directories they launch agents in. A directory passed to an agent on its command line
   appears in no config file and cannot be discovered, so each one needs `--assume-root PATH`.
2. Run the assessment over the knowledge base and anywhere else it has copies:

   ```
   python3 -m kbscan assess <path> [<path> ...] --summary [--assume-root <dir> ...]
   ```

   Shell history and agent session directories are scanned automatically. They are where a value
   lands after somebody used it once.

3. Read the numbers using the next section, and report them.

## Reading the numbers

`reachable` is the headline. It counts files holding sensitive content that sit inside a directory
some agent was granted. The target is zero. Anything above zero is a real finding regardless of
which model the agent uses.

`reachable_by_egress` says where content could go. `cloud-model` is the obvious one. **A local model
is not a clean result.** `chat-relay` and `web` are egress too, and a local agent that posts
summaries to a chat workspace is a path out.

`config_gaps` above zero means an agent config could not be read. **Coverage is then incomplete, and
you must not describe the result as clean** even if `reachable` is zero.

`launch_roots_visible: partial` is always present. It is a reminder, not a finding. Mention it if
the user supplied no `--assume-root`.

`max_copies_of_one_identifier` counts the most places a single identifier appears. A number above
one means rotating or removing it in one place leaves it live elsewhere.

`by_detector` breaks the findings down. `connection-string` and `private-key` are live credentials
and come first.

`sensitive_files` above `reachable` means some sensitive content is outside every agent grant. That
is good, and not a reason to relax.

## What to recommend

In this order, which is the order of consequence.

1. **Rotate any credential found, before changing anything else.** A credential that has sat in a
   synced or agent-readable folder is already disclosed and should be treated that way.
2. **Move what cannot leave off the path**, rather than defending the path. The test is that an
   agent trying to open one of those files gets "no such file".
3. **Write down where each pipeline's output goes.** The model column is the one people fill in, and
   the egress column is the one that finds the leak.

Do not recommend deleting records to make the number go down without saying that retention
obligations and litigation holds may apply. That is a question for the user, and sometimes for
their counsel.

## Set it up as a detective control

Record a baseline once the user has fixed what they intend to fix:

```
python3 -m kbscan baseline <path> ... --out ~/.config/kbscan/baseline.json
```

Then schedule the check. It exits 1 when something new appears and 0 otherwise, so any scheduler can
alert on it:

```
python3 -m kbscan check <path> ... --baseline ~/.config/kbscan/baseline.json --summary
```

**If the scheduler announces results to a chat service, the announcement is a crossing.** Keep
`--summary` on the scheduled command for that reason.

The salt in `~/.config/kbscan/salt` must persist. A new salt changes every fingerprint and makes
every saved baseline report everything as new.

## What the scan does not catch

Say so when it matters to the user's question.

It cannot see sensitivity that comes only from location. A file in a medical folder that carries no
identifier and no front-matter declaration is invisible to it.

It cannot see a clinical note or a client narrative that names nobody on the roster and contains no
structured identifier. Prose is where identity hides.

It reads configs for the agents it has adapters for. An agent it does not know about is not reported
as a gap, only as absent, so ask what else the user runs.

It skips binary files, which includes PDFs and images.
