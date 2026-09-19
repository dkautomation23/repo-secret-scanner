# Security policy

repo-secret-scanner walks a directory, matches secret-shaped patterns, and
prints redacted findings. This file defines what counts as a security issue
in that specific tool.

## Reporting

Use GitHub's private vulnerability reporting on this repository: **Security →
Report a vulnerability**. It opens a private thread; nothing becomes public
until there is a fix.

If that is not available to you, email **hello@dkautomation.dev** with
`repo-secret-scanner` in the subject line.

Include the commit or version you ran, the exact command, and what happened.
A proof of concept is welcome; a scanner's raw output usually is not.

**Do not open a public issue for a vulnerability.**

## Supported versions

No tagged releases yet — the `main` branch is the supported version. Report
against the commit you actually ran.

## What to expect

| | |
|---|---|
| First reply | within 3 working days |
| Assessment | within 7 working days of the first reply |
| Fix or a stated decision not to fix | within 30 days for anything reproducible |

Single-person commitments, not a company SLA.

## Scope

In scope:

- A secret the scanner did detect showing up **unredacted** anywhere in its
  own output — text mode, `--format json`, or the `--selftest` path. Every
  finding is supposed to go through `redact()` before it is printed.
- Any way for scanning a file to execute, import, or evaluate that file's
  content, instead of only reading its bytes and matching regexes against
  them.
- A crafted filename or file content that makes the scan write anything, or
  read outside the directory given on the command line.

Out of scope:

- A secret the scanner **misses** (false negative). That is a
  detection-quality bug — open a normal issue, it will be taken seriously,
  but it is not a vulnerability.
- A false positive.
- Findings that only appear with `--entropy` and need pattern tuning, not a
  security fix.

## Credit

Named in the fix's release notes if you want that; say so if you would rather
not be.

There is no bug bounty.
