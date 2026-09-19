# Contributing

Real commands for this repository. `.github/workflows/ci.yml` is the source of
truth if this page and CI ever disagree.

## Setup

No dependencies to install — the tool is pure standard library, Python 3.9+.
Clone it and run it.

## Before you write code

This is a **defensive** tool — scan code you own or are authorised to review
(see the banner in the README). A pull request that adds anything beyond
detection and reporting (for example, automatic remediation or key rotation)
will be declined; open an issue first if you think that boundary is wrong.

## The one rule that is not negotiable

A new check starts as a failing test. For a new secret pattern: add the regex
to `RULES` in `scan.py`, then extend `selftest()` with a case that plants a
dummy value of that shape (built at runtime, the way the existing GitHub-token
case is, so no secret-shaped literal is committed) and asserts it is caught.
Confirm it fails first, then add the pattern.

## Running the tests

```bash
python -m compileall -q .
python scan.py --selftest
```

Same two steps CI runs, in that order.

## Commit messages

Match `git log --oneline` in this repository: a short, imperative summary, no
ticket prefixes, no emoji. Recent examples:

```
Run the tests in CI on every push
repo-secret-scanner: dependency-free leaked-secret scanner with pre-commit/CI exit codes and selftest
```

## License

Contributions are published under this repository's MIT license.
