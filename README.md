# repo-secret-scanner

[![CI](https://github.com/dkautomation23/repo-secret-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/dkautomation23/repo-secret-scanner/actions/workflows/ci.yml)

A tiny, dependency-free scanner that catches **leaked secrets before they ship** —
API keys, tokens, and private keys committed by accident. One Python file, no
install, non-zero exit code on a hit so it drops straight into a pre-commit hook
or CI.

> **Defensive use only.** Scan code you own or are authorised to review.

## Quick start

```bash
python scan.py .                 # scan the current tree
python scan.py path/ --format json
python scan.py . --entropy       # also flag high-entropy strings (noisier)
python scan.py . --selftest      # plant a dummy secret and confirm detection
```

Sample output:

```
  config/prod.env:12  [GitHub token]  ghp_…a1b2 (40 chars)
  src/client.py:8     [Hardcoded credential]  "sup…123" (12 chars)

2 potential secret(s) found.
```

Secrets are always **redacted** in output (first/last 4 chars + length) — the
tool never prints the full value.

## What it catches

AWS access keys, GitHub tokens, Slack tokens, Google API keys, Stripe live keys,
OpenAI-style keys, PEM private-key blocks, JWTs, and generic
`api_key = "..."` / `password: "..."` assignments. With `--entropy` it also flags
long high-entropy strings that look like keys.

## Use it as a gate

Pre-commit hook (`.git/hooks/pre-commit`):

```bash
#!/bin/sh
python scan.py . || {
  echo "Secret scan failed — remove the secret or mark it with a pragma."
  exit 1
}
```

GitHub Actions step:

```yaml
- run: python scan.py .
```

Because the scan exits non-zero on a finding, the commit or the build stops.

## Silencing false positives

Add an inline marker on the line (e.g. a fixture or a public sample value):

```python
DEMO_TOKEN = "not-a-real-secret"  # pragma: allowlist secret
```

`.git`, `node_modules`, virtualenvs and build dirs are skipped automatically, as
are binary files and files over 1 MB.

## Notes

- Pure standard library — no dependencies, runs on Python 3.9+.
- Regex + entropy scanning is a strong first line, not a guarantee; rotate any
  key that has ever touched a public commit rather than trusting a clean scan of
  the current tree.

## License

MIT — see [LICENSE](LICENSE).
