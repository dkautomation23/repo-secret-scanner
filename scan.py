#!/usr/bin/env python3
"""repo-secret-scanner — catch leaked secrets before they ship.

Walk a directory, match high-signal secret patterns (plus an optional
high-entropy string check), and report findings as file:line with the secret
value redacted. Exit code is non-zero when anything is found, so it drops
straight into a pre-commit hook or a CI step.

DEFENSIVE USE ONLY — scan code you own or are authorised to review.

Usage:
    python scan.py .                       # scan current tree
    python scan.py path/ --format json     # machine-readable
    python scan.py . --entropy             # also flag high-entropy strings
    python scan.py . --selftest            # prove it catches a planted secret
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache"}
MAX_BYTES = 1_000_000
ALLOW_MARK = "pragma: allowlist secret"

RULES: list[tuple[str, re.Pattern]] = [
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe secret key", re.compile(r"sk_live_[0-9A-Za-z]{16,}")),
    ("OpenAI-style key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Hardcoded credential",
     re.compile(r"""(?i)(?:api[_-]?key|secret|token|passw(?:or)?d)\s*[:=]\s*['"][^'"]{6,}['"]""")),
]

ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    match: str


def redact(secret: str) -> str:
    secret = secret.strip("'\"")
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}…{secret[-4:]} ({len(secret)} chars)"


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def is_probably_text(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(2048)
    except OSError:
        return False
    return b"\x00" not in chunk


def scan_file(path: Path, check_entropy: bool) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    for lineno, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARK in line:
            continue
        for name, rx in RULES:
            for m in rx.finditer(line):
                findings.append(Finding(str(path), lineno, name, redact(m.group(0))))
        if check_entropy:
            for cand in ENTROPY_CANDIDATE.findall(line):
                if len(cand) >= 20 and shannon(cand) >= 4.0:
                    findings.append(Finding(str(path), lineno, "High-entropy string", redact(cand)))
    return findings


def walk(root: Path, check_entropy: bool) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        if not is_probably_text(path):
            continue
        findings.extend(scan_file(path, check_entropy))
    return findings


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.file, f.line, f.rule, f.match)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def selftest() -> int:
    with tempfile.TemporaryDirectory() as d:
        planted = Path(d) / "leak.env"
        # build a dummy token at runtime so no secret-shaped literal is committed
        planted.write_text("API_TOKEN = 'ghp_" + "a" * 36 + "'\n", encoding="utf-8")
        (Path(d) / "clean.py").write_text("x = 1  # nothing to see\n", encoding="utf-8")
        found = walk(Path(d), check_entropy=False)
        ok = any(f.rule == "GitHub token" for f in found) and len(found) >= 1
        print("selftest:", "PASS — planted secret detected" if ok else "FAIL")
        return 0 if ok else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan a directory for leaked secrets.")
    ap.add_argument("path", nargs="?", default=".", help="directory or file to scan")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--entropy", action="store_true", help="also flag high-entropy strings (noisier)")
    ap.add_argument("--selftest", action="store_true", help="plant a dummy secret and confirm detection")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    root = Path(args.path)
    if not root.exists():
        sys.exit(f"no such path: {root}")
    findings = dedupe(walk(root, args.entropy) if root.is_dir() else scan_file(root, args.entropy))

    if args.format == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print(f"clean — no secrets found in {root}")
        else:
            for f in findings:
                print(f"  {f.file}:{f.line}  [{f.rule}]  {f.match}")
            print(f"\n{len(findings)} potential secret(s) found.")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
