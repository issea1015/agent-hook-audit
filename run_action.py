#!/usr/bin/env python3
"""Entry point for the agent-hook-audit GitHub Action.

Finds Claude Code hook configurations in the checked-out repo
(.claude/settings.json, .claude/settings.local.json, any plugin hooks/hooks.json),
audits each hook command and the script it runs with audit.py, writes a job
summary, and fails the job on HIGH findings (or on MEDIUM too, if fail-on=medium).
Standard library only. Makes no network calls.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit  # noqa: E402

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build"}
ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def discover(root: Path) -> list[Path]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        d = Path(dirpath)
        if d.name == ".claude":
            found += [d / f for f in ("settings.json", "settings.local.json") if f in filenames]
        if d.name == "hooks" and "hooks.json" in filenames:
            found.append(d / "hooks.json")
    return sorted(found)


SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def line_of(path: Path, msg: str) -> int:
    """Best-effort line number: the first line of the file containing the finding's command."""
    cmd = msg.split(": ", 1)[-1]
    needle = json.dumps(cmd)[1:-1][:60]  # as it appears JSON-escaped in the file
    try:
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if needle and needle in line:
                return i
    except OSError:
        pass
    return 1


def sarif(root: Path, findings: list) -> dict:
    rules = sorted({rule for _, _, rule, _ in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agent-hook-audit",
                "rules": [{"id": r, "shortDescription": {"text": f"Claude Code hook: {r}"}} for r in rules],
            }},
            "results": [{
                "ruleId": rule,
                "level": SARIF_LEVEL[sev],
                "message": {"text": f"{sev}: {msg.replace(str(root) + os.sep, '')}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.relative_to(root).as_posix()},
                    "region": {"startLine": line_of(f, msg)},
                }}],
            } for f, sev, rule, msg in findings],
        }],
    }


POLICY = ".github/agent-hook-policy.json"


def load_policy(root: Path) -> dict:
    """Optional org/repo policy: {"fail_on": "...", "allow": [{"pattern": regex, "reason": "..."}]}."""
    p = root / POLICY
    if not p.exists():
        return {}
    pol = json.loads(p.read_text())
    for a in pol.get("allow", []):
        a["_rx"] = re.compile(a["pattern"])
        if not a.get("reason"):
            raise ValueError(f"{POLICY}: every allow entry needs a reason ({a['pattern']})")
    return pol


def main(argv=None) -> int:
    root = Path(argv[0] if argv else os.environ.get("INPUT_PATH", ".")).resolve()
    try:
        policy = load_policy(root)
    except (ValueError, json.JSONDecodeError, re.error, KeyError) as e:
        print(f"::error file={POLICY}::invalid policy: {e}")
        return 2
    fail_on = (os.environ.get("INPUT_FAIL_ON") or policy.get("fail_on") or "high").upper()
    if fail_on not in ORDER:
        print(f"::error::fail-on must be high, medium or low, not {fail_on.lower()}")
        return 2
    files = discover(root)
    findings, allowed = [], []
    for f in files:
        for sev, rule, msg in audit.audit_settings(f):
            hit = next((a for a in policy.get("allow", []) if a["_rx"].search(msg)), None)
            (allowed if hit else findings).append((f, sev, rule, msg if not hit else f"{msg} [allowed: {hit['reason']}]"))
    n_cmds = 0
    for f in files:
        try:
            n_cmds += len(audit.hook_commands(json.loads(f.read_text())))
        except (OSError, json.JSONDecodeError):
            pass
    for f, sev, rule, msg in findings:
        level = "error" if ORDER[sev] >= ORDER[fail_on] else "warning"
        rel = f.relative_to(root)
        print(f"::{level} file={rel},title={rule}::{sev} {msg.replace(str(root) + os.sep, '')}")
    failing = [x for x in findings if ORDER[x[1]] >= ORDER[fail_on]]
    verdict = "FAIL" if failing else "PASS"
    lines = [f"## Agent hook audit: {verdict}",
             f"{n_cmds} hook command(s) in {len(files)} config file(s); {len(findings)} finding(s), "
             f"{len(failing)} at or above `{fail_on.lower()}`"
             + (f"; {len(allowed)} allowed by `{POLICY}`." if allowed else "."), ""]
    if findings:
        lines += ["| Severity | Rule | Where |", "|---|---|---|"]
        lines += [f"| {sev} | {rule} | `{msg.replace(str(root) + os.sep, '')[:200]}` |" for _, sev, rule, msg in findings]
    sarif_out = os.environ.get("INPUT_SARIF_FILE")
    if sarif_out:
        Path(sarif_out).write_text(json.dumps(sarif(root, findings), indent=2) + "\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
