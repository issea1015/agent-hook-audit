#!/usr/bin/env python3
"""Static safety auditor + structure validator for the Agent Workflow Kit.

Checks every item under skills/, hooks/, templates/:
  - has README.md with a "## Safety audit" section
  - skills have SKILL.md with frontmatter `name` and `description`
  - Python files: flags imports that reach the network, spawn processes, or delete files
  - Shell files: flags curl/wget/nc, rm -rf, sudo
Any capability flagged in code must be acknowledged in the README's safety audit
section (by its keyword), or the audit fails. Exit 0 = pass, 1 = fail.

  audit.py [PACK_DIR]        audit a pack (default: this kit)
  audit.py --settings [F..]  audit hook configurations in settings.json / hooks.json files,
                             and the scripts those hooks run
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
SECTIONS = ("skills", "hooks", "templates")

PY_CAPS = {
    "network": {"urllib", "urllib.request", "http.client", "requests", "socket", "httpx", "aiohttp"},
    "subprocess": {"subprocess", "os.system", "pty"},
    "delete": {"shutil.rmtree", "os.remove", "os.unlink", "os.rmdir"},
}
SH_CAPS = {
    "network": re.compile(r"\b(curl|wget|nc|ssh|scp)\b"),
    "delete": re.compile(r"\brm\s+-[a-zA-Z]*r"),
    "sudo": re.compile(r"\bsudo\b"),
}


def py_caps(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names |= {f"{node.module}.{a.name}" for a in node.names}
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            names.add(f"{node.value.id}.{node.attr}")
    return {cap for cap, mods in PY_CAPS.items() if names & mods}


def sh_caps(path: Path) -> set[str]:
    text = "\n".join(l for l in path.read_text().splitlines() if not l.lstrip().startswith("#"))
    return {cap for cap, rx in SH_CAPS.items() if rx.search(text)}


def audit_item(item: Path) -> list[str]:
    errs = []
    readme = item / "README.md"
    if not readme.exists():
        return [f"{item.relative_to(KIT)}: missing README.md"]
    text = readme.read_text()
    m = re.search(r"^## Safety audit\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not m:
        errs.append(f"{item.relative_to(KIT)}: README missing '## Safety audit' section")
    audit_text = (m.group(1) if m else "").lower()

    if item.parent.name == "skills":
        skill = item / "SKILL.md"
        if not skill.exists():
            errs.append(f"{item.relative_to(KIT)}: missing SKILL.md")
        else:
            fm = re.match(r"^---\n(.*?)\n---\n", skill.read_text(), re.S)
            if not fm or not re.search(r"^name:\s*\S", fm.group(1), re.M) \
                    or not re.search(r"^description:\s*\S", fm.group(1), re.M):
                errs.append(f"{item.relative_to(KIT)}: SKILL.md needs frontmatter name + description")

    for f in item.rglob("*"):
        caps: set[str] = set()
        if f.suffix == ".py":
            caps = py_caps(f)
        elif f.suffix in (".sh", ".bash", ".zsh"):
            caps = sh_caps(f)
        for cap in sorted(caps):
            if cap not in audit_text:
                errs.append(f"{f.relative_to(KIT)}: uses '{cap}' capability but the safety audit "
                            f"doesn't acknowledge it")
    return errs


# --- settings audit: hook *configurations* (settings.json, plugin hooks.json) -------------
# A hook keeps running after the skill that installed it is gone, and registries
# audit skill code, not hook configs. These rules read the command strings.
SETTINGS_RULES = [
    ("HIGH", "download-and-run", re.compile(
        r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|"
        r"\b(curl|wget)\b[^|;&]*\|\s*python3?\b|(ba)?sh\s+<\(\s*(curl|wget)", re.I)),
    ("HIGH", "obfuscated", re.compile(r"base64\s+(-d|--decode)|\bxxd\s+-r|\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}", re.I)),
    ("HIGH", "secret-access", re.compile(
        r"(~|\$HOME)/\.(ssh|aws|gnupg|config/gh)|\.env\b|id_(rsa|ed25519)|"
        r"\$\{?(AWS_SECRET|GITHUB_TOKEN|GH_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|NPM_TOKEN)", re.I)),
    ("HIGH", "network", re.compile(r"\b(curl|wget|nc|ncat|ssh|scp|rsync|Invoke-WebRequest)\b|https?://", re.I)),
    ("MEDIUM", "eval", re.compile(r"\beval\b|\b(ba)?sh\s+-c\b|\bpython3?\s+-c\b|\bnode\s+-e\b", re.I)),
    ("MEDIUM", "temp-path", re.compile(r"(^|\s|[\"'])/(tmp|var/tmp|dev/shm)/")),
    ("LOW", "delete", re.compile(r"\brm\s+-[a-zA-Z]*[rf]")),
]
SCRIPT_RX = re.compile(r"""[\"']?((?:~|\$HOME|\$\{?CLAUDE_(?:PROJECT_DIR|PLUGIN_ROOT)\}?|\.{1,2}|/)[^\s\"';|&]*\.(?:py|sh|bash|zsh|js|mjs|ts))""")
DEFAULT_SETTINGS = ("~/.claude/settings.json", ".claude/settings.json", ".claude/settings.local.json")


def hook_commands(data: dict) -> list[tuple[str, str]]:
    """(where, command) for every hook command and the statusLine in a settings/hooks.json dict."""
    out = []
    for event, entries in (data.get("hooks") or {}).items():
        for i, entry in enumerate(entries or []):
            matcher = entry.get("matcher", "*") if isinstance(entry, dict) else "*"
            for h in (entry.get("hooks", []) if isinstance(entry, dict) else []):
                if isinstance(h, dict) and h.get("type", "command") == "command" and h.get("command"):
                    out.append((f"hooks.{event}[{i}] matcher={matcher!r}", h["command"]))
    sl = data.get("statusLine")
    if isinstance(sl, dict) and sl.get("command"):
        out.append(("statusLine", sl["command"]))
    return out


def resolve_script(ref: str, settings_file: Path) -> Path:
    home = str(Path.home())
    project = settings_file.resolve().parent.parent  # <project>/.claude/settings.json
    plugin = project  # <plugin>/hooks/hooks.json has the same depth
    for var in ("${CLAUDE_PLUGIN_ROOT}", "$CLAUDE_PLUGIN_ROOT"):
        ref = ref.replace(var, str(plugin))
    ref = ref.replace("$HOME", home).replace("${CLAUDE_PROJECT_DIR}", str(project)) \
             .replace("$CLAUDE_PROJECT_DIR", str(project))
    if ref.startswith("~"):
        ref = home + ref[1:]
    p = Path(ref)
    return p if p.is_absolute() else project / p


def audit_settings(path: Path) -> list[tuple[str, str, str]]:
    """Findings (severity, rule, message) for one settings file."""
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return [("HIGH", "unreadable", f"{path}: cannot parse ({e.__class__.__name__}); check it by hand")]
    findings = []
    for where, cmd in hook_commands(data):
        hit_rules = set()
        for sev, rule, rx in SETTINGS_RULES:
            if rule == "network" and hit_rules & {"download-and-run"}:
                continue  # already reported more specifically
            if rx.search(cmd):
                hit_rules.add(rule)
                findings.append((sev, rule, f"{path} {where}: {cmd}"))
        for ref in SCRIPT_RX.findall(cmd):
            script = resolve_script(ref, path)
            if not script.is_file():
                findings.append(("MEDIUM", "missing-script", f"{path} {where}: script not found: {ref}"))
                continue
            caps = py_caps(script) if script.suffix == ".py" else \
                sh_caps(script) if script.suffix in (".sh", ".bash", ".zsh") else set()
            for cap in sorted(caps):
                sev = "HIGH" if cap in ("network", "sudo") else "MEDIUM"
                findings.append((sev, f"script-{cap}", f"{path} {where}: {script} uses '{cap}'"))
    return findings


def run_settings(files: list[str]) -> int:
    if files:
        paths = [Path(f).expanduser() for f in files]
    else:
        paths = [p for p in (Path(f).expanduser() for f in DEFAULT_SETTINGS) if p.exists()]
        # hooks shipped by installed plugins run too, so audit them as well
        paths += sorted(Path("~/.claude/plugins/cache").expanduser().glob("*/*/*/hooks/hooks.json"))
    if not paths:
        print("no settings files found (looked for: " + ", ".join(DEFAULT_SETTINGS) + ")")
        return 0
    findings = [f for p in paths for f in audit_settings(p)]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for sev, rule, msg in sorted(findings, key=lambda f: order[f[0]]):
        print(f"{sev:6} {rule:16} {msg}")
    n_cmds = sum(len(hook_commands(json.loads(p.read_text()))) for p in paths
                 if p.exists() and _parses(p))
    high = sum(1 for f in findings if f[0] == "HIGH")
    print(f"audited {n_cmds} hook command(s) in {len(paths)} file(s): "
          f"{'FAIL' if high else 'PASS'} ({high} high, {len(findings) - high} other)")
    return 1 if high else 0


def _parses(p: Path) -> bool:
    try:
        json.loads(p.read_text())
        return True
    except (OSError, json.JSONDecodeError):
        return False


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Static safety audit for Claude Code skills, hooks and hook settings.")
    ap.add_argument("path", nargs="?", help="pack folder with skills/ hooks/ templates/ (default: this kit)")
    ap.add_argument("--settings", nargs="*", metavar="FILE",
                    help="audit hook configurations instead (default: ~/.claude/settings.json, "
                         ".claude/settings.json, .claude/settings.local.json and installed plugins' hooks.json)")
    a = ap.parse_args(argv)
    if a.settings is not None:
        return run_settings(a.settings)
    global KIT
    if a.path:
        KIT = Path(a.path).resolve()
    items = [d for s in SECTIONS if (KIT / s).exists() for d in sorted((KIT / s).iterdir()) if d.is_dir()]
    errs = [e for item in items for e in audit_item(item)]
    for e in errs:
        print(f"FAIL {e}")
    print(f"audited {len(items)} item(s): {'FAIL' if errs else 'PASS'}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
