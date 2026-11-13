# Agent hook audit (GitHub Action)

Fails a pull request that adds a dangerous Claude Code hook. A hook keeps running after the
skill that installed it is removed, and skill registries scan skill code, not hook configs.

```yaml
# .github/workflows/agent-hook-audit.yml
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: issea1015/agent-hook-audit@v1
        with:
          fail-on: high   # or medium
```

For GitHub code scanning, add `sarif-file: hook-audit.sarif` and upload it with
`github/codeql-action/upload-sarif` (with `if: always()` so it uploads even when the audit fails).

Scans `.claude/settings.json`, `.claude/settings.local.json` and every plugin `hooks/hooks.json`,
plus the scripts those hooks run. Writes a job summary and inline annotations.

## Policy file (optional)
`.github/agent-hook-policy.json` sets the default severity and allow-lists reviewed hooks. Every exception needs a reason:
```json
{
  "fail_on": "medium",
  "allow": [
    {"pattern": "scripts/notify-slack\\.sh", "reason": "reviewed 2026-11: posts build status to our Slack"}
  ]
}
```
Allowed findings don't fail the job; the summary still counts them.

## Safety audit
- Standard library Python only. No network calls, no writes except the job summary file GitHub provides.
- Reads files in the checked-out repo; never executes the hooks or scripts it audits.
