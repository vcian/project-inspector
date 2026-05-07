# Exceptions workflow (static prototype)

Governance suppressions live in `project-inspector.config.json` under `governanceSuppressions`.

This UI sketch is **optional** — for organizations that want approval queues:

1. Import `governance-suppressions.json` + `governance-audit.jsonl` from `project-report/`.
2. Present rows with owner / reason / `expiresAt`.
3. On approve, open a PR that edits `project-inspector.config.json` (never mutate suppressions silently).

Open `index.html` locally after a scan to review the JSON shapes side-by-side.
