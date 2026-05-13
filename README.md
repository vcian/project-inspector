# project-inspector

Deterministic, offline-first static analysis for Node.js and TypeScript ecosystems.  
`project-inspector` scans source code, lockfiles, and project structure to generate production-focused reports for security, architecture, dependencies, API exposure, performance, and release readiness — delivered as a single self-contained interactive HTML dashboard and machine-readable artifacts.

## Why use this

- Fast local feedback for engineering and AppSec review.
- Stable, deterministic output suitable for CI gates and trend tracking.
- Zero LLM dependency; works in restricted or disconnected environments.
- Produces an interactive HTML dashboard, Markdown reports, and machine-readable artifacts (`json`, `sarif`).
- No CDN dependencies — the HTML report is fully self-contained and works offline.

## Core capabilities

- Static code analysis (AST + rule heuristics).
- Security signals aligned with OWASP-style categorization.
- Dependency and migration risk intelligence (offline + optional `npm audit`).
- API surface discovery (HTTP + CLI command heuristics).
- Performance and memory anti-pattern detection.
- Inventory and project topology mapping.
- Database schema intelligence — ER diagram with entity/relation visualization.
- CI gate verdict via `check`.

## Interactive HTML dashboard

Every scan produces `project-report/index.html` — a single-file, fully offline HTML report with the following tabs:

| Tab | Content |
|-----|---------|
| **Issues** | Full findings table with severity badges, filters, owner, fix guidance, and compliance tags |
| **Bundle** | All generated report files with inline Markdown and JSON preview, syntax-highlighted |
| **Architecture** | Data-flow pipeline diagram, framework detection, architecture issues list |
| **Database** | Auto-detected ER diagram (Collections for Mongoose, Tables for SQL/Prisma/TypeORM/Drizzle/Sequelize), relations, indexing hints, schema model cards |

The dashboard requires no server — open it directly in a browser.

## Supported ecosystems

- Node.js / TypeScript / JavaScript
- React / Next.js
- Express / Fastify
- Heuristic NestJS support
- MongoDB / Mongoose (Collection-level ER diagram and relation detection)
- SQL databases via Prisma, TypeORM, Drizzle ORM, Sequelize, or raw `.sql` DDL
- Monorepo and multi-project workspace detection (heuristic)

## Install

### Global install (recommended for CI runners and local CLI use)

```bash
npm install -g project-inspector
```

### Verify install

```bash
project-inspector --help
```

## Quick start

```bash
cd your-project
project-inspector scan
```

Default output directory: `./project-report`

Open the report:

```bash
# macOS
open project-report/index.html
# Windows
start project-report/index.html
# Linux
xdg-open project-report/index.html
```

## CLI commands

| Command | Purpose |
|--------|---------|
| `scan` | Run all configured engines and write reports |
| `check` | Run `scan`, evaluate readiness gates, and exit non-zero on failure |
| `watch` | Re-run scans on file changes (debounced, single-flight queue) |
| `chat` | Offline keyword search over previously generated reports (no LLM) |
| `clear` | Remove report directory (including `.cache`) |
| `update-vuln-db` | Refresh optional vulnerability override DB from `VULN_DB_URL` (HTTPS) |

## Command usage

### `scan`

```bash
project-inspector scan [options]
```

| Option | Description |
|--------|-------------|
| `-c, --cwd <path>` | Project root. Default: current working directory |
| `-o, --out <path>` | Output directory. Default: `<cwd>/project-report` |
| `-j, --concurrency <n>` | Parallelism for file-level work (`1-32`; default `max(2, cpuCount - 1)`) |
| `--mode <quick\|deep\|diff>` | Scan strategy. `diff` forces git-changed scope |
| `--online` | Enable online dependency audit (`npm audit`) where supported |
| `--incremental` | Prefer git-changed files |
| `--no-cache` | Ignore cached file hash / merged scan reuse |
| `--rescan` | Force full workspace scan (disable cache + incremental optimization) |
| `--offline` | Disable vuln DB staleness messaging and auto-refresh behavior |
| `--auto-update-db` | Best-effort HTTPS refresh of vuln override DB before dependency engine |
| `--format <md\|json\|sarif>` | Generate extra machine outputs (`results.json` and/or `results.sarif`) |

### `check`

```bash
project-inspector check [options]
```

Same options as `scan`.  
`check` writes `ci-result.json` and exits with code `1` when gate criteria fail.

### `watch`

```bash
project-inspector watch [options]
```

Same options as `scan`. Uses a `1500ms` debounce and single-flight scheduling to prevent overlapping scans.

### `chat`

```bash
project-inspector chat [options]
```

| Option | Description |
|--------|-------------|
| `-c, --cwd <path>` | Root directory used to locate latest reports |

### `clear`

```bash
project-inspector clear [options]
```

| Option | Description |
|--------|-------------|
| `-c, --cwd <path>` | Project root |
| `-o, --out <path>` | Report directory to delete |

### `update-vuln-db`

```bash
project-inspector update-vuln-db [options]
```

| Option | Description |
|--------|-------------|
| `-c, --cwd <path>` | Project root |
| `-o, --out <path>` | Report directory |

## Recommended production workflows

### Local developer loop

```bash
project-inspector scan --mode quick --incremental
```

### Pre-merge validation

```bash
project-inspector check --mode deep --format json --format sarif
```

### Large refactor or branch baseline refresh

```bash
project-inspector scan --rescan --mode deep
```

### Air-gapped / strict offline environment

```bash
project-inspector scan --offline
```

## Output files

Reports are consolidated:

- `security.md` contains security findings + OWASP drill-down + cross-engine hotspots + threat scenarios.
- `performance.md` includes memory engine signals.
- `dependencies.md` includes migration hints.
- Legacy standalone files (`compliance.md`, `hotspots.md`, `attack-scenarios.md`, `memory.md`, `migration.md`) are removed on next write.

| Path | Content |
|------|---------|
| `project-report/index.html` | **Interactive HTML dashboard** (Issues, Bundle, Architecture, Database tabs) |
| `project-report/summary.md` | Executive summary and report index |
| `project-report/security.md` | Security findings, OWASP mapping, hotspots, threat scenarios |
| `project-report/architecture.md` | Architecture analysis, layer mapping, structural issues |
| `project-report/database.md` | Database schema analysis, ER relations, indexing hints |
| `project-report/api.md` | Discovered HTTP routes, auth heuristics, OpenAPI export |
| `project-report/action-plan.md` | Prioritized remediation checklist |
| `project-report/audit-summary.md` | Full cross-engine audit narrative |
| `project-report/production-decision.md` | Human-readable production verdict |
| `project-report/decision.json` | Machine-readable verdict for CI automation |
| `project-report/scores.json` | Numeric scores + segment rollup when present |
| `project-report/openapi.json` | OpenAPI **3.1** export from detected HTTP routes |
| `project-report/sbom.cdx.json` | CycloneDX SBOM from npm lockfile |
| `project-report/osv-summary.json` | OSV vulnerability hints (skipped when offline) |
| `project-report/pr-comment.md` | GitHub-style Markdown for PR comments / job summaries |
| `project-report/governance-suppressions.json` | Snapshot of governance suppressions |
| `project-report/governance-audit.jsonl` | Append-only audit entries per scan |
| `docs/rules-catalog.md` | Generated rules catalog (`npm run docs:catalog`) |
| `project-report/inventory.json` | File-level inventory with kind/framework/LOC/bytes |
| `project-report/results.json` | Present when `--format json` is used |
| `project-report/results.sarif` | Present when `--format sarif` is used (SARIF 2.1.0) |
| `project-report/ci-result.json` | Written by `check` command |
| `project-report/.cache/merged-scan.json` | Cached merged payload for partial refresh |
| `project-report/.cache/file-hashes.json` | SHA-256 hash map for incremental scans |
| `project-report/.cache/dependency-snapshot.json` | Dependency/lockfile fingerprint (includes vuln DB fingerprint) |
| `project-report/.cache/vuln-db-meta.json` | Metadata about last vuln DB fetch and staleness |

## CI integration

### GitHub Actions example

```yaml
name: Static Analysis Gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g project-inspector
      - name: Run production gate
        run: project-inspector check --cwd . --mode deep --format sarif --format json
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: project-report/results.sarif
```

## Configuration reference

| Key / Flag | Type | Purpose |
|------------|------|---------|
| `LOG_LEVEL` | env | Pino log level (`fatal`, `error`, `warn`, `info`, `debug`, ...) |
| `--mode` | cli | `quick`, `deep`, `diff` |
| `--concurrency` | cli | Control parallelism (`1-32`) |
| `--format` | cli | Additional machine outputs (`json`, `sarif`) |
| `--auto-update-db` | cli | Best-effort refresh using `VULN_DB_URL` before dependency scan |
| `--offline` | cli | Disable remote vuln DB staleness flow and auto-refresh |
| `VULN_DB_URL` | env | HTTPS URL to override vulnerability rule database |
| `policyPack` | `project-inspector.config.json` | Named overlay (`packs/<id>.json`) merging extra ignore globs / suppress substrings (HIPAA, SOC2, PCI, OWASP ASVS samples ship under `packs/`) |

### `VULN_DB_URL` payload shape

```json
{
  "version": "string",
  "updated": "ISO-8601 timestamp",
  "rules": []
}
```

## Reliability and security model

### What this tool is good at

- Deterministic static risk discovery.
- Engineering governance and CI gate standardization.
- Early issue detection before runtime testing.

### What this tool is not

- Not a replacement for penetration testing or dynamic analysis.
- Not full inter-procedural taint analysis.
- Not a complete framework semantic model.

Use findings as high-signal review inputs, then confirm in code review or targeted testing.

## Limitations

- Security engine uses AST + pattern heuristics (no full cross-function data flow).
- `chat` is offline keyword search over local report text, not an AI assistant.
- NestJS route/auth/validation classification is decorator-oriented heuristic analysis.
- Supply-chain insight combines offline rules with optional `npm audit` in `--online` mode.
- Multi-project auto-detection is heuristic when no explicit workspace config exists.
- Mongoose schema detection covers `mongoose.Schema`, `new Schema()`, and `mongoose.model()` patterns; non-standard schema factory wrappers may not be captured.

## Performance and determinism notes

- Caching is enabled by default for speed.
- `--rescan` should be used after major repository churn.
- `--mode diff` and `--incremental` optimize for changed-file workflows.
- Machine output contracts (`decision.json`, `ci-result.json`, `results.sarif`) are suited for automation.

## Development and maintenance

### Local development scripts

| Script | Description |
|--------|-------------|
| `npm run build` | Compile TypeScript to `dist/` (runs build verification post-step) |
| `npm run dev` | Run CLI entry in dev mode using `tsx` |
| `npm run typecheck` | TypeScript strict type check (no emit) |
| `npm run lint` | ESLint with zero warnings |
| `npm test` | Node test runner for all configured test files |
| `npm run test:coverage` | Test suite with lcov + text coverage via `c8` |
| `npm run ci` | Full local CI gate: typecheck + lint + test |
| `npm run clean` | Remove `dist/` directory |
| `npm run refresh-majors` | Refresh curated package major-version metadata (network required) |
| `npm run docs:catalog` | Generate `docs/rules-catalog.md` from engine rule definitions |

### Node version

- Runtime requirement: `node >= 18.0.0`
- Recommended for CI: Node.js `20.x` LTS

## Production adoption checklist

- Run `check` in CI on every PR and protected branch push.
- Upload `results.sarif` to your security platform (GitHub Advanced Security compatible).
- Track `scores.json` and `decision.json` over time for trend baselining.
- Use `--rescan` for release branches and major refactors.
- Keep `VULN_DB_URL` fresh if using private override intelligence.
- Open `project-report/index.html` locally for the full interactive dashboard view.

## Open-source governance

- Contribution guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Security policy: `SECURITY.md`
- Support guide: `SUPPORT.md`
- Change history: `CHANGELOG.md`
- Release process: `RELEASING.md`

## License

MIT
