# Project Inspector Overview

## What This Package Is

`project-inspector` is an offline-first static analysis CLI and library for Node.js and JavaScript/TypeScript projects. Its goal is to scan a codebase deterministically, without requiring an LLM or cloud API, and produce practical engineering reports around:

- security
- dependency risk
- architecture
- API surface
- environment/config hygiene
- performance and memory risks
- code quality and maintainability
- test coverage signals
- production-readiness scoring

The current package is aimed at Node.js / TypeScript / React / Next.js / Express / Fastify projects, with heuristic NestJS support.

## Package Purpose

The package exists to answer a simple question:

"If we point this tool at a project, can it quickly tell us whether the codebase looks healthy, risky, or not production-ready?"

It is not a compiler, not a runtime profiler, and not a full security scanner with deep taint analysis. It is a static, deterministic intelligence layer that turns repository structure and source code patterns into actionable reports.

## What Is Implemented Today

### CLI surface

The package already ships a real CLI with these commands:

- `scan`
- `check`
- `watch`
- `chat`
- `clear`
- `update-vuln-db`

### Programmatic API

The library exports:

- `runScan`
- `evaluateCheckGates`
- `clearProjectReportDir`
- `downloadVulnDbOverride`

That means it can be used both as a terminal tool and as an embedded library in CI or other automation.

### Analysis engines currently present

The scan pipeline already includes these engines:

- AST engine
- security engine
- dependency engine
- outdated dependency engine
- migration engine
- API engine
- environment engine
- architecture engine
- performance engine
- memory engine
- code-smell engine
- database engine
- test engine
- inventory engine
- lint engine
- self-check engine
- compliance mapper
- scoring engine
- hotspot engine

### Report outputs

The tool can already generate:

- markdown reports
- `issues.json`
- `inventory.json`
- `scores.json`
- `ci-result.json` from `check`
- `results.json` optional machine output
- `results.sarif` optional SARIF output

### Scan modes and operational features

These workflow features are implemented:

- `quick`, `deep`, and `diff` scan modes
- incremental scanning from git-changed files
- file-hash caching
- merged scan cache reuse
- dependency snapshot reuse
- env snapshot reuse
- AST cache reuse
- watch mode with debounce + single-flight queue
- optional online `npm audit`
- optional remote vulnerability DB override download
- CI-style gate evaluation

## How The Package Works

At a high level the flow is:

1. CLI parses command options.
2. `runScan()` discovers source files and detects the project profile.
3. The runner computes file hashes and cache state.
4. It decides whether to fully scan, partially scan, or reuse previous results.
5. Engines analyze the repository in parallel where possible.
6. Findings are enriched with compliance mappings.
7. Scores and hotspots are computed.
8. Reports and machine-readable outputs are written to `project-report/`.

### Main runtime flow

The main orchestration happens in `src/core/scan-runner.ts`.

That file is responsible for:

- scan mode behavior
- cache reuse and invalidation
- incremental file selection
- engine scheduling
- fallback handling if an engine crashes
- result merging for partial scans
- output writing

### Detection and inventory

The package first detects framework/runtime characteristics from `package.json`, lockfiles, and `tsconfig.json`.

It currently infers:

- framework family
- package manager
- TypeScript presence
- JSX presence
- runtime class (`node`, `browser`, `hybrid`)
- entry points from package metadata

Then the inventory engine classifies files into kinds like:

- controller
- service
- repository
- route
- component
- page
- layout
- module
- DTO
- entity
- test
- util

### AST engine

The AST engine is one of the strongest implemented pieces. It uses `ts-morph` and already supports:

- function discovery
- complexity estimation
- nesting-depth estimation
- long-function detection
- local import graph generation
- circular dependency detection
- unused export heuristics

This gives the tool real structural understanding instead of only regex scanning.

### Security engine

The security engine combines regex heuristics and AST heuristics.

It currently looks for patterns like:

- hardcoded secrets and token shapes
- `eval`
- `new Function`
- DOM/React HTML injection
- command execution risk
- SQL interpolation hints
- weak crypto usage
- insecure randomness
- permissive CORS
- JWT misconfiguration
- SSRF-like request patterns
- framework-specific hints for NestJS, Express, Next.js, Angular

This is useful, but still heuristic. It does not perform real cross-function taint tracking.

### Dependency and supply-chain analysis

Dependency intelligence is implemented in multiple layers:

- lockfile detection
- direct dependency counting
- offline vulnerability rule matching
- optional downloaded vulnerability-rule overrides
- deprecated package heuristics
- optional online `npm audit`
- outdated-major detection from bundled known-major data
- migration hints for Next.js, React, NestJS, Fastify, Express, Mongoose, and `@types/node`

### API analysis

The API engine detects route-like handlers for:

- Express
- Fastify
- Next.js route handlers
- NestJS controllers

It also adds heuristics for:

- likely protected vs unknown auth
- likely present vs likely missing validation

### Environment analysis

The env engine currently checks:

- root `.env*` files
- whether env files are tracked by git
- possible secrets inside tracked env files
- env keys found in files
- env keys referenced in source
- possible missing documented env keys

### Performance and memory analysis

The package already scans for operational Node.js risks such as:

- sync filesystem usage
- sync child-process calls
- CPU-heavy sync crypto
- `await` inside loops
- nested loops
- regex backtracking risk
- unbounded in-memory caches
- uncleared intervals
- listener cleanup issues
- whole-buffer accumulation
- stream lifecycle leaks
- global state retention

### Database analysis

The database engine is heuristic but useful. It can already detect:

- raw SQL usage
- SQL template interpolation
- string-concatenated SQL with request values
- `Prisma.$queryRawUnsafe`
- `SELECT *`
- ORM/library signals

### Test, lint, scoring, and reporting

The package also has real support for:

- test file discovery and low-coverage heuristics
- ESLint integration
- TypeScript compiler diagnostics
- Prettier check integration
- readiness scoring
- CI gate failure generation
- human-readable markdown reports
- SARIF generation

## Current State Of This Repository

Based on the latest generated reports checked into `project-report/`, this repository is feature-rich but not yet production-ready as a mature external tool.

### Current positive signals

- Core CLI is implemented end-to-end.
- The engine architecture is real, not placeholder-only.
- Caching and incremental scan behavior are implemented.
- SARIF and CI gate output exist.
- Report generation is substantial and well-structured.
- The package has both CLI and library entry points.

### Current weak signals

- No automated test suite is present.
- The tool fails its own readiness gate.
- The tool flags many issues against itself.
- `src/core/scan-runner.ts` is a very large orchestration module.
- Some detections are broad enough to produce self-scan noise and likely false positives.
- Plugin discovery exists, but plugin execution/integration is not wired into the scan flow.

### Self-scan snapshot from current reports

The latest `project-report/summary.md` shows roughly:

- 55 files analyzed
- 169 functions mapped
- 118 import edges
- 0 circular dependency chains
- 7 security issues
- 22 performance issues
- 3 test-related issues
- 2 database issues
- 1 architecture issue
- production readiness score: `2/100` on the latest deep scan report

The latest checked `ci-result.json` also shows the check currently failing, mainly because of:

- low readiness score
- low security score
- no automated tests

## What The Codebase Covers Well

The strongest implemented areas today are:

- scan orchestration
- offline report generation
- AST-based maintainability analysis
- multi-engine architecture
- dependency and outdated-package intelligence
- Node.js performance and memory heuristics
- CI gating and SARIF export
- incremental and cached scanning

This is already enough for:

- local engineering review
- internal codebase health checks
- CI experiments
- early-stage static-analysis adoption
- proof-of-concept production pilots under supervision

## What Is Not Covered Well Yet

The package is not yet a complete production-grade scanner in these areas:

- no inter-procedural taint analysis
- no true data-flow analysis from input to sink
- no real type-aware security reasoning beyond local AST patterns
- no runtime validation of findings
- no real test coverage integration from Jest/Vitest/nyc reports
- no package-manager-deep analysis beyond current heuristics
- no monorepo/package-workspace-aware orchestration layer
- no user-facing config system for suppressions, thresholds, or custom rules
- no active plugin execution model
- no schema-aware database analysis
- no framework-specific deep analyzers beyond heuristics

## Is It Production Ready?

Short answer: not yet for broad external production use as a trusted gatekeeper.

More precise answer:

- It is production-shaped software.
- It is not yet production-hardened software.

Today it looks closer to a strong internal beta than a final production-grade analysis product.

Reasons:

- no automated tests
- large orchestrator complexity
- self-scan false-positive pressure
- limited configurability
- heuristic-heavy findings
- no independent verification of build/lint/test health from this review session

## Biggest Missing Pieces

These are the highest-priority missing pieces if the goal is a serious production release.

### 1. Automated tests

This is the biggest gap by far.

Needed immediately:

- unit tests for each engine
- regression fixtures for rule matching
- snapshot tests for report output
- CLI integration tests for `scan`, `check`, and `watch`
- cache/incremental behavior tests

### 2. False-positive reduction

The tool currently finds many issues in its own analysis code because the rules are broad. Some of that is valid, but some is expected scanner self-noise.

Needed:

- confidence tuning
- engine-specific suppressions
- scanner-internal rule exemptions where justified
- better distinction between test/dev/tooling code and runtime app code

### 3. Refactor the scan runner

`src/core/scan-runner.ts` currently owns too many responsibilities.

It should be split into smaller units such as:

- file discovery and cache planner
- engine execution planner
- partial merge coordinator
- output writer
- budget/timing manager

### 4. Configuration system

Right now the product is mostly flag-driven.

A real production package should support a config file for:

- enabled/disabled engines
- custom thresholds
- ignore paths
- severity overrides
- finding suppressions
- framework-specific settings

### 5. Stronger ecosystem support

To be widely useful, the tool should improve:

- monorepo/workspace awareness
- pnpm/yarn workspace intelligence
- framework-deep scanning for NestJS/Next.js
- richer dependency knowledge
- better API/auth detection

## Recommended Next Improvement Plan

### Phase 1: make the tool trustworthy

- add automated tests
- refactor `scan-runner`
- stabilize lint and report artifacts
- reduce self-scan noise

### Phase 2: make the tool configurable

- add config file support
- add suppression/baseline support
- add per-engine toggles and thresholds

### Phase 3: make the tool more accurate

- better route/auth detection
- better SQL and secret heuristics
- partial data-flow analysis for common sink patterns
- monorepo awareness

### Phase 4: make the tool easier to adopt

- improve docs with examples
- add golden sample repositories
- add CI examples for GitHub Actions
- publish rule coverage and known limitations clearly

## Bottom-Line Assessment

`project-inspector` already implements a meaningful static-analysis product. It is not just scaffolding. The CLI, scan pipeline, engine set, caching, scoring, and report generation are all real and substantial.

However, the package still needs hardening before it should be treated as a production-grade quality/security gate for other teams. The most important work now is not "add more features first"; it is:

- tests
- refactoring
- configuration
- false-positive control
- production hardening

If we position it honestly today, the best label is:

"Promising internal beta/static-analysis platform with strong offline reporting and good architectural foundations, but still missing the reliability and tuning expected from a production-grade scanner."
