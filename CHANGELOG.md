# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Production-grade `README.md` with complete CLI usage, CI guidance, output contracts, and limitations.
- Open-source governance docs:
  - `CONTRIBUTING.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `CHANGELOG.md`
- Baseline GitHub Actions CI workflow for typecheck, lint, tests, deep scan, and SARIF upload.

## [0.3.0] - 2026-05-05

### Added

- Offline-first deterministic scanning pipeline.
- Multi-engine analysis architecture (AST, security, dependencies, API, performance, memory, database, tests, lint, inventory).
- Report generation for markdown and machine formats (`json`, `sarif`).
- CI readiness gating via `check` and `decision.json`.
