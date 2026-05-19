# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2] - 2026-05-19

### Fixed

- Moved `typescript` from `devDependencies` to `dependencies` — required at runtime by `ast-engine` and `security-engine` (`JsxEmit`, `ScriptTarget` imports).
- Package scoped to `@vcian/project-inspector` for npm organization publishing.

## [0.3.1] - 2026-05-15

### Added

- Production-grade `README.md` with complete CLI usage, CI guidance, output contracts, and limitations.
- Open-source governance docs: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `SUPPORT.md`, `CHANGELOG.md`, `RELEASING.md`.
- Baseline GitHub Actions CI workflow (typecheck, lint, tests) and automated release workflow with npm provenance.
- `RELEASING.md` step-by-step release process documentation.

## [0.3.0] - 2026-05-05

### Added

- Offline-first deterministic scanning pipeline.
- Multi-engine analysis architecture (AST, security, dependencies, API, performance, memory, database, tests, lint, inventory).
- Report generation for markdown and machine formats (`json`, `sarif`).
- CI readiness gating via `check` and `decision.json`.

[Unreleased]: https://github.com/vcian/project-inspector/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/vcian/project-inspector/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/vcian/project-inspector/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/vcian/project-inspector/releases/tag/v0.3.0
