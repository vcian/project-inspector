# Contributing to project-inspector

Thanks for contributing to `project-inspector`.

## Development setup

### Prerequisites

- Node.js `20.x` LTS recommended (`>=18` supported by package engines).
- npm `>=9`.

### Install

```bash
npm install
```

### Useful commands

```bash
npm run build
npm run typecheck
npm run lint
npm test
```

Run the CLI locally in dev mode:

```bash
npm run dev -- scan --mode deep --rescan
```

## Branch and commit guidelines

- Create focused branches (one concern per PR).
- Keep commits atomic and descriptive.
- Prefer small, reviewable pull requests.
- Reference related issue IDs in PR descriptions.

## Pull request checklist

Before opening a PR, ensure:

- Code builds and type-checks.
- Lint passes with zero warnings.
- Relevant tests are added/updated.
- Documentation is updated when behavior or output changes.
- CLI examples in docs still work.
- Backward compatibility is considered for output contracts.

## Testing expectations

For any engine/reporting change, add regression coverage:

- Engine unit tests for detection behavior.
- Snapshot/contract tests for report output where applicable.
- Keep tests deterministic (no flaky time/network coupling).

## Security and responsible disclosure

Do not open public issues for exploitable vulnerabilities.
Please follow `SECURITY.md` for private disclosure.

## Coding standards

- TypeScript strictness: avoid `any`.
- Fail safely: handle errors explicitly.
- Keep analyzer rules deterministic and testable.
- Prefer explicit code over clever shortcuts.

## Scope of contributions

Good first contribution areas:

- False-positive reductions.
- Test coverage improvements.
- Report UX and readability.
- New deterministic rules with fixtures.
- Docs, examples, and CI improvements.

Changes that may require maintainer discussion first:

- Scoring/gating policy changes.
- Output schema breaking changes.
- Major rule semantics shifts.

## Reporting bugs and feature requests

When filing issues, include:

- OS and Node version.
- Exact command and flags used.
- Minimal reproducible repository or code sample.
- Relevant output files from `project-report/`.

This helps maintainers reproduce and fix quickly.
