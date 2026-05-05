# Releasing project-inspector

This document defines the standard release process for `project-inspector`.

## Release strategy

- Versioning: Semantic Versioning (`MAJOR.MINOR.PATCH`).
- Trigger: Git tag push matching `v*.*.*`.
- Automation: `.github/workflows/release.yml`.
- Publish target: npm public registry with provenance.

## Prerequisites

- You have publish rights on npm for `project-inspector`.
- Repository secret `NPM_TOKEN` is configured.
- Branch protection and CI checks are green.
- `CHANGELOG.md` is updated for the release.

## Pre-release checklist

- [ ] `npm run typecheck`
- [ ] `npm run lint`
- [ ] `npm test`
- [ ] `npm run build`
- [ ] `npm run dev -- check --mode deep --rescan --format json`
- [ ] `README.md` and docs reflect current CLI behavior
- [ ] `CHANGELOG.md` has final release notes

## Step-by-step release

### 1) Ensure main is up to date

```bash
git checkout main
git pull origin main
```

### 2) Bump version

Choose one:

```bash
npm version patch
# or
npm version minor
# or
npm version major
```

This updates `package.json` and `package-lock.json` and creates a local tag.

### 3) Push commit and tag

```bash
git push origin main --follow-tags
```

This triggers the release workflow on the new `vX.Y.Z` tag.

### 4) Verify automation

After workflow completion, confirm:

- GitHub release is created for the tag.
- npm package is published:
  - `npm view project-inspector version`
- provenance was attached by workflow (`--provenance`).

## Manual verification after publish

Install and smoke test:

```bash
npm install -g project-inspector@latest
project-inspector --help
```

Run a quick scan in a sample repo:

```bash
project-inspector scan --mode quick
```

## Rollback / hotfix guidance

### npm package issues

- Do not unpublish stable packages unless absolutely necessary.
- Publish a patch fix immediately (e.g., `v0.3.2`) with corrected behavior.
- Mark problematic release in GitHub notes and changelog.

### GitHub release note issues

- Edit release notes in GitHub UI.
- Keep `CHANGELOG.md` as source of truth.

## Release cadence recommendation

- Patch: bug fixes, false-positive tuning, docs corrections.
- Minor: new engine rules, non-breaking CLI/report enhancements.
- Major: breaking output schema, breaking CLI semantics, major rule behavior shifts.

## Ownership

At least one maintainer should:

- approve the release PR,
- verify CI artifacts,
- and validate npm publish results.
