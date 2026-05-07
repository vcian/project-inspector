# project-inspector documentation

- **[Rules catalog](./rules-catalog.md)** — generated inventory of heuristic rule titles per engine (`node scripts/gen-rules-catalog.mjs`).
- **Policy packs** — place JSON under `packs/<id>.json` and set `"policyPack": "<id>"` in `project-inspector.config.json`.

Publish this folder with GitHub Pages or mkdocs; keep generated catalogs in CI.
