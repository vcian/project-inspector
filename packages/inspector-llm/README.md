# inspector-llm (optional BYOK)

Bring-your-own-key optional layer that turns trusted findings into plain-language explanations and suggested patches.

**Default posture:** disabled — core `project-inspector` stays deterministic and offline.

## Planned integration

1. Read `project-report/decision.json` + `scores.json` + `results.sarif`.
2. Call your LLM provider with a pinned prompt template (no repo code leaves your boundary unless you choose).
3. Emit `project-report/llm-explain.md` for human review only — never feed back into CI gates without explicit approval.

## Security

- Never commit API keys; use CI secrets or local env vars.
- Treat LLM output as **untrusted narrative** until reviewed.
