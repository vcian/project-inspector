# GitHub App (optional PR Checks)

First-class PR Checks can **upload SARIF** today via Actions (`results.sarif`). This folder documents an optional GitHub App pattern:

1. Register a GitHub App with **Checks: write** and **Pull requests: read**.
2. On `pull_request` / `workflow_run`, clone the head ref and run `project-inspector check`.
3. Annotate from SARIF or split `pr-comment.md` into inline review comments.

Keep the App stateless: store no scan payloads — regenerate from CI artifacts only.
