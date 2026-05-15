# Security Policy

## Supported versions

`project-inspector` is pre-1.0 (`0.x`), so only the latest released minor is considered supported for security fixes.

| Version | Supported |
|---------|-----------|
| Latest `0.x` | Yes |
| Older `0.x` | Best effort |

## Reporting a vulnerability

Please do **not** disclose vulnerabilities via public GitHub issues.

Instead, report privately with:

- A clear vulnerability description.
- Reproduction steps or proof of concept.
- Affected version(s) and environment details.
- Potential impact assessment.

Use [GitHub private vulnerability reporting](https://github.com/vcian/project-inspector/security/advisories/new) or email `support@viitorcloud.com` for coordinated disclosure.

## Response targets

Project maintainers aim for:

- Initial triage acknowledgment: within 3 business days.
- Confirmation/rejection after triage: within 7 business days.
- Fix timeline: depends on severity and complexity.

These are targets, not guaranteed SLAs.

## Coordinated disclosure

- Please allow reasonable time to investigate and patch.
- We will coordinate disclosure timing after a fix is available.
- Credit is provided to reporters unless anonymity is requested.

## Security hardening notes for users

`project-inspector` is a static-analysis tool and should be treated as one signal in a broader secure SDLC:

- Pair with dynamic testing, threat modeling, and secure code review.
- Validate findings before making production decisions.
- Run in isolated CI environments for untrusted repositories.
- Keep Node runtime and dependencies updated.
