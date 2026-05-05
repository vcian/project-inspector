import type { Issue } from '../core/types.js';

export interface LocalVulnRule {
  readonly id: string;
  readonly packageNames: readonly string[];
  readonly severity: Issue['severity'];
  readonly title: string;
  readonly description: string;
  readonly impact: string;
  readonly fix: string;
  /**
   * When set, emit only if the declared semver major parsed from `package.json` is **<=** this value
   * (typical for “legacy line” advisories).
   */
  readonly matchIfDeclaredMajorAtMost?: number;
  /** Optional 0–100 severity weight for CI aggregation; defaults derived from severity if omitted. */
  readonly severityScore?: number;
}

/** Curated offline rules (advisory-style); extend via `VULN_DB_URL` + `update-vuln-db`. */
export const LOCAL_VULN_RULES: readonly LocalVulnRule[] = [
  {
    id: 'lodash-prototype-pollution-era',
    packageNames: ['lodash'],
    severity: 'HIGH',
    title: 'lodash: review prototype pollution history for your semver range',
    description:
      'lodash 4.x lines had multiple prototype pollution CVEs; verify resolved version against advisories.',
    impact: 'Remote prototype pollution can lead to RCE or auth bypass in vulnerable merge/clone patterns.',
    fix: 'Upgrade lodash to a patched minor per npm advisory; run npm audit when online.',
    matchIfDeclaredMajorAtMost: 4,
    severityScore: 82,
  },
  {
    id: 'minimist-prototype',
    packageNames: ['minimist'],
    severity: 'MEDIUM',
    title: 'minimist: historical prototype pollution issues',
    description: 'minimist had prototype pollution advisories; verify your resolved version.',
    impact: 'Argument parsing bugs in CLI tools.',
    fix: 'Upgrade minimist; prefer structured argv parsers where possible.',
    severityScore: 44,
  },
  {
    id: 'xml2js-xxe',
    packageNames: ['xml2js'],
    severity: 'MEDIUM',
    title: 'xml2js: verify XXE-safe configuration for untrusted XML',
    description: 'XML parsers are common SSRF/XXE sinks when misconfigured.',
    impact: 'Server-side request forgery and file disclosure.',
    fix: 'Disable external entities; do not parse untrusted XML without hardening.',
  },
  {
    id: 'request-unmaintained',
    packageNames: ['request'],
    severity: 'HIGH',
    title: 'request package is unmaintained',
    description: 'The request HTTP client is deprecated with no security fixes.',
    impact: 'Unpatched transitive vulnerabilities.',
    fix: 'Migrate to fetch/undici/axios with active maintenance.',
  },
];

export interface LoadedVulnRules {
  readonly bundled: readonly LocalVulnRule[];
  readonly override: readonly LocalVulnRule[];
}

export function mergeVulnRules(bundled: readonly LocalVulnRule[], override: readonly LocalVulnRule[]): LocalVulnRule[] {
  const byId = new Map<string, LocalVulnRule>();
  for (const r of bundled) {
    byId.set(r.id, r);
  }
  for (const r of override) {
    byId.set(r.id, r);
  }
  return [...byId.values()];
}
