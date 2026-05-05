import type { ComplianceTag, Issue, ScanResult } from '../core/types.js';

function tagsForIssue(issue: Issue): ComplianceTag[] {
  const t: ComplianceTag[] = [];
  const title = issue.title.toLowerCase();
  const desc = issue.description.toLowerCase();
  const eng = issue.engine;

  const push = (framework: ComplianceTag['framework'], ruleId: string, ruleName: string): void => {
    t.push({ framework, ruleId, ruleName });
  };

  if (eng === 'security') {
    if (title.includes('secret') || title.includes('token') || title.includes('key') || title.includes('stripe')) {
      push('OWASP_TOP_10', 'A02:2021', 'Cryptographic Failures');
      push('OWASP_TOP_10', 'A07:2021', 'Identification and Authentication Failures');
      push('SANS_TOP_25', 'CWE-798', 'Use of Hard-coded Credentials');
      push('GDPR', 'Art.32', 'Security of processing');
    }
    if (title.includes('eval') || title.includes('function()') || title.includes('injection') || title.includes('sql')) {
      push('OWASP_TOP_10', 'A03:2021', 'Injection');
      push('SANS_TOP_25', 'CWE-89', 'SQL Injection');
    }
    if (title.includes('xss') || title.includes('innerhtml') || title.includes('dangerouslysetinnerhtml')) {
      push('OWASP_TOP_10', 'A03:2021', 'Injection (XSS)');
      push('SANS_TOP_25', 'CWE-79', 'Cross-site Scripting');
      push('INDIA_IT', 'DPDP-2023', 'Data integrity & security expectations');
    }
    if (title.includes('command') || title.includes('child_process') || title.includes('shell')) {
      push('OWASP_TOP_10', 'A03:2021', 'Injection (Command)');
      push('SANS_TOP_25', 'CWE-78', 'OS Command Injection');
    }
    if (title.includes('ssrf') || desc.includes('ssrf')) {
      push('SANS_TOP_25', 'CWE-918', 'Server-Side Request Forgery');
    }
    if (title.includes('prototype') || title.includes('pollution')) {
      push('SANS_TOP_25', 'CWE-1321', 'Improperly Controlled Modification of Object Prototype');
    }
    if (title.includes('cors')) {
      push('OWASP_TOP_10', 'A05:2021', 'Security Misconfiguration');
    }
    if (title.includes('rate') || title.includes('throttle') || title.includes('brute')) {
      push('OWASP_TOP_10', 'A07:2021', 'Identification and Authentication Failures');
    }
    if (title.includes('log') || title.includes('monitor')) {
      push('OWASP_TOP_10', 'A09:2021', 'Security Logging and Monitoring Failures');
    }
    if (title.includes('ssrf') || desc.includes('ssrf')) {
      push('OWASP_TOP_10', 'A10:2021', 'Server-Side Request Forgery');
    }
  }

  if (eng === 'api') {
    if (title.includes('auth')) {
      push('OWASP_TOP_10', 'A01:2021', 'Broken Access Control');
    }
    if (title.includes('validation')) {
      push('OWASP_TOP_10', 'A04:2021', 'Insecure Design');
    }
  }

  if (eng === 'dependency' || eng === 'outdated') {
    push('OWASP_TOP_10', 'A06:2021', 'Vulnerable and Outdated Components');
    push('SANS_TOP_25', 'CWE-1104', 'Use of Unmaintained Third-Party Components');
    if (title.includes('vulnerabilit') || title.includes('deprecated') || title.includes('drift')) {
      push('INDIA_IT', 'CERT-In', 'Vulnerability management baseline');
    }
  }

  if (eng === 'database') {
    if (title.toLowerCase().includes('injection') || title.toLowerCase().includes('interpolation')) {
      push('OWASP_TOP_10', 'A03:2021', 'Injection');
      push('SANS_TOP_25', 'CWE-89', 'SQL Injection');
    } else if (title.toLowerCase().includes('raw sql')) {
      push('OWASP_TOP_10', 'A03:2021', 'Injection (data access)');
      push('SANS_TOP_25', 'CWE-20', 'Improper Input Validation');
    } else {
      push('OWASP_TOP_10', 'A04:2021', 'Insecure Design (data layer)');
    }
    push('GDPR', 'Art.32', 'Security of processing');
  }

  if (eng === 'tests') {
    push('OWASP_TOP_10', 'A04:2021', 'Insecure Design (verification gaps)');
    push('SANS_TOP_25', 'CWE-1188', 'Insecure Default Initialization of Resource');
  }

  if (eng === 'env') {
    if (title.includes('tracked') || title.includes('git')) {
      push('OWASP_TOP_10', 'A09:2021', 'Security Logging and Monitoring Failures');
      push('GDPR', 'Art.32', 'Security of processing');
      push('HIPAA', '164.312(a)(2)(iv)', 'Encryption and integrity (media handling)');
      push('INDIA_IT', 'DPDP-2023', 'Reasonable security safeguards');
    } else if (title.includes('missing')) {
      push('OWASP_TOP_10', 'A05:2021', 'Security Misconfiguration');
    }
  }

  if (eng === 'architecture' && title.includes('child_process')) {
    push('OWASP_TOP_10', 'A04:2021', 'Insecure Design');
  }

  if (eng === 'memory' || eng === 'performance') {
    push('OWASP_TOP_10', 'A04:2021', 'Insecure Design (resilience/availability)');
  }

  if (eng === 'ast' && issue.severity === 'HIGH') {
    push('OWASP_TOP_10', 'A04:2021', 'Insecure Design (maintainability / coupling)');
  }

  if (/\bpassword\b|\bemail\b|\bphone\b|\bssn\b|\bphi\b/.test(title) || /\bpassword\b/.test(desc)) {
    push('GDPR', 'Art.5(1)(f)', 'Integrity and confidentiality');
    push('HIPAA', '164.312(e)(1)', 'Transmission security (when applicable)');
  }

  return dedupeTags(t);
}

function dedupeTags(tags: ComplianceTag[]): ComplianceTag[] {
  const seen = new Set<string>();
  const out: ComplianceTag[] = [];
  for (const tag of tags) {
    const k = `${tag.framework}:${tag.ruleId}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(tag);
    }
  }
  return out;
}

export function enrichIssue(issue: Issue): Issue {
  const compliance = tagsForIssue(issue);
  if (compliance.length === 0) {
    return issue;
  }
  return { ...issue, compliance };
}

export function enrichAllIssues(result: ScanResult): ScanResult {
  const mapAst = { ...result.ast, issues: result.ast.issues.map(enrichIssue) };
  const mapSec = { ...result.security, issues: result.security.issues.map(enrichIssue) };
  const mapDep = { ...result.dependency, issues: result.dependency.issues.map(enrichIssue) };
  const mapOut = { ...result.outdated, issues: result.outdated.issues.map(enrichIssue) };
  const mapTests = { ...result.tests, issues: result.tests.issues.map(enrichIssue) };
  const mapDb = { ...result.database, issues: result.database.issues.map(enrichIssue) };
  const mapApi = { ...result.api, issues: result.api.issues.map(enrichIssue) };
  const mapEnv = { ...result.env, issues: result.env.issues.map(enrichIssue) };
  const mapArch = { ...result.architecture, issues: result.architecture.issues.map(enrichIssue) };
  const mapPerf = { ...result.performance, issues: result.performance.issues.map(enrichIssue) };
  const mapMem = { ...result.memory, issues: result.memory.issues.map(enrichIssue) };
  const mapSmell = { ...result.codeSmell, issues: result.codeSmell.issues.map(enrichIssue) };
  const mapMig = { ...result.migration, issues: result.migration.issues.map(enrichIssue) };
  const mapInv = { ...result.inventory, issues: result.inventory.issues.map(enrichIssue) };
  const mapLint = { ...result.lint, issues: result.lint.issues.map(enrichIssue) };

  return {
    ...result,
    ast: mapAst,
    security: mapSec,
    dependency: mapDep,
    outdated: mapOut,
    tests: mapTests,
    database: mapDb,
    api: mapApi,
    env: mapEnv,
    architecture: mapArch,
    performance: mapPerf,
    memory: mapMem,
    codeSmell: mapSmell,
    migration: mapMig,
    inventory: mapInv,
    lint: mapLint,
  };
}
