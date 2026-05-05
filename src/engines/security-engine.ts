import { readFile } from 'node:fs/promises';
import { normalize } from 'node:path';
import { ScriptTarget } from 'typescript';
import type { Project } from 'ts-morph';
import { Project as TsMorphProject, SyntaxKind } from 'ts-morph';

import type { FrameworkTag, Issue, ProjectProfile, SecurityScanResult } from '../core/types.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';
import { runPool } from '../utils/async-pool.js';
import { frameworkForFile } from '../utils/detect-project.js';

interface LineRule {
  readonly id: string;
  readonly title: string;
  readonly severity: Issue['severity'];
  readonly regex: RegExp;
  readonly description: string;
  readonly impact: string;
  readonly fix: string;
  readonly whyItMatters?: string;
  readonly framework?: FrameworkTag;
}

const SELF_ANALYZER_RULE_IDS = new Set<string>([
  'eval',
  'new-function',
  'jwt-none-alg',
  'jwt-verify-false',
]);

function isSecurityAnalyzerFile(absPath: string): boolean {
  return absPath.replaceAll('\\', '/').toLowerCase().endsWith('/src/engines/security-engine.ts');
}

const SECRET_RULES: readonly LineRule[] = [
  {
    id: 'aws-access-key',
    title: 'Possible AWS access key material',
    severity: 'CRITICAL',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    description: 'String resembles an AWS access key id.',
    impact: 'Leaked keys grant cloud resource access, data exfiltration, privilege escalation.',
    fix: 'Rotate credentials, move to vault / OIDC, audit git history, enable GuardDuty.',
    whyItMatters: 'Public AWS keys get scanned by attackers within minutes.',
  },
  {
    id: 'github-token',
    title: 'Possible GitHub personal access token',
    severity: 'CRITICAL',
    regex: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
    description: 'String resembles a GitHub token.',
    impact: 'Repo/org takeover depending on scopes.',
    fix: 'Revoke and rotate; use short-lived OIDC or GitHub App tokens.',
  },
  {
    id: 'slack-token',
    title: 'Possible Slack token',
    severity: 'CRITICAL',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    description: 'String resembles a Slack bot/user token.',
    impact: 'Workspace messaging and secrets channels may leak.',
    fix: 'Revoke and rotate; store in a secret manager.',
  },
  {
    id: 'stripe-live',
    title: 'Possible Stripe secret key',
    severity: 'CRITICAL',
    regex: /\bsk_live_[A-Za-z0-9]{16,}\b/,
    description: 'Stripe live secret key pattern.',
    impact: 'Payment fraud and customer data exposure.',
    fix: 'Rotate keys immediately; never embed live secrets in client bundles.',
  },
  {
    id: 'jwt-token',
    title: 'Hardcoded JWT token in source',
    severity: 'HIGH',
    regex: /['"]eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}['"]/,
    description: 'A JWT literal was found in source.',
    impact: 'Static JWTs leak privileges and cannot be rotated quickly.',
    fix: 'Issue tokens at runtime; never hardcode.',
  },
  {
    id: 'private-key',
    title: 'PEM private key material in source',
    severity: 'CRITICAL',
    regex: /-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PRIVATE)\s+PRIVATE\s+KEY-----/,
    description: 'PEM-formatted private key detected.',
    impact: 'Severe key compromise; full signing/decryption capability.',
    fix: 'Rotate key immediately; move to KMS / HSM; purge from history.',
  },
  {
    id: 'generic-api-key',
    title: 'Possible hardcoded API key assignment',
    severity: 'HIGH',
    regex: /\b(?:api[_-]?key|apikey|secret|client_secret|password|passwd)\s*[:=]\s*['"][^'"\s]{12,}['"]/i,
    description: 'Literal assignment matching a credential pattern.',
    impact: 'Secrets leak via repositories, logs, and bundles.',
    fix: 'Load from environment or secret manager; enforce pre-commit secret scanning.',
  },
];

const GENERIC_LINE_RULES: readonly LineRule[] = [
  {
    id: 'eval',
    title: 'Use of eval()',
    severity: 'HIGH',
    regex: /\beval\s*\(/,
    description: 'eval executes arbitrary code and is difficult to secure.',
    impact: 'Remote code execution if attacker-controlled input reaches eval.',
    fix: 'Remove eval; use JSON.parse for JSON; redesign dynamic behavior.',
  },
  {
    id: 'new-function',
    title: 'Use of new Function()',
    severity: 'HIGH',
    regex: /\bnew\s+Function\s*\(/,
    description: 'Dynamic code generation — equivalent to eval in most threat models.',
    impact: 'Arbitrary code execution if inputs are influenced by users.',
    fix: 'Replace with safe parsing or explicit logic tables.',
  },
  {
    id: 'dom-xss',
    title: 'DOM XSS risk: direct HTML injection',
    severity: 'MEDIUM',
    regex: /\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=|\.insertAdjacentHTML\s*\(/,
    description: 'Assigning HTML from strings can introduce cross-site scripting.',
    impact: 'Session theft and account takeover.',
    fix: 'Prefer textContent; sanitize with a trusted library.',
  },
  {
    id: 'react-dangerous-html',
    title: 'React dangerouslySetInnerHTML usage',
    severity: 'MEDIUM',
    regex: /dangerouslySetInnerHTML/,
    description: 'Bypasses React escaping; XSS if HTML is influenced by users.',
    impact: 'Stored/reflected XSS.',
    fix: 'Avoid raw HTML; sanitize strictly; prefer server-side HTML generation.',
    framework: 'react',
  },
  {
    id: 'cmd-injection-template',
    title: 'Potential command injection via templated shell',
    severity: 'HIGH',
    regex: /(?<!\.)\b(?:exec|execSync)\s*\([^)]*[`$]/,
    description: 'Shell commands with template strings often concatenate untrusted input.',
    impact: 'Remote command execution on the host.',
    fix: 'Use spawn with argv array, validate inputs, avoid shell:true.',
  },
  {
    id: 'sql-string-concat',
    title: 'Possible SQL injection via string interpolation',
    severity: 'HIGH',
    regex: /\bquery\s*\([^)]*(?:`|\$\{)[^)]*\b(?:select|insert|update|delete)\b/i,
    description: 'SQL built with template literals is often vulnerable to injection.',
    impact: 'Database exfiltration, tampering, lateral movement.',
    fix: 'Use parameterized queries / prepared statements; never interpolate user input into SQL.',
  },
  {
    id: 'env-concat',
    title: 'Environment variable concatenation into strings',
    severity: 'LOW',
    regex: /\bprocess\.env\.[A-Z0-9_]+\s*\+\s*/,
    description: 'Concatenating env vars into strings can leak configuration into logs.',
    impact: 'Operational leakage; sometimes enables SSRF.',
    fix: 'Validate and normalize configuration at startup; avoid embedding secrets in URLs.',
  },
  {
    id: 'md5-hash',
    title: 'Use of MD5 for security',
    severity: 'MEDIUM',
    regex: /crypto\.createHash\s*\(\s*['"]md5['"]\s*\)/,
    description: 'MD5 is cryptographically broken for security use-cases.',
    impact: 'Collision attacks on signatures/passwords.',
    fix: 'Use SHA-256+ for integrity; bcrypt/argon2 for passwords.',
  },
  {
    id: 'sha1-hash',
    title: 'Use of SHA-1 for security',
    severity: 'LOW',
    regex: /crypto\.createHash\s*\(\s*['"]sha1['"]\s*\)/,
    description: 'SHA-1 is weak for signing / MACs.',
    impact: 'Collision and length-extension risks.',
    fix: 'Use SHA-256+ or HMAC-SHA256.',
  },
  {
    id: 'insecure-random',
    title: 'Math.random() used for security-sensitive value',
    severity: 'MEDIUM',
    regex: /Math\.random\s*\(\s*\)[^;\n]*(?:token|secret|key|id|password|otp)/i,
    description: 'Math.random is not cryptographically secure.',
    impact: 'Predictable IDs/tokens enable account takeover.',
    fix: 'Use crypto.randomUUID() or crypto.randomBytes().',
  },
  {
    id: 'cors-wildcard-static',
    title: 'CORS configured with wildcard origin',
    severity: 'MEDIUM',
    regex: /origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin.*\*/,
    description: 'Wildcard CORS origin is risky, especially with credentials.',
    impact: 'Cross-origin data access; CSRF-adjacent abuse.',
    fix: 'Use an explicit allowlist of origins.',
  },
  {
    id: 'jwt-none-alg',
    title: 'JWT "none" algorithm accepted',
    severity: 'CRITICAL',
    regex: /algorithm[s]?\s*:\s*['"]none['"]/i,
    description: 'Accepting "none" JWT algorithm disables signature verification.',
    impact: 'Token forgery and authentication bypass.',
    fix: 'Restrict algorithms to HS256/RS256/ES256; never allow "none".',
  },
  {
    id: 'jwt-verify-false',
    title: 'JWT verification disabled (verify: false)',
    severity: 'CRITICAL',
    regex: /verify\s*:\s*false/,
    description: 'Explicitly skipping signature verification on a JWT.',
    impact: 'Full authentication bypass.',
    fix: 'Always verify signatures; use jwt.verify with the correct secret/pubkey.',
  },
  {
    id: 'ssrf-raw-url',
    title: 'Outbound request uses unvalidated user URL',
    severity: 'MEDIUM',
    regex: /(?:fetch|axios\.(?:get|post|request)|https?\.request|http\.get)\s*\(\s*(?:req\.(?:body|query|params)|request\.(?:body|query|params))/,
    description: 'Server-side fetch/axios/http request with URL derived from request input.',
    impact: 'SSRF: attacker can reach cloud metadata, internal services, or scan networks.',
    fix: 'Allowlist hosts, resolve DNS and block private IP ranges, restrict protocols.',
  },
  {
    id: 'csrf-disabled',
    title: 'CSRF protection appears disabled',
    severity: 'MEDIUM',
    regex: /\bcsrf\s*:\s*false\b|ignoreMethods\s*:\s*\[\s*\]/i,
    description: 'Route or middleware configuration suggests CSRF checks are turned off.',
    impact: 'Browsers can be coerced into sending authenticated state-changing requests.',
    fix: 'Enable CSRF defenses for cookie-backed auth flows and enforce Origin/SameSite checks.',
  },
  {
    id: 'cookie-secure-missing',
    title: 'Session cookie missing secure attributes',
    severity: 'MEDIUM',
    regex: /\b(sameSite\s*:\s*['"]none['"]|httpOnly\s*:\s*false|secure\s*:\s*false)\b/i,
    description: 'Cookie/session configuration may weaken browser-side session protection.',
    impact: 'Session theft or cross-site request abuse becomes easier.',
    fix: 'Use `httpOnly: true`, `secure: true`, and an appropriate `sameSite` policy.',
  },
  // Framework-specific.
  {
    id: 'nest-auth-guard-missing',
    title: 'NestJS controller without @UseGuards / @Auth',
    severity: 'MEDIUM',
    regex: /@Controller\s*\([^)]*\)[\s\S]{0,200}export\s+class\s+\w+/,
    description: 'Heuristic: controllers should opt into an auth guard (or be explicitly @Public).',
    impact: 'Unauthenticated access to protected endpoints.',
    fix: 'Apply @UseGuards(JwtAuthGuard) at controller or method level; mark public endpoints explicitly.',
    framework: 'nestjs',
  },
  {
    id: 'express-no-helmet',
    title: 'Express app without helmet middleware',
    severity: 'MEDIUM',
    regex: /express\s*\(\s*\)/,
    description: 'Heuristic: creating an express app without any helmet usage in file.',
    impact: 'Missing basic security headers (CSP, HSTS, X-Frame-Options).',
    fix: 'Install and use `helmet()` as global middleware before routes.',
    framework: 'express',
  },
  {
    id: 'next-unsafe-rewrite',
    title: 'Next.js rewrite/redirect with wildcard destination',
    severity: 'MEDIUM',
    regex: /destination\s*:\s*['"](?:https?:\/\/)?\*|destination\s*:\s*`?https?:\/\/\$\{/,
    description: 'Dynamic rewrite destination may allow open redirect.',
    impact: 'Open redirect for phishing / token-theft flows.',
    fix: 'Use an allowlist of destinations; validate before returning rewrites.',
    framework: 'nextjs',
  },
  {
    id: 'angular-bypass-sanitizer',
    title: 'Angular bypassSecurityTrustHtml / Url / Script call',
    severity: 'HIGH',
    regex: /bypassSecurityTrust(?:Html|Url|Script|Style|ResourceUrl)\s*\(/,
    description: 'Angular DomSanitizer bypass APIs disable built-in XSS protection.',
    impact: 'XSS if input is influenced by users.',
    fix: 'Avoid bypass APIs; if unavoidable, sanitize via a trusted library.',
    framework: 'angular',
  },
];

function mkIssue(
  rule: LineRule,
  file: string,
  line: number,
  code: string,
  framework: FrameworkTag,
  extraConfidence?: Issue['confidence'],
): Issue {
  const fw = rule.framework ?? framework;
  return {
    id: `security:${rule.id}:${file}:${String(line)}`,
    engine: 'security',
    severity: rule.severity,
    title: rule.title,
    file,
    line,
    description: rule.description,
    impact: rule.impact,
    fix: rule.fix,
    code: code.trim().slice(0, 200),
    codeSnippet: code.trim().slice(0, 200),
    category: 'security',
    framework: fw,
    confidence: extraConfidence ?? 'medium',
    ...(rule.whyItMatters !== undefined ? { whyItMatters: rule.whyItMatters } : {}),
  };
}

function shouldSkipRuleLine(lineText: string): boolean {
  const trimmed = lineText.trim();
  // Avoid self-matching security regex definitions in analyzer source files.
  return trimmed.startsWith('regex:');
}

export interface SecurityMorphContext {
  readonly project: Project;
  readonly runExclusive: <T>(fn: () => Promise<T>) => Promise<T>;
  readonly getSourceText: (normalizedAbs: string) => string | undefined;
}

const TS_LIKE = /\.(?:ts|tsx|mts|cts)$/;

async function analyzeSecurityFile(
  absPath: string,
  profile: ProjectProfile,
  morph?: SecurityMorphContext,
): Promise<Issue[]> {
  const issues: Issue[] = [];
  let text: string | undefined;
  if (morph) {
    text = morph.getSourceText(normalize(absPath));
  }
  if (text === undefined) {
    try {
      text = await readFile(absPath, 'utf8');
    } catch {
      return issues;
    }
  }

  const lines = text.split(/\r?\n/);
  const fwForFile = frameworkForFile(absPath, profile);

  const applyRule = (rule: LineRule, firstMatch: boolean): void => {
    if (rule.framework !== undefined && rule.framework !== fwForFile) {
      return;
    }
    if (isSecurityAnalyzerFile(absPath) && SELF_ANALYZER_RULE_IDS.has(rule.id)) {
      return;
    }
    let matched = false;
    for (let i = 0; i < lines.length; i += 1) {
      const lineText = lines[i] ?? '';
      if (shouldSkipRuleLine(lineText)) {
        continue;
      }
      rule.regex.lastIndex = 0;
      if (rule.regex.test(lineText)) {
        issues.push(mkIssue(rule, absPath, i + 1, lineText, fwForFile, rule.id.startsWith('aws-') || rule.id === 'private-key' ? 'high' : 'medium'));
        matched = true;
        if (firstMatch) {
          break;
        }
      }
    }
    if (!matched) {
      // no-op; regex line search done.
    }
  };

  // Regex rules — no AST required, no morph serialization.
  for (const rule of SECRET_RULES) {
    applyRule(rule, false);
  }
  for (const rule of GENERIC_LINE_RULES) {
    // Framework-specific rules often only make sense for TS/JS source, which is fine.
    applyRule(rule, rule.id === 'express-no-helmet' || rule.id === 'nest-auth-guard-missing');
  }

  // Special case: express-no-helmet => only emit when `helmet(` is absent.
  const expressIdx = issues.findIndex((i) => i.id.startsWith('security:express-no-helmet:'));
  if (expressIdx >= 0 && /helmet\s*\(/.test(text)) {
    issues.splice(expressIdx, 1);
  }
  // Special case: nest-auth-guard-missing => only if no UseGuards/@Public on class.
  const nestIdx = issues.findIndex((i) => i.id.startsWith('security:nest-auth-guard-missing:'));
  if (nestIdx >= 0 && /@UseGuards\s*\(|@Public\s*\(/.test(text)) {
    issues.splice(nestIdx, 1);
  }

  // Only run AST heuristics for TS/JS; skip SFCs to keep it cheap.
  if (TS_LIKE.test(absPath) || absPath.endsWith('.js') || absPath.endsWith('.jsx') || absPath.endsWith('.mjs') || absPath.endsWith('.cjs')) {
    const astIssues = await runAstSecurityChecks(absPath, text, fwForFile, morph);
    issues.push(...astIssues);
  }

  return issues;
}

async function runAstSecurityChecks(
  absPath: string,
  text: string,
  framework: FrameworkTag,
  morph?: SecurityMorphContext,
): Promise<Issue[]> {
  // AST pass must run serially on the shared morph project to avoid concurrent mutation.
  // Returns a Promise so it can be scheduled through `runExclusive`.
  // eslint-disable-next-line @typescript-eslint/require-await
  const work = async (): Promise<Issue[]> => {
    const issues: Issue[] = [];
    const project = morph
      ? morph.project
      : new TsMorphProject({
          skipAddingFilesFromTsConfig: true,
          compilerOptions: { allowJs: true, checkJs: false, target: ScriptTarget.ES2022 },
        });
    const sf = project.createSourceFile(absPath, text, { overwrite: true });
    try {
      for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        const expr = call.getExpression();
        const calleeText = expr.getText();
        const calleeLeaf = calleeText.includes('.') ? (calleeText.split('.').pop() ?? calleeText) : calleeText;

        if (calleeText.endsWith('.setHeader') || calleeText === 'setHeader') {
          const args = call.getArguments();
          const first = (args[0]?.getText() ?? '').replaceAll(/['"]/g, '');
          const second = args[1]?.getText() ?? '';
          if (first.toLowerCase() === 'x-powered-by') {
            issues.push({
              id: `security:fingerprinting-header:${absPath}:${String(call.getStartLineNumber())}`,
              engine: 'security',
              severity: 'LOW',
              title: 'Custom X-Powered-By header',
              file: absPath,
              line: call.getStartLineNumber(),
              description: 'Advertising stack details can aid attackers.',
              impact: 'Easier targeted attacks; minor info disclosure.',
              fix: 'Remove X-Powered-By; keep security headers minimal and standard.',
              category: 'security',
              framework,
              confidence: 'high',
            });
          }
          if (first.toLowerCase() === 'access-control-allow-origin' && second.includes('*')) {
            issues.push({
              id: `security:cors-wildcard-runtime:${absPath}:${String(call.getStartLineNumber())}`,
              engine: 'security',
              severity: 'MEDIUM',
              title: 'Permissive CORS policy (wildcard)',
              file: absPath,
              line: call.getStartLineNumber(),
              description: 'Wildcard origin can be risky with credentials.',
              impact: 'Cross-origin data access depending on API sensitivity.',
              fix: 'Restrict origins to an allowlist; validate Origin header server-side.',
              category: 'security',
              framework,
              confidence: 'high',
            });
          }
        }

        if (/^(?:exec|execSync|spawn|spawnSync)$/.test(calleeLeaf)) {
          const args = call.getArguments();
          const firstArg = args[0];
          if (firstArg && firstArg.getKind() !== SyntaxKind.StringLiteral) {
            issues.push({
              id: `security:dynamic-shell-command:${absPath}:${String(call.getStartLineNumber())}`,
              engine: 'security',
              severity: 'HIGH',
              title: 'Dynamic child_process invocation',
              file: absPath,
              line: call.getStartLineNumber(),
              description: 'Command arguments are not string literals; possible user-influenced execution.',
              impact: 'Command injection and host compromise.',
              fix: 'Use spawn with argv array, validate inputs, avoid shell: true.',
              category: 'security',
              framework,
              confidence: 'medium',
            });
          }
        }
      }
    } finally {
      // Keep the shared project small; remove this file from the workspace after checks.
      try {
        project.removeSourceFile(sf);
      } catch {
        // ignore; ts-morph sometimes throws on already-removed sources.
      }
    }
    return issues;
  };
  if (morph) {
    return morph.runExclusive(work);
  }
  return work();
}

export interface SecurityEngineOptions {
  readonly fileFilter?: ReadonlySet<string>;
  readonly pathsOverride?: ReadonlySet<string>;
  readonly sourceFiles?: readonly string[];
  readonly morph?: SecurityMorphContext;
  readonly profile?: ProjectProfile;
}

const DEFAULT_PROFILE: ProjectProfile = {
  primaryFramework: 'unknown',
  frameworks: [],
  hasTypescript: false,
  hasJsx: false,
  runtime: 'unknown',
  packageManager: 'unknown',
  entryPoints: [],
};

export async function runSecurityEngine(
  cwd: string,
  concurrency: number,
  options?: SecurityEngineOptions,
): Promise<SecurityScanResult> {
  const files =
    options?.sourceFiles && options.sourceFiles.length > 0
      ? [...options.sourceFiles]
      : await discoverSourceFiles(cwd);
  const normalizedAll = files.map((f) => normalize(f));
  let scoped = normalizedAll;
  if (options?.fileFilter) {
    scoped = scoped.filter((f) => options.fileFilter?.has(f));
  }
  const pathsOverride = options?.pathsOverride;
  if (pathsOverride) {
    scoped = scoped.filter((f) => pathsOverride.has(f));
  }
  const filtered = Boolean(options?.fileFilter || pathsOverride);
  if (filtered && scoped.length === 0) {
    return { issues: [] };
  }
  const list = filtered ? scoped : normalizedAll;
  const morph = options?.morph;
  const profile = options?.profile ?? DEFAULT_PROFILE;
  const results = await runPool(list, concurrency, (file) => analyzeSecurityFile(file, profile, morph));
  return { issues: results.flat() };
}
