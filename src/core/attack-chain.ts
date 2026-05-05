import type { Issue } from './types.js';

/**
 * One-line exploit narrative for decision output (static heuristic, not taint tracing).
 */
export function buildAttackChainNarrative(issue: Issue): string {
  const sink = `${issue.file.replaceAll('\\', '/')}:${String(issue.line)}`;
  const hay = `${issue.title} ${issue.description} ${issue.fix}`.toLowerCase();
  let source = 'Untrusted or partially trusted input';
  if (/sql|query|template|interpolation|prisma\.\$execute/.test(hay)) {
    source = 'Request or string data concatenated into SQL';
  } else if (/jwt|token|verify|alg|auth|session|cookie/.test(hay)) {
    source = 'Token, header, or session material';
  } else if (/exec|spawn|child_process|shell|cmd/.test(hay)) {
    source = 'User-influenced data reaching a process / shell primitive';
  } else if (/xss|innerhtml|dangerouslysetinnerhtml|sanitize|dom/.test(hay)) {
    source = 'User-controlled HTML or DOM sink';
  } else if (/ssrf|fetch|axios|request|http\.get|metadata/.test(hay)) {
    source = 'URL/host/path influenced by external or user input';
  } else if (/secret|key|credential|password|token|pem|private/.test(hay)) {
    source = 'Repository, build artifact, or runtime surface exposing secrets';
  } else if (/random|math\.random|md5|sha1|hash|crypto/.test(hay)) {
    source = 'Weak or predictable cryptographic material';
  } else if (/cors|csrf|helmet|header/.test(hay)) {
    source = 'HTTP client or browser-facing configuration';
  }
  return `${source} → **${issue.engine}** finding → **sink** at \`${sink}\` — _${issue.title}_.`;
}
