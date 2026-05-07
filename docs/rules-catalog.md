# Rules catalog (generated)

_Heuristic extraction from `src/engines/*.ts`. Regenerate: `node scripts/gen-rules-catalog.mjs`._

## api-engine.command.test.ts

_No quoted titles matched — engine may build titles dynamically._

## api-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## arch-policy-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## architecture-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## ast-cache-io.ts

_No quoted titles matched — engine may build titles dynamically._

## ast-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## code-smell-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## compliance-mapper.ts

_No quoted titles matched — engine may build titles dynamically._

## database-engine.ts

| Rule title (sample) |
| --- |
| Raw SQL usage detected |
| Possible SQL interpolation in template literal |
| Possible string-concatenated SQL with user input |
| Prisma $queryRawUnsafe — raw SQL without tagged template |
| SELECT * may pull large result sets |

## database-intel.ts

_No quoted titles matched — engine may build titles dynamically._

## dependency-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## env-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## hotspot-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## inventory-engine.ts

| Rule title (sample) |
| --- |
| Very large source file |
| NestJS controllers without DTO layer |
| No test files detected for a non-trivial service |

## lint-engine.ts

| Rule title (sample) |
| --- |
| ESLint output truncated for this file |
| Prettier: file is not formatted |

## memory-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## migration-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## outdated-engine.ts

_No quoted titles matched — engine may build titles dynamically._

## performance-engine.ts

| Rule title (sample) |
| --- |
| Synchronous filesystem API in hot code |
| Synchronous child_process execution |
| Unbounded JSON.parse on external data |
| Synchronous CPU-heavy crypto on main thread |
| bcrypt sync API used on the main thread |
| Sequential await inside a loop (possible N+1) |
| Nested for-loops with mutable accumulator |
| Catastrophic backtracking regex pattern |
| Very large inline array literal |

## polyglot-engine.ts

| Rule title (sample) |
| --- |
| Potentially dangerous Python API (heuristic) |
| Go external command construction (heuristic) |

## security-engine.ts

| Rule title (sample) |
| --- |
| Possible AWS access key material |
| Possible GitHub personal access token |
| Possible Slack token |
| Possible Stripe secret key |
| Hardcoded JWT token in source |
| PEM private key material in source |
| Possible hardcoded API key assignment |
| Use of eval() |
| Use of new Function() |
| DOM XSS risk: direct HTML injection |
| React dangerouslySetInnerHTML usage |
| Potential command injection via templated shell |
| Possible SQL injection via string interpolation |
| Environment variable concatenation into strings |
| Use of MD5 for security |
| Use of SHA-1 for security |
| Math.random() used for security-sensitive value |
| CORS configured with wildcard origin |
| JWT  |
| JWT verification disabled (verify: false) |
| Outbound request uses unvalidated user URL |
| CSRF protection appears disabled |
| Session cookie missing secure attributes |
| NestJS controller without @UseGuards / @Auth |
| Express app without helmet middleware |
| Next.js rewrite/redirect with wildcard destination |
| Angular bypassSecurityTrustHtml / Url / Script call |
| Custom X-Powered-By header |
| Permissive CORS policy (wildcard) |
| Dynamic child_process invocation |

## self-check-engine.ts

| Rule title (sample) |
| --- |
| Tool has no automated tests — dogfooding gap |

## semver-lite.ts

_No quoted titles matched — engine may build titles dynamically._

## test-engine.ts

_No quoted titles matched — engine may build titles dynamically._

