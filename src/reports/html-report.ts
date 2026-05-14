import { readFile, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

import type { ScanResult } from '../core/types.js';
import { loadCodeOwnersRules, ownerForPath, type CodeOwnersRule } from '../utils/codeowners.js';

function esc(raw: string): string {
  return raw
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function rel(cwd: string, file: string): string {
  return relative(cwd, file).replaceAll('\\', '/');
}

function buildTrustedPayload(result: ScanResult, rules: readonly CodeOwnersRule[]) {
  const trusted = result.trustedIssues ?? [];
  return trusted.slice(0, 800).map((i) => ({
    sev: i.severity,
    eng: i.engine,
    path: rel(result.cwd, i.file),
    line: i.line,
    title: i.title,
    desc: i.description.slice(0, 300),
    fix: i.fix.slice(0, 200),
    conf: i.confidence ?? '',
    ev: (i.codeSnippet ?? i.code ?? '').slice(0, 300),
    own: ownerForPath(rules, rel(result.cwd, i.file)) ?? '',
    comp: (i.compliance ?? []).map((c) => c.framework).join(', '),
  }));
}

export async function writeReportIndexHtml(result: ScanResult, outDir: string): Promise<void> {
  const verdict = result.productionDecision?.verdict ?? '—';
  const gateOk = result.productionDecision?.gateOk;
  const gateLabel = gateOk === true ? 'PASS' : gateOk === false ? 'FAIL' : '—';
  const sc = result.scores;
  const diag = result.scoreDiagnostics;
  const top = result.productionDecision?.topCritical.slice(0, 10) ?? [];
  const rules = await loadCodeOwnersRules(result.cwd);
  const trustedList = result.trustedIssues ?? [];
  const bundleFiles: Record<string, string> = {};
  for (const fn of ['action-plan.md', 'audit-summary.md', 'api.md', 'architecture.md', 'database.md', 'decision.json', 'scores.json', 'governance-suppressions.json']) {
    try {
      bundleFiles[fn] = (await readFile(join(outDir, fn), 'utf8')).slice(0, 60_000);
    } catch {
      /* file not yet generated — intentionally skipped */
    }
  }
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const engMap = new Map<string, number>();
  const fileMap = new Map<string, number>();
  for (const i of trustedList) {
    sevCounts[i.severity] += 1;
    engMap.set(i.engine, (engMap.get(i.engine) ?? 0) + 1);
    const fp = rel(result.cwd, i.file);
    fileMap.set(fp, (fileMap.get(fp) ?? 0) + 1);
  }
  const engBars = [...engMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 14);
  const hotFiles = [...fileMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20);
  const hist = result.baselineHistory ?? [];
  const treemapNodes = hotFiles.map(([fp, n]) => ({
    p: fp,
    n,
    seg: fp.includes('/') ? (fp.split('/')[0] ?? fp) : fp,
  }));
  const payload = {
    trusted: buildTrustedPayload(result, rules),
    trustedTruncated: trustedList.length > 800,
    baseline: result.baselineComparison ?? null,
    baselineHistory: hist,
    severityCounts: sevCounts,
    engineCounts: Object.fromEntries(engBars),
    hotFiles,
    treemap: treemapNodes,
    routes: result.api.routes.slice(0, 200).map((r) => ({
      method: r.method,
      path: r.pathPattern,
      file: rel(result.cwd, r.file),
      line: r.line,
      auth: r.authHeuristic,
    })),
    scores: sc,
    verdict,
    gateLabel,
    mode: result.mode,
    online: result.online ? 'yes' : 'no',
    finishedAt: result.finishedAt,
    totalDurationMs: result.totalDurationMs ?? 0,
    filesAnalyzed: result.ast.filesAnalyzed,
    trustedCount: trustedList.length,
    diagNote: diag?.readinessWeightNotes ?? '',
    diagAxes: diag?.axes ?? null,
    top: top.map((t) => ({ sev: t.severity, file: t.relFile, line: t.line, title: t.title })),
    bundleFiles,
    dbModels: (result.database.intelligence?.models ?? []).slice(0, 30).map((m) => ({
      name: m.name,
      source: m.source,
      fields: m.fields.slice(0, 12).map((f) => ({ n: f.name, t: f.typeToken })),
    })),
    dbRelations: (result.database.intelligence?.relations ?? []).slice(0, 60).map((r) => ({
      from: r.from,
      to: r.to,
      card: r.cardinality,
    })),
    dbHints: (result.database.intelligence?.indexingHints ?? []).slice(0, 12),
    dbIssues: trustedList.filter((i) => i.engine === 'database').slice(0, 30).map((i) => ({
      sev: i.severity,
      title: i.title,
      file: rel(result.cwd, i.file),
      line: i.line,
      desc: i.description.slice(0, 200),
    })),
    archIssues: result.architecture.issues.slice(0, 30).map((i) => ({
      sev: i.severity,
      title: i.title,
      file: rel(result.cwd, i.file),
      line: i.line,
      desc: i.description.slice(0, 200),
    })),
    framework: result.profile?.primaryFramework ?? 'app',
    entityCount: result.inventory.kindCounts['entity'],
    migrationCount: result.inventory.kindCounts['migration'],
  };
  const jsonPayload = JSON.stringify(payload).replaceAll('</script>', '<\\/script>');
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>project-inspector — ${esc(verdict)}</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#12151f;--bg-card:#1c2030;--bg-row:#1f2438;--bg-hover:#252a40;
  --border:#2e3450;--border2:#252a40;
  --text:#e2e4ef;--text-dim:#8891a9;--text-faint:#555e7a;
  --blue:#4f8ef5;--blue-dim:#1d3a6e;--green:#22c55e;--green-dim:#14532d;
  --red:#ef4444;--red-dim:#4b1010;--orange:#f97316;--orange-dim:#5a2d0c;
  --yellow:#eab308;--yellow-dim:#4a3500;--gray:#94a3b8;--gray-dim:#1e2436;
  --radius:4px;--radius-lg:10px;
  --font:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --mono:'SF Mono','Fira Code',Consolas,monospace;
  --shadow:0 2px 8px #0005;
}
html{color-scheme:dark}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.5;min-height:100vh}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
code{font-family:var(--mono);font-size:.82em;background:var(--bg-row);padding:.1em .35em;border-radius:3px}
.topbar{background:var(--bg-card);border-bottom:1px solid var(--border);padding:.55rem 1.25rem;display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;position:sticky;top:0;z-index:10;box-shadow:var(--shadow)}
.topbar-brand{font-weight:700;font-size:.95rem;letter-spacing:-.01em}
.topbar-meta{font-size:.75rem;color:var(--text-dim);margin-left:auto}
.page{padding:1.25rem;max-width:1360px;margin:0 auto}
.pill{display:inline-flex;align-items:center;padding:.2rem .65rem;border-radius:2rem;font-weight:700;font-size:.78rem;letter-spacing:.04em;border:1px solid}
.pill-ready{background:var(--green-dim);color:var(--green);border-color:var(--green)}
.pill-blocked{background:var(--red-dim);color:var(--red);border-color:var(--red)}
.pill-warn{background:var(--yellow-dim);color:var(--yellow);border-color:var(--yellow)}
.score-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(128px,1fr));gap:.65rem;margin:1rem 0}
.score-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:.9rem 1rem 1rem;text-align:center;transition:border-color .15s,transform .1s;cursor:default}
.score-card:hover{border-color:var(--blue);transform:translateY(-1px)}
.sc-val{font-size:2.1rem;font-weight:800;line-height:1;letter-spacing:-.03em}
.sc-lbl{font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text-dim);margin-top:.3rem}
.sc-bar{height:3px;border-radius:2px;background:var(--bg-row);margin-top:.6rem;overflow:hidden}
.sc-bar-fill{height:100%;border-radius:2px;transition:width .5s}
.c-green{color:var(--green)}.c-yellow{color:var(--yellow)}.c-orange{color:var(--orange)}.c-red{color:var(--red)}.c-gray{color:var(--gray)}.c-blue{color:var(--blue)}
.tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:1.1rem;overflow-x:auto;scrollbar-width:none;gap:0}
.tabs::-webkit-scrollbar{display:none}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;padding:.5rem .85rem;font-size:.82rem;font-weight:500;color:var(--text-dim);cursor:pointer;white-space:nowrap;transition:color .15s,border-color .15s;display:flex;align-items:center;gap:.35rem}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--blue);border-bottom-color:var(--blue);font-weight:600}
.tab-badge{background:var(--bg-row);color:var(--text-dim);border-radius:2rem;font-size:.68rem;padding:.05rem .4rem;min-width:1.2rem;text-align:center}
.tab-btn.active .tab-badge{background:var(--blue-dim);color:var(--blue)}
.pane{display:none}.pane.active{display:block}
.sh{font-size:.92rem;font-weight:700;color:var(--text);margin:1.25rem 0 .6rem;display:flex;align-items:center;gap:.45rem}
.sh .ico{font-size:1rem}
.note{font-size:.76rem;color:var(--text-dim);margin:.25rem 0 .7rem}
.stat-row{display:flex;flex-wrap:wrap;gap:.6rem;margin:.65rem 0}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:.6rem .9rem;text-align:center;min-width:88px}
.stat-card .sv{font-size:1.4rem;font-weight:800;line-height:1.1}
.stat-card .sl{font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text-dim);margin-top:.15rem}
.tbl-wrap{overflow-x:auto;border-radius:var(--radius-lg);border:1px solid var(--border);margin:.5rem 0}
table{border-collapse:collapse;width:100%;font-size:.82rem}
thead{position:sticky;top:0;z-index:2}
th{background:var(--bg-row);color:var(--text-dim);font-weight:600;text-align:left;padding:.5rem .65rem;border-bottom:1px solid var(--border);font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;user-select:none}
th.sortable{cursor:pointer}
th.sortable:hover{color:var(--text);background:var(--bg-hover)}
th .sort-icon{display:inline-block;margin-left:.3rem;opacity:.4;font-size:.68rem;vertical-align:middle}
th.sort-asc .sort-icon,th.sort-desc .sort-icon{opacity:1;color:var(--blue)}
td{padding:.4rem .65rem;border-bottom:1px solid var(--border2);vertical-align:top}
tr:last-child td{border-bottom:none}
tbody tr:hover td{background:var(--bg-hover)}
.num{font-variant-numeric:tabular-nums;font-weight:600}
.ev{max-width:260px;white-space:pre-wrap;word-break:break-all;color:var(--text-dim);font-size:.75rem}
.hidden{display:none!important}
.toolbar{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:.65rem 0}
.search-wrap{position:relative;flex:1;min-width:200px}
.search-wrap .ico-search{position:absolute;left:.6rem;top:50%;transform:translateY(-50%);color:var(--text-dim);font-size:.85rem;pointer-events:none}
.toolbar input[type="search"]{width:100%;background:var(--bg-card);border:1px solid var(--border);color:var(--text);padding:.38rem .55rem .38rem 2rem;border-radius:var(--radius);font-size:.82rem;outline:none}
.toolbar input[type="search"]:focus{border-color:var(--blue)}
.toolbar select{background:var(--bg-card);border:1px solid var(--border);color:var(--text);padding:.38rem .55rem;border-radius:var(--radius);font-size:.82rem;outline:none;cursor:pointer}
.toolbar select:focus{border-color:var(--blue)}
.toolbar select option{background:var(--bg-card)}
.result-count{font-size:.76rem;color:var(--text-dim);padding:.3rem .1rem;white-space:nowrap}
.sev{display:inline-block;padding:.1rem .45rem;border-radius:3px;font-size:.68rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.sev-CRITICAL{background:var(--red-dim);color:var(--red);border:1px solid #5a1515}
.sev-HIGH{background:var(--orange-dim);color:var(--orange);border:1px solid #7a3a10}
.sev-MEDIUM{background:var(--yellow-dim);color:var(--yellow);border:1px solid #6a4d00}
.sev-LOW{background:var(--gray-dim);color:var(--gray);border:1px solid #2a3048}
.donut-wrap{display:flex;align-items:center;gap:1.25rem;flex-wrap:wrap;margin:.65rem 0}
.donut{width:90px;height:90px;border-radius:50%;flex-shrink:0;position:relative}
.donut-hole{position:absolute;inset:19px;background:var(--bg-card);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.82rem;font-weight:700;color:var(--text)}
.legend{display:flex;flex-direction:column;gap:.35rem;font-size:.8rem}
.legend-row{display:flex;align-items:center;gap:.5rem}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.hbar{display:grid;grid-template-columns:9rem 1fr 3rem;gap:.4rem;align-items:center;margin-bottom:.3rem;font-size:.78rem}
.hb-track{background:var(--bg-row);border-radius:2px;height:7px;overflow:hidden}
.hb-fill{height:100%;border-radius:2px;background:var(--blue)}
.hb-num{text-align:right;color:var(--text-dim)}
.gauge-wrap{display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap;margin:.65rem 0}
.gauge{position:relative;width:110px;height:58px;overflow:hidden}
.gauge svg{position:absolute;top:0;left:0}
.spark{color:var(--blue);margin:.3rem 0}
.hs-list{margin:.5rem 0;display:flex;flex-direction:column;gap:2px}
.hs-row{display:grid;grid-template-columns:2.4rem 1fr 9rem 2.8rem;align-items:center;gap:.6rem;padding:.44rem .75rem;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);cursor:pointer;transition:background .12s,border-color .12s}
.hs-row:hover{background:var(--bg-hover);border-color:var(--blue)}
.hs-badge{display:inline-flex;align-items:center;justify-content:center;height:1.55rem;width:100%;border-radius:3px;font-size:.6rem;font-weight:800;letter-spacing:.02em;flex-shrink:0}
.hs-ts{background:#0c2a3f;color:#4fc3f7}.hs-js{background:#382d00;color:#ffd740}
.hs-json{background:#0d2a1a;color:#4caf50}.hs-css{background:#1a0d3d;color:#9c7eff}
.hs-env{background:#1e1e24;color:#90a4ae}.hs-other{background:#1e1226;color:#ce93d8}
.hs-name{font-size:.82rem;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hs-dir{font-size:.7rem;color:var(--text-faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:.05rem}
.hs-bar-wrap{background:var(--bg-row);border-radius:2px;height:5px;overflow:hidden}
.hs-bar{height:100%;border-radius:2px;transition:width .4s}
.hs-cnt{text-align:right;font-size:.82rem;font-weight:700;font-variant-numeric:tabular-nums;color:var(--text)}
.delta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:.6rem;margin:.5rem 0}
.delta-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:.7rem;text-align:center}
.delta-card .dv{font-size:1.5rem;font-weight:800}
.delta-card .dl{font-size:.68rem;color:var(--text-dim);margin-top:.15rem;text-transform:uppercase;letter-spacing:.05em}
.method{display:inline-block;padding:.1rem .45rem;border-radius:3px;font-size:.68rem;font-weight:700;font-family:var(--mono);text-transform:uppercase}
.m-GET{background:#0d3520;color:#22c55e}.m-POST{background:#1a2a42;color:#4f8ef5}
.m-PUT,.m-PATCH{background:#3d2000;color:#f97316}.m-DELETE{background:#3d0f0f;color:#ef4444}
.m-ALL,.m-USE{background:#2a2000;color:#eab308}
.auth-open{color:var(--red);font-weight:700;font-size:.72rem}
.auth-ok{color:var(--green);font-size:.72rem}
.auth-unk{color:var(--text-dim);font-size:.72rem}
.modal-back{position:fixed;inset:0;background:#000c;display:none;z-index:100;align-items:center;justify-content:center;padding:1rem}
.modal-back.open{display:flex}
.modal{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);max-width:820px;width:100%;max-height:88vh;display:flex;flex-direction:column;box-shadow:0 8px 32px #0008}
.modal-hd{padding:.7rem 1rem;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;gap:.5rem}
.modal-hd h3{font-size:.88rem;font-weight:700;line-height:1.4}
.modal-x{background:none;border:none;color:var(--text-dim);font-size:1rem;cursor:pointer;padding:.2rem .45rem;border-radius:var(--radius);line-height:1;flex-shrink:0}
.modal-x:hover{background:var(--bg-hover);color:var(--text)}
.modal-body{padding:.8rem 1rem;overflow-y:auto;font-size:.83rem}
.mfield{margin-bottom:.65rem}
.mfield-lbl{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text-dim);margin-bottom:.2rem}
.mfield-val{color:var(--text);word-break:break-word}
.mfield pre{background:var(--bg-row);border:1px solid var(--border);border-radius:var(--radius);padding:.55rem .7rem;font-size:.74rem;white-space:pre-wrap;word-break:break-all;margin-top:.2rem}
.links-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:.5rem;margin:.65rem 0}
.link-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:.55rem .8rem;display:flex;align-items:center;gap:.45rem;font-size:.82rem;color:var(--text);transition:border-color .15s,background .15s}
.link-card:hover{border-color:var(--blue);background:var(--bg-hover);text-decoration:none}
.bnd-row{display:flex;align-items:center;gap:.55rem;background:var(--bg-row);border:1px solid var(--border);border-radius:var(--radius-lg);padding:.45rem .75rem;margin-bottom:.35rem}
.bnd-icon{font-size:1rem;flex-shrink:0}
.bnd-name{flex:1;font-size:.83rem;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bnd-badge{font-size:.67rem;padding:.08rem .32rem;border-radius:var(--radius);border:1px solid var(--border);color:var(--text-dim);flex-shrink:0}
.bnd-btn{font-size:.74rem;padding:.22rem .58rem;background:var(--blue);color:#fff;border:none;border-radius:var(--radius);cursor:pointer;flex-shrink:0}
.bnd-btn:hover{filter:brightness(1.15)}
.bnd-open{background:none;border:1px solid var(--border);color:var(--text-dim)}
.bnd-open:hover{border-color:var(--blue);color:var(--blue)}
.pv-overlay{position:fixed;inset:0;z-index:200;background:var(--bg);display:none;flex-direction:column;overflow:hidden}
.pv-overlay.open{display:flex}
.pv-ov-hd{display:flex;align-items:center;gap:.55rem;padding:.55rem 1.1rem;border-bottom:1px solid var(--border);background:var(--bg-card);flex-shrink:0}
.pv-ov-icon{font-size:1.1rem;flex-shrink:0}
.pv-ov-title{flex:1;font-size:.95rem;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pv-ov-close{background:none;border:1px solid var(--border);color:var(--text-dim);font-size:.78rem;cursor:pointer;padding:.22rem .65rem;border-radius:var(--radius);flex-shrink:0;display:flex;align-items:center;gap:.3rem}
.pv-ov-close:hover{background:var(--bg-hover);color:var(--text);border-color:var(--text-dim)}
.pv-ov-body{flex:1;overflow:auto;padding:1.25rem 2rem;display:flex;flex-direction:column;min-height:0}
.pv-tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:.6rem}
.pv-tab{font-size:.75rem;padding:.28rem .7rem;cursor:pointer;border-bottom:2px solid transparent;color:var(--text-dim);background:none;border-top:none;border-left:none;border-right:none}
.pv-tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.md-body{font-size:.81rem;line-height:1.65;color:var(--text);overflow-y:auto;flex:1;min-height:0}
.md-body h1,.md-body h2{font-size:.98rem;font-weight:700;margin:.9rem 0 .3rem;color:var(--text)}
.md-body h3,.md-body h4{font-size:.86rem;font-weight:600;margin:.7rem 0 .22rem;color:var(--text)}
.md-body p{margin:.25rem 0 .5rem}
.md-body ul,.md-body ol{margin:.2rem 0 .45rem;padding-left:1.35rem}
.md-body li{margin:.12rem 0}
.md-body code{background:var(--bg-row);border:1px solid var(--border);border-radius:3px;padding:.04rem .28rem;font-family:var(--mono);font-size:.77rem}
.md-body pre{background:var(--bg-row);border:1px solid var(--border);border-radius:var(--radius);padding:.5rem .65rem;overflow-x:auto;margin:.35rem 0}
.md-body pre code{background:none;border:none;padding:0;font-size:.75rem}
.md-body table{border-collapse:collapse;width:100%;font-size:.78rem;margin:.45rem 0}
.md-body th{background:var(--bg-row);border:1px solid var(--border);padding:.28rem .5rem;text-align:left;font-weight:600}
.md-body td{border:1px solid var(--border);padding:.25rem .5rem}
.md-body blockquote{border-left:3px solid var(--blue);margin:.35rem 0;padding:.28rem .65rem;color:var(--text-dim);background:var(--bg-row)}
.md-body strong{font-weight:700;color:var(--text)}
.md-body hr{border:none;border-top:1px solid var(--border);margin:.55rem 0}
.json-body{font-family:var(--mono);font-size:.76rem;line-height:1.6;overflow-y:auto;flex:1;min-height:0;white-space:pre-wrap;word-break:break-all}
.json-body .jk{color:#7dd3fc}.json-body .js{color:#86efac}.json-body .jn{color:#f9a8d4}.json-body .jb{color:#fbbf24}
.vis-wrap{display:flex;flex-direction:column;gap:.75rem;overflow-y:auto;flex:1;min-height:0}
.vis-sec{background:var(--bg-row);border:1px solid var(--border);border-radius:var(--radius-lg);padding:.6rem .75rem}
.vis-sec-t{font-size:.74rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text-dim);margin-bottom:.5rem}
.pipe-flow{display:flex;align-items:center;flex-wrap:wrap;gap:0;font-size:.77rem}
.pipe-node{background:var(--bg-card);border:1px solid var(--blue);border-radius:var(--radius-lg);padding:.3rem .6rem;color:var(--text);font-weight:600;white-space:nowrap}
.pipe-arrow{color:var(--text-dim);padding:0 .28rem}
.pipe-note{font-size:.71rem;color:var(--text-dim);margin-top:.4rem}
.model-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(145px,1fr));gap:.45rem}
.model-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:.45rem .6rem;font-size:.75rem}
.model-card-t{font-weight:700;color:var(--text);margin-bottom:.25rem;font-size:.78rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.model-card-s{font-size:.65rem;color:var(--text-dim);margin-bottom:.28rem;text-transform:capitalize}
.model-field{display:flex;justify-content:space-between;gap:.28rem;font-size:.7rem;padding:.08rem 0;border-bottom:1px solid var(--border)}
.model-field:last-child{border-bottom:none}
.mfn{color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.mft{color:var(--text-dim);font-family:var(--mono);flex-shrink:0;font-size:.67rem}
.model-more{font-size:.68rem;color:var(--text-dim);margin-top:.22rem}
.rel-list{display:flex;flex-direction:column;gap:.22rem}
.rel-row{display:flex;align-items:center;gap:.38rem;font-size:.75rem;padding:.2rem .38rem;background:var(--bg-card);border-radius:var(--radius)}
.rel-from{color:var(--blue);font-family:var(--mono);font-weight:600}
.rel-card{font-size:.68rem;background:var(--bg-row);border:1px solid var(--border);border-radius:3px;padding:.04rem .25rem;color:var(--text-dim);flex-shrink:0}
.rel-to{color:var(--text);font-family:var(--mono)}
.hint-list{display:flex;flex-direction:column;gap:.22rem}
.hint-row{display:flex;align-items:flex-start;gap:.38rem;font-size:.75rem;padding:.2rem .38rem;background:var(--bg-card);border-radius:var(--radius)}
.hint-dot{color:#fbbf24;flex-shrink:0}
.vis-stats{display:flex;gap:1.1rem;flex-wrap:wrap}
.vis-stat-n{font-size:1.35rem;font-weight:700;color:var(--blue);line-height:1}
.vis-stat-l{font-size:.68rem;color:var(--text-dim);margin-top:.12rem}
.vis-issue-list{display:flex;flex-direction:column;gap:.28rem}
.vis-issue{display:flex;align-items:flex-start;gap:.45rem;padding:.32rem .48rem;background:var(--bg-card);border-radius:var(--radius);border-left:3px solid var(--border)}
.vis-issue.sev-CRITICAL{border-left-color:#ef4444}.vis-issue.sev-HIGH{border-left-color:#f97316}.vis-issue.sev-MEDIUM{border-left-color:#eab308}.vis-issue.sev-LOW{border-left-color:#22c55e}
.vis-issue-body{flex:1;min-width:0}
.vis-issue-t{font-size:.78rem;font-weight:600;color:var(--text);margin-bottom:.12rem}
.vis-issue-l{font-size:.7rem;color:var(--text-dim);font-family:var(--mono)}
.vis-issue-d{font-size:.71rem;color:var(--text-dim);margin-top:.12rem;line-height:1.5}
.pv-panel{display:flex;flex-direction:column;flex:1;min-height:0;overflow:hidden}
</style>
</head>
<body>
<header class="topbar">
  <span class="topbar-brand">project-inspector</span>
  <span id="verdictPill"></span>
  <span class="topbar-meta" id="topMeta"></span>
</header>
<div class="page">
  <div class="score-grid" id="scoreGrid"></div>
  <nav class="tabs" id="tabBar" role="tablist"></nav>
  <div id="paneOverview"  class="pane active"></div>
  <div id="paneFindings" class="pane"></div>
  <div id="paneSecurity" class="pane"></div>
  <div id="panePerf"     class="pane"></div>
  <div id="paneDeps"     class="pane"></div>
  <div id="paneRoutes"   class="pane"></div>
  <div id="paneTests"    class="pane"></div>
  <div id="paneArch"     class="pane"></div>
  <div id="paneBundle"   class="pane"></div>
</div>
<div class="modal-back" id="modalBack" role="dialog" aria-modal="true">
  <div class="modal">
    <div class="modal-hd">
      <h3 id="modalTitle">Finding detail</h3>
      <button class="modal-x" id="modalClose" aria-label="Close">&#x2715;</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>
<div class="pv-overlay" id="pvOverlay" role="dialog" aria-modal="true">
  <div class="pv-ov-hd">
    <span class="pv-ov-icon" id="pvOvIcon"></span>
    <span class="pv-ov-title" id="pvOvTitle"></span>
    <button class="pv-ov-close" id="pvOvClose" aria-label="Close preview">&#x2715; Close</button>
  </div>
  <div class="pv-ov-body" id="pvOvBody"></div>
</div>
<script type="application/json" id="pi-data">${jsonPayload}</script>
<script>
(function(){
'use strict';
var D=JSON.parse(document.getElementById('pi-data').textContent||'{}');
var trusted=D.trusted||[];
var routes=D.routes||[];
var sc=D.scores||{};
var sevC=D.severityCounts||{};
var engC=D.engineCounts||{};
var hotFiles=D.hotFiles||[];
var hist=D.baselineHistory||[];
var base=D.baseline;
var top=D.top||[];
var diag=D.diagAxes||null;
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function el(tag,cls,html){var e=document.createElement(tag);if(cls)e.className=cls;if(html!=null)e.innerHTML=html;return e;}
function scoreColor(v){return v>=80?'c-green':v>=55?'c-yellow':v>=30?'c-orange':'c-red';}
function barColor(v){return v>=80?'#22c55e':v>=55?'#eab308':v>=30?'#f97316':'#ef4444';}
function sevBadge(s){return '<span class="sev sev-'+esc(s)+'">'+esc(s)+'</span>';}
function methodBadge(m){
  var u=(m||'ALL').toUpperCase();
  var cls={GET:'m-GET',POST:'m-POST',PUT:'m-PUT',PATCH:'m-PATCH',DELETE:'m-DELETE'}[u]||'m-ALL';
  return '<span class="method '+cls+'">'+esc(u)+'</span>';
}
function authBadge(a){
  if(a==='likely-open')return '<span class="auth-open">&#x26A0; Open</span>';
  if(a==='likely-protected')return '<span class="auth-ok">&#x2713; Protected</span>';
  return '<span class="auth-unk">?</span>';
}
var vdict=D.verdict||'—';
var pcls=vdict==='READY'?'pill pill-ready':vdict==='BLOCKED'?'pill pill-blocked':'pill pill-warn';
document.getElementById('verdictPill').innerHTML='<span class="'+pcls+'">'+esc(vdict)+'</span>';
document.getElementById('topMeta').textContent='Mode: '+D.mode+' \xb7 Online: '+D.online+' \xb7 '+D.filesAnalyzed+' files \xb7 '+(D.totalDurationMs?(D.totalDurationMs/1000).toFixed(1)+'s':'')+' \xb7 '+D.finishedAt;
[
  {k:'productionReadiness',l:'Readiness'},
  {k:'security',l:'Security'},
  {k:'performance',l:'Performance'},
  {k:'codeQuality',l:'Code Quality'},
  {k:'compliance',l:'Compliance'},
  {k:'tests',l:'Tests'},
].forEach(function(ax){
  var v=sc[ax.k]||0;
  var card=el('div','score-card');
  card.innerHTML='<div class="sc-val '+scoreColor(v)+'">'+v+'</div>'+
    '<div class="sc-lbl">'+esc(ax.l)+'</div>'+
    '<div class="sc-bar"><div class="sc-bar-fill" style="width:'+v+'%;background:'+barColor(v)+'"></div></div>';
  document.getElementById('scoreGrid').appendChild(card);
});
var TABS=[
  {id:'paneOverview',l:'Overview',ico:'&#x1F4CA;'},
  {id:'paneFindings',l:'Findings',ico:'&#x1F50D;',cnt:D.trustedCount},
  {id:'paneSecurity',l:'Security',ico:'&#x1F512;',cnt:(sevC.CRITICAL||0)+(sevC.HIGH||0)},
  {id:'panePerf',l:'Performance',ico:'&#x26A1;'},
  {id:'paneDeps',l:'Dependencies',ico:'&#x1F4E6;'},
  {id:'paneRoutes',l:'API Routes',ico:'&#x1F310;',cnt:routes.length},
  {id:'paneTests',l:'Tests',ico:'&#x1F9EA;'},
  {id:'paneArch',l:'Architecture',ico:'&#x1F3D7;'},
  {id:'paneBundle',l:'Bundle',ico:'&#x1F4C1;'},
];
var tabBar=document.getElementById('tabBar');
TABS.forEach(function(t){
  var b=el('button','tab-btn');
  b.dataset.pane=t.id;
  b.innerHTML=t.ico+' '+esc(t.l)+(t.cnt?'<span class="tab-badge">'+t.cnt+'</span>':'');
  b.addEventListener('click',function(){openTab(t.id);});
  tabBar.appendChild(b);
});
var paneBuilt={};
var builders={
  paneOverview:buildOverview,paneFindings:buildFindings,paneSecurity:buildSecurity,
  panePerf:buildPerf,paneDeps:buildDeps,paneRoutes:buildRoutes,
  paneTests:buildTests,paneArch:buildArch,paneBundle:buildBundle,
};
function openTab(id){
  document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.toggle('active',b.dataset.pane===id);});
  document.querySelectorAll('.pane').forEach(function(p){p.classList.toggle('active',p.id===id);});
  if(!paneBuilt[id]){builders[id]&&builders[id]();paneBuilt[id]=true;}
}
document.querySelectorAll('.tab-btn')[0].classList.add('active');
paneBuilt['paneOverview']=false;
openTab('paneOverview');
function makeSortable(tableId){
  var tbl=document.getElementById(tableId);if(!tbl)return;
  var sortCol=-1,sortDir=1;
  tbl.querySelectorAll('th.sortable').forEach(function(th,i){
    th.innerHTML=th.innerHTML+'<span class="sort-icon">&#x21C5;</span>';
    th.addEventListener('click',function(){
      if(sortCol===i){sortDir*=-1;}else{sortCol=i;sortDir=-1;}
      tbl.querySelectorAll('th.sortable').forEach(function(h){h.classList.remove('sort-asc','sort-desc');});
      th.classList.add(sortDir===1?'sort-asc':'sort-desc');
      th.querySelector('.sort-icon').textContent=sortDir===1?'&#x2191;':'&#x2193;';
      var tbody=tbl.querySelector('tbody');
      var rows=Array.from(tbody.querySelectorAll('tr'));
      rows.sort(function(a,b){
        var av=(a.cells[i]||{}).textContent||'';
        var bv=(b.cells[i]||{}).textContent||'';
        var an=parseFloat(av),bn=parseFloat(bv);
        if(!isNaN(an)&&!isNaN(bn))return(an-bn)*sortDir;
        return av.localeCompare(bv)*sortDir;
      });
      rows.forEach(function(r){tbody.appendChild(r);});
    });
  });
}
function buildOverview(){
  var pane=document.getElementById('paneOverview');
  var r=sc.productionReadiness||0;
  var gcolor=r>=80?'#22c55e':r>=55?'#eab308':r>=30?'#f97316':'#ef4444';
  var angle=Math.min(r/100,1)*180;
  function arcPt(deg){var a=(180+deg)*Math.PI/180;return[55+42*Math.cos(a),55+42*Math.sin(a)];}
  var p0=arcPt(0),p1=arcPt(angle),lg=angle>180?1:0;
  var gaugeSvg='<svg width="110" height="58" viewBox="0 0 110 58" aria-label="readiness '+r+'/100">'+
    '<path d="M13,55 A42,42 0 0,1 97,55" fill="none" stroke="#252a40" stroke-width="10" stroke-linecap="round"/>'+
    (angle>0?'<path d="M'+p0[0].toFixed(1)+','+p0[1].toFixed(1)+' A42,42 0 '+lg+',1 '+p1[0].toFixed(1)+','+p1[1].toFixed(1)+'" fill="none" stroke="'+gcolor+'" stroke-width="10" stroke-linecap="round"/>':'')+
    '<text x="55" y="53" text-anchor="middle" font-size="19" font-weight="800" fill="'+gcolor+'">'+r+'</text>'+
    '</svg>';
  var gateColor=D.gateLabel==='PASS'?'#22c55e':D.gateLabel==='FAIL'?'#ef4444':'#94a3b8';
  var html='<div class="sh"><span class="ico">&#x1F4CA;</span>Production Readiness</div>';
  html+='<div class="gauge-wrap"><div><div class="gauge">'+gaugeSvg+'</div><div class="note" style="text-align:center">Readiness</div></div>';
  html+='<div class="stat-row">';
  html+='<div class="stat-card"><div class="sv" style="color:'+gateColor+'">'+esc(D.gateLabel)+'</div><div class="sl">Gate</div></div>';
  html+='<div class="stat-card"><div class="sv c-blue">'+esc(String(D.trustedCount))+'</div><div class="sl">Findings</div></div>';
  html+='<div class="stat-card"><div class="sv c-red">'+esc(String(sevC.CRITICAL||0))+'</div><div class="sl">Critical</div></div>';
  html+='<div class="stat-card"><div class="sv c-orange">'+esc(String(sevC.HIGH||0))+'</div><div class="sl">High</div></div>';
  html+='</div></div>';
  var total=(sevC.CRITICAL||0)+(sevC.HIGH||0)+(sevC.MEDIUM||0)+(sevC.LOW||0);
  html+='<div class="sh"><span class="ico">&#x1F3AF;</span>Severity breakdown</div>';
  if(total>0){
    var dcols=['#ef4444','#f97316','#eab308','#94a3b8'];
    var dvals=[sevC.CRITICAL||0,sevC.HIGH||0,sevC.MEDIUM||0,sevC.LOW||0];
    var dlbls=['CRITICAL','HIGH','MEDIUM','LOW'];
    var cum=0;
    var slices=dvals.map(function(v,i){var s=cum;cum+=v/total*360;return{s:s,e:cum,c:dcols[i]};});
    var dcss=slices.map(function(x){return x.c+' '+x.s.toFixed(1)+'deg '+x.e.toFixed(1)+'deg';}).join(',');
    html+='<div class="donut-wrap"><div class="donut" style="background:conic-gradient('+dcss+')"><div class="donut-hole">'+total+'</div></div>';
    html+='<div class="legend">';
    dlbls.forEach(function(l,i){html+='<div class="legend-row"><div class="legend-dot" style="background:'+dcols[i]+'"></div><span>'+l+': <strong>'+dvals[i]+'</strong></span></div>';});
    html+='</div></div>';
  }else{html+='<p class="note">No trusted findings.</p>';}
  html+='<div class="sh"><span class="ico">&#x2699;</span>Findings by engine</div>';
  var ee=Object.entries(engC).sort(function(a,b){return b[1]-a[1];});
  if(ee.length){
    var emax=ee[0][1]||1;
    ee.forEach(function(e){html+='<div class="hbar"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-dim)">'+esc(e[0])+'</span><div class="hb-track"><div class="hb-fill" style="width:'+Math.round(e[1]/emax*100)+'%"></div></div><span class="hb-num">'+e[1]+'</span></div>';});
  }
  if(diag){
    html+='<div class="sh"><span class="ico">&#x1F52C;</span>Score details</div>';
    html+='<div class="tbl-wrap"><table id="tbl-diag"><thead><tr><th class="sortable">Axis</th><th class="sortable">Score</th><th class="sortable">Hits</th><th class="sortable">Engines</th></tr></thead><tbody>';
    [['Security',sc.security,diag.security],['Performance',sc.performance,diag.performance],
     ['Code Quality',sc.codeQuality,diag.codeQuality],['Compliance',sc.compliance,diag.compliance],['Tests',sc.tests,diag.tests]
    ].forEach(function(row){
      html+='<tr><td>'+esc(row[0])+'</td><td class="num '+scoreColor(row[1])+'">'+row[1]+'</td>'+
        '<td class="num">'+(row[2]?row[2].contributingTrustedIssueCount:'&#x2014;')+'</td>'+
        '<td style="color:var(--text-dim);font-size:.78rem">'+(row[2]&&row[2].enginesRepresented.length?esc(row[2].enginesRepresented.join(', ')):'&#x2014;')+'</td></tr>';
    });
    html+='</tbody></table></div>';
    if(D.diagNote)html+='<p class="note">'+esc(D.diagNote)+'</p>';
  }
  if(hotFiles.length){
    html+='<div class="sh"><span class="ico">&#x1F525;</span>Hotspot files</div><div class="hs-list">';
    var hfmax=hotFiles[0][1]||1;
    hotFiles.forEach(function(f){
      var fp=f[0],cnt=f[1];
      var parts=fp.replace(/\\\\/g,'/').split('/');
      var fname=parts.pop()||fp;
      var fdir=parts.join('/');
      var dot=fname.lastIndexOf('.');
      var ext=(dot>0?fname.slice(dot+1):'').toLowerCase();
      var badge,bcls;
      if(ext==='ts'||ext==='tsx'){badge='TS';bcls='hs-ts';}
      else if(ext==='js'||ext==='jsx'||ext==='mjs'){badge='JS';bcls='hs-js';}
      else if(ext==='json'){badge='{}';bcls='hs-json';}
      else if(ext==='css'||ext==='scss'||ext==='sass'||ext==='less'){badge='CSS';bcls='hs-css';}
      else if(fname.startsWith('.env')||ext==='env'){badge='ENV';bcls='hs-env';}
      else{badge='&#xB7;&#xB7;&#xB7;';bcls='hs-other';}
      var pct=Math.round(cnt/hfmax*100);
      var bc=pct===100?'#ef4444':pct>=60?'#f97316':pct>=30?'#eab308':'#4f8ef5';
      html+='<div class="hs-row" data-path="'+esc(fp)+'">'+
        '<span class="hs-badge '+bcls+'">'+badge+'</span>'+
        '<div style="min-width:0"><div class="hs-name">'+esc(fname)+'</div>'+(fdir?'<div class="hs-dir">'+esc(fdir)+'</div>':'')+'</div>'+
        '<div class="hs-bar-wrap"><div class="hs-bar" style="width:'+pct+'%;background:'+bc+'"></div></div>'+
        '<span class="hs-cnt">'+cnt+'</span></div>';
    });
    html+='</div>';
  }
  if(hist.length>=2){
    var ys=hist.map(function(h){return h.fingerprintCount||0;});
    var miny=Math.min.apply(null,ys),maxy=Math.max.apply(null,ys);
    var W=280,H=52,pad=6;
    var pts=ys.map(function(y,i){
      var x=pad+(i/Math.max(ys.length-1,1))*(W-pad*2);
      var yn=maxy===miny?0.5:(y-miny)/(maxy-miny);
      return x.toFixed(1)+','+(pad+(1-yn)*(H-pad*2)).toFixed(1);
    }).join(' ');
    html+='<div class="sh"><span class="ico">&#x1F4C8;</span>Baseline fingerprint trend</div>';
    html+='<div class="spark"><svg width="'+W+'" height="'+H+'" viewBox="0 0 '+W+' '+H+'"><polyline fill="none" stroke="currentColor" stroke-width="2" points="'+pts+'"/></svg></div>';
  }
  html+='<div class="sh"><span class="ico">&#x1F4D0;</span>Baseline delta</div>';
  if(base){
    html+='<div class="delta-grid">'+
      '<div class="delta-card"><div class="dv c-red">'+base.newCount+'</div><div class="dl">New</div></div>'+
      '<div class="delta-card"><div class="dv c-green">'+base.resolvedCount+'</div><div class="dl">Resolved</div></div>'+
      '<div class="delta-card"><div class="dv c-gray">'+base.unchangedCount+'</div><div class="dl">Unchanged</div></div>'+
      '</div><p class="note">Compared to baseline saved <code>'+esc(base.baselineSavedAt)+'</code>.</p>';
  }else{
    html+='<p class="note">No baseline yet. Run <code>project-inspector scan --save-baseline</code> to create one.</p>';
  }
  pane.innerHTML=html;
  makeSortable('tbl-diag');
  pane.querySelectorAll('.hs-row').forEach(function(row){
    row.addEventListener('click',function(){
      var fp=row.dataset.path||'';
      openTab('paneFindings');
      setTimeout(function(){var q=document.getElementById('fi-q');if(q){q.value=fp;filterFindings();}},60);
    });
  });
}
function buildFindings(){
  var pane=document.getElementById('paneFindings');
  var engs=[...new Set(trusted.map(function(t){return t.eng;}))].sort();
  var html='<div class="sh"><span class="ico">&#x1F50D;</span>All findings <span class="tab-badge" id="fi-count">'+trusted.length+'</span></div>';
  if(D.trustedTruncated)html+='<p class="note">Showing first 800 rows.</p>';
  html+='<div class="toolbar">'+
    '<div class="search-wrap"><span class="ico-search">&#x1F50D;</span><input type="search" id="fi-q" placeholder="Search path, title, engine, owner, compliance…" autocomplete="off"/></div>'+
    '<select id="fi-sev"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>'+
    '<select id="fi-eng"><option value="">All engines</option></select>'+
    '<select id="fi-conf"><option value="">All confidence</option><option>high</option><option>medium</option><option>low</option></select>'+
    '<span class="result-count" id="fi-count2"></span>'+
  '</div>'+
  '<div class="tbl-wrap"><table id="fi-tbl">'+
  '<thead><tr>'+
    '<th class="sortable">Severity</th>'+
    '<th class="sortable">Engine</th>'+
    '<th class="sortable">Conf</th>'+
    '<th class="sortable">Owner</th>'+
    '<th class="sortable">Location</th>'+
    '<th class="sortable">Title</th>'+
    '<th class="sortable">Compliance</th>'+
  '</tr></thead><tbody id="fi-tbody"></tbody></table></div>';
  pane.innerHTML=html;
  var engSel=pane.querySelector('#fi-eng');
  engs.forEach(function(e){var o=document.createElement('option');o.value=e;o.textContent=e;engSel.appendChild(o);});
  var tbody=pane.querySelector('#fi-tbody');
  trusted.forEach(function(t,idx){
    var tr=document.createElement('tr');
    var sevOrder={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3}[t.sev]||9;
    tr.dataset.sev=t.sev;tr.dataset.eng=t.eng;tr.dataset.conf=t.conf||'';
    tr.dataset.q=(t.sev+' '+t.eng+' '+t.path+' '+t.title+' '+t.conf+' '+t.own+' '+t.comp).toLowerCase();
    tr.dataset.sevord=String(sevOrder);
    tr.innerHTML=
      '<td>'+sevBadge(t.sev)+'</td>'+
      '<td style="font-family:var(--mono);font-size:.78rem">'+esc(t.eng)+'</td>'+
      '<td style="color:var(--text-dim);font-size:.76rem">'+esc(t.conf||'—')+'</td>'+
      '<td style="color:var(--text-dim)">'+esc(t.own||'—')+'</td>'+
      '<td style="font-family:var(--mono);font-size:.76rem"><code>'+esc(t.path)+':'+t.line+'</code></td>'+
      '<td style="max-width:280px;word-break:break-word"><a href="#" class="fi-detail" data-idx="'+idx+'">'+esc(t.title)+'</a></td>'+
      '<td style="color:var(--text-dim);font-size:.72rem">'+esc(t.comp||'—')+'</td>';
    tbody.appendChild(tr);
  });
  pane.querySelectorAll('.fi-detail').forEach(function(a){
    a.addEventListener('click',function(e){e.preventDefault();showModal(trusted[+a.dataset.idx]);});
  });
  pane.querySelector('#fi-sev').addEventListener('change',filterFindings);
  pane.querySelector('#fi-eng').addEventListener('change',filterFindings);
  pane.querySelector('#fi-conf').addEventListener('change',filterFindings);
  pane.querySelector('#fi-q').addEventListener('input',filterFindings);
  makeSortable('fi-tbl');
  updateFiCount();
}
function filterFindings(){
  var pane=document.getElementById('paneFindings');if(!pane)return;
  var fSev=(pane.querySelector('#fi-sev')||{}).value||'';
  var fEng=(pane.querySelector('#fi-eng')||{}).value||'';
  var fConf=(pane.querySelector('#fi-conf')||{}).value||'';
  var needle=((pane.querySelector('#fi-q')||{}).value||'').toLowerCase().trim();
  var count=0;
  pane.querySelectorAll('#fi-tbody tr').forEach(function(tr){
    var ok=true;
    if(fSev&&tr.dataset.sev!==fSev)ok=false;
    if(ok&&fEng&&tr.dataset.eng!==fEng)ok=false;
    if(ok&&fConf&&tr.dataset.conf!==fConf)ok=false;
    if(ok&&needle&&tr.dataset.q.indexOf(needle)===-1)ok=false;
    tr.classList.toggle('hidden',!ok);
    if(ok)count++;
  });
  var c2=document.getElementById('fi-count2');if(c2)c2.textContent=count+' rows';
  var c1=document.getElementById('fi-count');if(c1)c1.textContent=String(count);
}
function updateFiCount(){
  var c1=document.getElementById('fi-count');if(c1)c1.textContent=String(trusted.length);
  var c2=document.getElementById('fi-count2');if(c2)c2.textContent=trusted.length+' rows';
}
function buildSecurity(){
  var pane=document.getElementById('paneSecurity');
  var si=trusted.filter(function(t){return['security','env','database','dependency'].indexOf(t.eng)!==-1;});
  var html='<div class="sh"><span class="ico">&#x1F512;</span>Security findings</div>';
  html+='<div class="stat-row">';
  [{l:'CRITICAL',c:'c-red'},{l:'HIGH',c:'c-orange'},{l:'MEDIUM',c:'c-yellow'},{l:'LOW',c:'c-gray'}].forEach(function(s){
    var n=si.filter(function(i){return i.sev===s.l;}).length;
    html+='<div class="stat-card"><div class="sv '+s.c+'">'+n+'</div><div class="sl">'+s.l+'</div></div>';
  });
  html+='</div>';
  if(top.length){
    html+='<div class="sh"><span class="ico">&#x1F6A8;</span>Top critical items</div>'+
      '<div class="tbl-wrap"><table id="tbl-top"><thead><tr><th class="sortable">Sev</th><th class="sortable">Location</th><th class="sortable">Title</th></tr></thead><tbody>';
    top.forEach(function(t){html+='<tr><td>'+sevBadge(t.sev)+'</td><td style="font-family:var(--mono);font-size:.76rem"><code>'+esc(t.file)+':'+t.line+'</code></td><td>'+esc(t.title)+'</td></tr>';});
    html+='</tbody></table></div>';
  }
  html+='<div class="sh"><span class="ico">&#x1F50E;</span>All security findings <span class="tab-badge">'+si.length+'</span></div>'+
    '<div class="toolbar"><div class="search-wrap"><span class="ico-search">&#x1F50D;</span><input type="search" id="sec-q" placeholder="Search…"/></div></div>'+
    '<div class="tbl-wrap"><table id="tbl-sec"><thead><tr><th class="sortable">Sev</th><th class="sortable">Engine</th><th class="sortable">Location</th><th class="sortable">Title</th><th>Evidence</th></tr></thead><tbody id="sec-tbody">';
  si.forEach(function(t,i){html+='<tr data-q="'+esc((t.sev+' '+t.eng+' '+t.path+' '+t.title).toLowerCase())+'">'+
    '<td>'+sevBadge(t.sev)+'</td><td style="font-family:var(--mono);font-size:.78rem">'+esc(t.eng)+'</td>'+
    '<td style="font-family:var(--mono);font-size:.76rem"><code>'+esc(t.path)+':'+t.line+'</code></td>'+
    '<td><a href="#" class="sd" data-i="'+i+'">'+esc(t.title)+'</a></td>'+
    '<td class="ev">'+esc((t.ev||'').slice(0,100))+'</td></tr>';});
  html+='</tbody></table></div>';
  pane.innerHTML=html;
  pane.querySelectorAll('.sd').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();showModal(si[+a.dataset.i]);});});
  var sq=pane.querySelector('#sec-q');
  if(sq)sq.addEventListener('input',function(){
    var n=sq.value.toLowerCase();
    pane.querySelectorAll('#sec-tbody tr').forEach(function(tr){tr.classList.toggle('hidden',!!(n&&tr.dataset.q.indexOf(n)===-1));});
  });
  makeSortable('tbl-top');
  makeSortable('tbl-sec');
}
function buildPerf(){
  var pane=document.getElementById('panePerf');
  var pi=trusted.filter(function(t){return t.eng==='performance'||t.eng==='memory';});
  var html='<div class="sh"><span class="ico">&#x26A1;</span>Performance findings <span class="tab-badge">'+pi.length+'</span></div>';
  if(!pi.length){html+='<p class="note">No performance issues found.</p>';pane.innerHTML=html;return;}
  html+='<div class="toolbar"><div class="search-wrap"><span class="ico-search">&#x1F50D;</span><input type="search" id="perf-q" placeholder="Search…"/></div></div>'+
    '<div class="tbl-wrap"><table id="tbl-perf"><thead><tr><th class="sortable">Sev</th><th class="sortable">Engine</th><th class="sortable">Location</th><th class="sortable">Title</th></tr></thead><tbody id="perf-tbody">';
  pi.forEach(function(t,i){html+='<tr data-q="'+esc((t.sev+' '+t.eng+' '+t.path+' '+t.title).toLowerCase())+'">'+
    '<td>'+sevBadge(t.sev)+'</td><td style="font-family:var(--mono);font-size:.78rem">'+esc(t.eng)+'</td>'+
    '<td style="font-family:var(--mono);font-size:.76rem"><code>'+esc(t.path)+':'+t.line+'</code></td>'+
    '<td><a href="#" class="pd" data-i="'+i+'">'+esc(t.title)+'</a></td></tr>';});
  html+='</tbody></table></div>';
  pane.innerHTML=html;
  pane.querySelectorAll('.pd').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();showModal(pi[+a.dataset.i]);});});
  var pq=pane.querySelector('#perf-q');
  if(pq)pq.addEventListener('input',function(){
    var n=pq.value.toLowerCase();
    pane.querySelectorAll('#perf-tbody tr').forEach(function(tr){tr.classList.toggle('hidden',!!(n&&tr.dataset.q.indexOf(n)===-1));});
  });
  makeSortable('tbl-perf');
}
function buildDeps(){
  var pane=document.getElementById('paneDeps');
  var di=trusted.filter(function(t){return['dependency','outdated','migration'].indexOf(t.eng)!==-1;});
  var html='<div class="sh"><span class="ico">&#x1F4E6;</span>Dependency findings <span class="tab-badge">'+di.length+'</span></div>';
  if(!di.length){html+='<p class="note">No dependency issues found.</p>';pane.innerHTML=html;return;}
  html+='<div class="toolbar"><div class="search-wrap"><span class="ico-search">&#x1F50D;</span><input type="search" id="dep-q" placeholder="Search…"/></div></div>'+
    '<div class="tbl-wrap"><table id="tbl-dep"><thead><tr><th class="sortable">Sev</th><th class="sortable">Engine</th><th class="sortable">Title</th><th>Description</th></tr></thead><tbody id="dep-tbody">';
  di.forEach(function(t,i){html+='<tr data-q="'+esc((t.sev+' '+t.eng+' '+t.title).toLowerCase())+'">'+
    '<td>'+sevBadge(t.sev)+'</td><td style="font-family:var(--mono);font-size:.78rem">'+esc(t.eng)+'</td>'+
    '<td><a href="#" class="dd" data-i="'+i+'">'+esc(t.title)+'</a></td>'+
    '<td style="color:var(--text-dim);max-width:320px">'+esc((t.desc||'').slice(0,140))+'</td></tr>';});
  html+='</tbody></table></div>';
  pane.innerHTML=html;
  pane.querySelectorAll('.dd').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();showModal(di[+a.dataset.i]);});});
  var dq=pane.querySelector('#dep-q');
  if(dq)dq.addEventListener('input',function(){
    var n=dq.value.toLowerCase();
    pane.querySelectorAll('#dep-tbody tr').forEach(function(tr){tr.classList.toggle('hidden',!!(n&&tr.dataset.q.indexOf(n)===-1));});
  });
  makeSortable('tbl-dep');
}
function buildRoutes(){
  var pane=document.getElementById('paneRoutes');
  var open=routes.filter(function(r){return r.auth==='likely-open';}).length;
  var html='<div class="sh"><span class="ico">&#x1F310;</span>API Routes <span class="tab-badge">'+routes.length+'</span></div>'+
    '<div class="stat-row">'+
    '<div class="stat-card"><div class="sv c-blue">'+routes.length+'</div><div class="sl">Total</div></div>'+
    '<div class="stat-card"><div class="sv c-red">'+open+'</div><div class="sl">Unprotected</div></div>'+
    '<div class="stat-card"><div class="sv c-green">'+(routes.length-open)+'</div><div class="sl">Protected</div></div>'+
    '</div>';
  if(!routes.length){html+='<p class="note">No API routes detected.</p>';pane.innerHTML=html;return;}
  html+='<div class="toolbar"><div class="search-wrap"><span class="ico-search">&#x1F50D;</span><input type="search" id="rt-q" placeholder="Search path, method, file…"/></div>'+
    '<select id="rt-auth"><option value="">All auth</option><option value="likely-open">Open only</option><option value="likely-protected">Protected only</option></select></div>'+
    '<div class="tbl-wrap"><table id="tbl-rt"><thead><tr><th class="sortable">Method</th><th class="sortable">Path</th><th class="sortable">Auth</th><th class="sortable">File</th></tr></thead><tbody id="rt-tbody">';
  routes.forEach(function(r){
    html+='<tr data-q="'+esc(((r.method||'')+(r.path||'')+(r.file||'')+(r.auth||'')).toLowerCase())+'" data-auth="'+esc(r.auth||'')+'">'+
      '<td>'+methodBadge(r.method)+'</td>'+
      '<td style="font-family:var(--mono)">'+esc(r.path)+'</td>'+
      '<td>'+authBadge(r.auth)+'</td>'+
      '<td style="font-family:var(--mono);font-size:.76rem;color:var(--text-dim)"><code>'+esc(r.file)+':'+r.line+'</code></td></tr>';
  });
  html+='</tbody></table></div>';
  pane.innerHTML=html;
  function filterRoutes(){
    var n=(pane.querySelector('#rt-q')||{}).value||'';n=n.toLowerCase();
    var fa=(pane.querySelector('#rt-auth')||{}).value||'';
    pane.querySelectorAll('#rt-tbody tr').forEach(function(tr){
      var ok=true;
      if(n&&tr.dataset.q.indexOf(n)===-1)ok=false;
      if(ok&&fa&&tr.dataset.auth!==fa)ok=false;
      tr.classList.toggle('hidden',!ok);
    });
  }
  pane.querySelector('#rt-q').addEventListener('input',filterRoutes);
  pane.querySelector('#rt-auth').addEventListener('change',filterRoutes);
  makeSortable('tbl-rt');
}
function buildTests(){
  var pane=document.getElementById('paneTests');
  var ti=trusted.filter(function(t){return t.eng==='test'||t.eng==='tests';});
  var html='<div class="sh"><span class="ico">&#x1F9EA;</span>Test coverage</div>'+
    '<p class="note">Score: <strong class="'+scoreColor(sc.tests||0)+'">'+sc.tests+'</strong>/100</p>';
  if(!ti.length){html+='<p class="note">No test issues flagged.</p>';pane.innerHTML=html;return;}
  html+='<div class="tbl-wrap"><table id="tbl-tests"><thead><tr><th class="sortable">Sev</th><th class="sortable">Title</th><th class="sortable">Location</th></tr></thead><tbody>';
  ti.forEach(function(t,i){html+='<tr><td>'+sevBadge(t.sev)+'</td>'+
    '<td><a href="#" class="tid" data-i="'+i+'">'+esc(t.title)+'</a></td>'+
    '<td style="font-family:var(--mono);font-size:.76rem"><code>'+esc(t.path)+':'+t.line+'</code></td></tr>';});
  html+='</tbody></table></div>';
  pane.innerHTML=html;
  pane.querySelectorAll('.tid').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();showModal(ti[+a.dataset.i]);});});
  makeSortable('tbl-tests');
}
function buildArch(){
  var pane=document.getElementById('paneArch');
  var ai=trusted.filter(function(t){return t.eng==='ast'||t.eng==='architecture'||t.eng==='code-smell';});
  var html='<div class="sh"><span class="ico">&#x1F3D7;</span>Architecture &amp; code quality</div>'+
    '<p class="note">Code Quality: <strong class="'+scoreColor(sc.codeQuality||0)+'">'+sc.codeQuality+'</strong>/100</p>';
  if(hotFiles.length){
    html+='<div class="sh"><span class="ico">&#x1F525;</span>Files with most issues</div>';
    var hmax=hotFiles[0][1]||1;
    hotFiles.slice(0,10).forEach(function(f){
      html+='<div class="hbar"><span title="'+esc(f[0])+'" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-dim);font-size:.75rem">'+esc(f[0].length>32?'…'+f[0].slice(-30):f[0])+'</span>'+
        '<div class="hb-track"><div class="hb-fill" style="width:'+Math.round(f[1]/hmax*100)+'%;background:#ef4444"></div></div>'+
        '<span class="hb-num">'+f[1]+'</span></div>';
    });
  }
  if(!ai.length){html+='<p class="note">No architecture issues found.</p>';pane.innerHTML=html;return;}
  html+='<div class="sh"><span class="ico">&#x1F4CB;</span>Code quality findings <span class="tab-badge">'+ai.length+'</span></div>'+
    '<div class="toolbar"><div class="search-wrap"><span class="ico-search">&#x1F50D;</span><input type="search" id="arch-q" placeholder="Search…"/></div></div>'+
    '<div class="tbl-wrap"><table id="tbl-arch"><thead><tr><th class="sortable">Sev</th><th class="sortable">Engine</th><th class="sortable">Location</th><th class="sortable">Title</th></tr></thead><tbody id="arch-tbody">';
  ai.forEach(function(t,i){html+='<tr data-q="'+esc((t.sev+' '+t.eng+' '+t.path+' '+t.title).toLowerCase())+'">'+
    '<td>'+sevBadge(t.sev)+'</td><td style="font-family:var(--mono);font-size:.78rem">'+esc(t.eng)+'</td>'+
    '<td style="font-family:var(--mono);font-size:.76rem"><code>'+esc(t.path)+':'+t.line+'</code></td>'+
    '<td><a href="#" class="aid" data-i="'+i+'">'+esc(t.title)+'</a></td></tr>';});
  html+='</tbody></table></div>';
  pane.innerHTML=html;
  pane.querySelectorAll('.aid').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();showModal(ai[+a.dataset.i]);});});
  var aq=pane.querySelector('#arch-q');
  if(aq)aq.addEventListener('input',function(){
    var n=aq.value.toLowerCase();
    pane.querySelectorAll('#arch-tbody tr').forEach(function(tr){tr.classList.toggle('hidden',!!(n&&tr.dataset.q.indexOf(n)===-1));});
  });
  makeSortable('tbl-arch');
}
function escH(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function ifmt(s){
  s=s.replace(new RegExp('\\x60([^\\x60\\n]+)\\x60','g'),function(_m,c){return '<code>'+escH(c)+'</code>';});
  s=s.replace(/\\*\\*([^*\\n]+)\\*\\*/g,function(_m,c){return '<strong>'+escH(c)+'</strong>';});
  return s;
}
function renderMd(md){
  if(!md)return '<p class="note">No content.</p>';
  var lines=md.split(/\\r?\\n/);var out='';var inCode=false;var inUl=false;var inOl=false;var inTbl=false;var cbuf='';var clang='';
  function closeL(){if(inUl){out+='</ul>';inUl=false;}if(inOl){out+='</ol>';inOl=false;}}
  function closeTbl(){if(inTbl){out+='</tbody></table>';inTbl=false;}}
  for(var i=0;i<lines.length;i++){
    var ln=lines[i];
    if(ln.startsWith('\x60\x60\x60')){
      if(!inCode){inCode=true;clang=ln.slice(3).trim();cbuf='';}
      else{closeL();closeTbl();out+='<pre><code>'+escH(cbuf.replace(/\\n$/,''))+'</code></pre>';inCode=false;}
      continue;
    }
    if(inCode){cbuf+=ln+'\\n';continue;}
    var hm=ln.match(/^(#{1,4})\\s+(.*)/);
    if(hm){closeL();closeTbl();out+='<h'+hm[1].length+'>'+escH(hm[2])+'</h'+hm[1].length+'>';continue;}
    if(/^---+$/.test(ln.trim())){closeL();closeTbl();out+='<hr>';continue;}
    if(ln.startsWith('> ')){closeL();closeTbl();out+='<blockquote>'+ifmt(escH(ln.slice(2)))+'</blockquote>';continue;}
    var ulm=ln.match(/^[-*+]\\s+(.*)/);
    if(ulm){closeTbl();if(!inUl){closeL();out+='<ul>';inUl=true;}out+='<li>'+ifmt(escH(ulm[1]))+'</li>';continue;}
    var olm=ln.match(/^\\d+\\.\\s+(.*)/);
    if(olm){closeTbl();if(!inOl){closeL();out+='<ol>';inOl=true;}out+='<li>'+ifmt(escH(olm[1]))+'</li>';continue;}
    if(ln.includes('|')&&ln.trim().startsWith('|')){
      if(i+1<lines.length&&/^\\|[-| :]+\\|/.test(lines[i+1]||'')){
        closeL();if(!inTbl){out+='<table><thead><tr>';inTbl=true;}
        ln.split('|').slice(1,-1).forEach(function(c){out+='<th>'+ifmt(escH(c.trim()))+'</th>';});
        out+='</tr></thead><tbody>';i++;
      }else if(inTbl){
        out+='<tr>';ln.split('|').slice(1,-1).forEach(function(c){out+='<td>'+ifmt(escH(c.trim()))+'</td>';});out+='</tr>';
      }
      continue;
    }
    closeTbl();
    if(!ln.trim()){closeL();}
    else{closeL();out+='<p>'+ifmt(escH(ln))+'</p>';}
  }
  if(inCode)out+='<pre><code>'+escH(cbuf)+'</code></pre>';
  closeL();closeTbl();
  return out;
}
function renderJson(raw){
  if(!raw)return '<span style="color:var(--text-dim)">No content.</span>';
  var s=escH(raw);
  s=s.replace(/&quot;([^&\\n]+?)&quot;\\s*:/g,'<span class="jk">&quot;$1&quot;</span>:');
  s=s.replace(/:\\s*&quot;([^&\\n]*?)&quot;/g,': <span class="js">&quot;$1&quot;</span>');
  s=s.replace(/:\\s*(-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)/g,': <span class="jn">$1</span>');
  s=s.replace(/:\\s*(true|false|null)/g,': <span class="jb">$1</span>');
  return s;
}
function renderArchVis(){
  var fw=escH(String(D.framework||'app'));
  var ai=D.archIssues||[];
  var mdls=D.dbModels||[];
  var html='<div class="vis-wrap">';
  html+='<div class="vis-sec"><div class="vis-sec-t">Data Flow Pipeline</div>'+
    '<div class="pipe-flow">'+
      '<div class="pipe-node">Client / UI</div><span class="pipe-arrow">&#x2192;</span>'+
      '<div class="pipe-node">Router</div><span class="pipe-arrow">&#x2192;</span>'+
      '<div class="pipe-node">Controllers</div><span class="pipe-arrow">&#x2192;</span>'+
      '<div class="pipe-node">Services</div><span class="pipe-arrow">&#x2192;</span>'+
      '<div class="pipe-node">Repositories</div><span class="pipe-arrow">&#x2192;</span>'+
      '<div class="pipe-node">Database</div>'+
    '</div>'+
    '<div class="pipe-note">Framework: <strong>'+fw+'</strong> &nbsp;&#x2022;&nbsp; '+
      escH(String(mdls.length))+' models &nbsp;&#x2022;&nbsp; '+
      escH(String(D.entityCount||0))+' entity files &nbsp;&#x2022;&nbsp; '+
      escH(String(D.migrationCount||0))+' migrations</div></div>';
  if(ai.length){
    html+='<div class="vis-sec"><div class="vis-sec-t">Architecture Issues ('+ai.length+')</div><div class="vis-issue-list">';
    ai.slice(0,20).forEach(function(x){
      html+='<div class="vis-issue sev-'+escH(x.sev)+'">'+sevBadge(x.sev)+
        '<div class="vis-issue-body"><div class="vis-issue-t">'+escH(x.title)+'</div>'+
        '<div class="vis-issue-l">'+escH(x.file)+':'+escH(String(x.line))+'</div>'+
        (x.desc?'<div class="vis-issue-d">'+escH(x.desc)+'</div>':'')+
        '</div></div>';
    });
    html+='</div></div>';
  }else{
    html+='<div class="vis-sec"><p class="note" style="margin:0">No architecture issues found.</p></div>';
  }
  return html+'</div>';
}
function renderDbVis(){
  var mdls=D.dbModels||[];var rels=D.dbRelations||[];var hints=D.dbHints||[];var di=D.dbIssues||[];
  var html='<div class="vis-wrap">';
  html+='<div class="vis-sec"><div class="vis-sec-t">Overview</div><div class="vis-stats">'+
    '<div><div class="vis-stat-n">'+escH(String(mdls.length))+'</div><div class="vis-stat-l">Models</div></div>'+
    '<div><div class="vis-stat-n">'+escH(String(rels.length))+'</div><div class="vis-stat-l">Relations</div></div>'+
    '<div><div class="vis-stat-n">'+escH(String(hints.length))+'</div><div class="vis-stat-l">Index Hints</div></div>'+
    '<div><div class="vis-stat-n">'+escH(String(D.entityCount||0))+'</div><div class="vis-stat-l">Entity Files</div></div>'+
    '<div><div class="vis-stat-n">'+escH(String(D.migrationCount||0))+'</div><div class="vis-stat-l">Migrations</div></div>'+
  '</div></div>';
  if(mdls.length){
    html+='<div class="vis-sec"><div class="vis-sec-t">Schema Models</div><div class="model-grid">';
    mdls.forEach(function(m){
      html+='<div class="model-card"><div class="model-card-t" title="'+escH(m.name)+'">'+escH(m.name)+'</div>'+
        '<div class="model-card-s">'+escH(m.source)+'</div>';
      (m.fields||[]).forEach(function(f){
        html+='<div class="model-field"><span class="mfn">'+escH(f.n)+'</span><span class="mft">'+escH(f.t)+'</span></div>';
      });
      if((m.fields||[]).length===12)html+='<div class="model-more">+more</div>';
      html+='</div>';
    });
    html+='</div></div>';
  }
  if(rels.length){
    html+='<div class="vis-sec"><div class="vis-sec-t">Relations</div><div class="rel-list">';
    rels.slice(0,30).forEach(function(r){
      html+='<div class="rel-row"><span class="rel-from">'+escH(r.from)+'</span>'+
        '<span class="rel-card">'+escH(r.card)+'</span>'+
        '<span class="rel-to">'+escH(r.to)+'</span></div>';
    });
    if(rels.length>30)html+='<div class="note" style="margin:.25rem 0">+'+(rels.length-30)+' more</div>';
    html+='</div></div>';
  }
  if(hints.length){
    html+='<div class="vis-sec"><div class="vis-sec-t">Indexing Hints</div><div class="hint-list">';
    hints.forEach(function(h){html+='<div class="hint-row"><span class="hint-dot">&#x25CF;</span><span>'+escH(h)+'</span></div>';});
    html+='</div></div>';
  }
  if(di.length){
    html+='<div class="vis-sec"><div class="vis-sec-t">Database Issues ('+di.length+')</div><div class="vis-issue-list">';
    di.slice(0,20).forEach(function(x){
      html+='<div class="vis-issue sev-'+escH(x.sev)+'">'+sevBadge(x.sev)+
        '<div class="vis-issue-body"><div class="vis-issue-t">'+escH(x.title)+'</div>'+
        '<div class="vis-issue-l">'+escH(x.file)+':'+escH(String(x.line))+'</div>'+
        (x.desc?'<div class="vis-issue-d">'+escH(x.desc)+'</div>':'')+
        '</div></div>';
    });
    html+='</div></div>';
  }
  return html+'</div>';
}
function switchPvTab(btn,tab){
  var tabs=btn.closest('.pv-tabs');if(!tabs)return;
  tabs.querySelectorAll('.pv-tab').forEach(function(t){t.classList.remove('active');});
  btn.classList.add('active');
  var container=tabs.parentNode;if(!container)return;
  container.querySelectorAll('.pv-panel').forEach(function(p){p.style.display='none';});
  var tgt=container.querySelector('#pv-'+tab);
  if(tgt)tgt.style.display='';
}
function openPreview(name,icon,label){
  var bf=D.bundleFiles||{};var raw=bf[name]||'';
  var isJson=name.endsWith('.json');var isArch=(name==='architecture.md');var isDb=(name==='database.md');
  var oi=document.getElementById('pvOvIcon');
  var ot=document.getElementById('pvOvTitle');
  var ob=document.getElementById('pvOvBody');
  if(!oi||!ot||!ob)return;
  oi.textContent=icon;
  ot.textContent=label;
  var pvTabs='';
  if(isArch||isDb)pvTabs='<div class="pv-tabs"><button class="pv-tab active" onclick="switchPvTab(this,&quot;vis&quot;)">Visual</button><button class="pv-tab" onclick="switchPvTab(this,&quot;md&quot;)">Markdown</button></div>';
  else if(isJson)pvTabs='<div class="pv-tabs"><button class="pv-tab active" onclick="switchPvTab(this,&quot;json&quot;)">JSON</button></div>';
  else pvTabs='<div class="pv-tabs"><button class="pv-tab active" onclick="switchPvTab(this,&quot;md&quot;)">Markdown</button></div>';
  var cnt='';
  if(isArch){
    cnt='<div id="pv-vis" class="pv-panel" style="overflow:auto">'+renderArchVis()+'</div>'+
        '<div id="pv-md" class="pv-panel" style="display:none"><div class="md-body">'+renderMd(raw)+'</div></div>';
  }else if(isDb){
    cnt='<div id="pv-vis" class="pv-panel" style="overflow:auto">'+renderDbVis(raw)+'</div>'+
        '<div id="pv-md" class="pv-panel" style="display:none"><div class="md-body">'+renderMd(raw)+'</div></div>';
  }else if(isJson){
    cnt='<div id="pv-json" class="pv-panel"><div class="json-body">'+renderJson(raw)+'</div></div>';
  }else{
    cnt='<div id="pv-md" class="pv-panel"><div class="md-body">'+renderMd(raw)+'</div></div>';
  }
  ob.innerHTML=pvTabs+cnt;
  document.getElementById('pvOverlay').classList.add('open');
  document.getElementById('pvOvClose').focus();
}
function buildBundle(){
  var pane=document.getElementById('paneBundle');
  var bf=D.bundleFiles||{};
  var entries=[
    {h:'action-plan.md',    i:'&#x1F4CB;',l:'Action Plan',        pv:true},
    {h:'audit-summary.md',  i:'&#x1F4DD;',l:'Audit Summary',      pv:true},
    {h:'api.md',            i:'&#x1F310;',l:'API Routes',          pv:true},
    {h:'architecture.md',   i:'&#x1F3D7;',l:'Architecture',        pv:true},
    {h:'database.md',       i:'&#x1F5C4;',l:'Database Schema',     pv:true},
    {h:'decision.json',     i:'&#x1F4CA;',l:'Production Decision', pv:true},
    {h:'scores.json',       i:'&#x1F3AF;',l:'Scores',              pv:true},
    {h:'governance-suppressions.json',i:'&#x1F507;',l:'Suppressions',pv:true},
    {h:'results.sarif',     i:'&#x1F52C;',l:'SARIF 2.1',           pv:false},
    {h:'openapi.json',      i:'&#x1F310;',l:'OpenAPI Spec',        pv:false},
    {h:'sbom.cdx.json',     i:'&#x1F4E6;',l:'SBOM (CycloneDX)',    pv:false},
  ];
  var html='<div class="sh"><span class="ico">&#x1F4C1;</span>Report bundle</div>'+
    '<p class="note">All files are local &#x2014; open via <code>file://</code>. Zero CDN calls, works offline.</p>';
  entries.forEach(function(e){
    var has=!!(bf[e.h]);
    var pvBtn=has&&e.pv?'<button class="bnd-btn" onclick="openPreview(&quot;'+escH(e.h)+'&quot;,&quot;'+escH(e.i)+'&quot;,&quot;'+escH(e.l)+'&quot;)">View</button>':'';
    var openBtn=has?'<a href="'+escH(e.h)+'" class="bnd-btn bnd-open" target="_blank">Open</a>':
      '<span style="font-size:.72rem;color:var(--text-dim);flex-shrink:0;padding:.22rem 0">Not generated</span>';
    html+='<div class="bnd-row">'+
      '<span class="bnd-icon">'+e.i+'</span>'+
      '<span class="bnd-name">'+escH(e.l)+'</span>'+
      pvBtn+openBtn+
    '</div>';
  });
  pane.innerHTML=html;
}
function showModal(t){
  var body=document.getElementById('modalBody');
  var title=document.getElementById('modalTitle');
  if(!body||!title)return;
  title.textContent=t.title;
  var html='<div style="margin-bottom:.6rem">'+sevBadge(t.sev)+' <span style="font-family:var(--mono);color:var(--text-dim);font-size:.8rem">'+esc(t.eng)+'</span></div>';
  function field(lbl,val,mono){
    if(!val&&val!==0)return;
    html+='<div class="mfield"><div class="mfield-lbl">'+lbl+'</div>'+
      (mono?'<div class="mfield-val" style="font-family:var(--mono);font-size:.8rem">'+esc(String(val))+'</div>':
            '<div class="mfield-val">'+esc(String(val))+'</div>')+'</div>';
  }
  field('Location',t.path+':'+t.line,true);
  field('Confidence',t.conf);
  field('Owner',t.own);
  field('Compliance',t.comp);
  field('Description',t.desc);
  field('Fix',t.fix);
  if(t.ev)html+='<div class="mfield"><div class="mfield-lbl">Evidence</div><pre>'+esc(t.ev)+'</pre></div>';
  body.innerHTML=html;
  document.getElementById('modalBack').classList.add('open');
  document.getElementById('modalClose').focus();
}
document.getElementById('modalClose').addEventListener('click',closeModal);
document.getElementById('modalBack').addEventListener('click',function(e){if(e.target===this)closeModal();});
document.getElementById('pvOvClose').addEventListener('click',closePvOverlay);
document.addEventListener('keydown',function(e){if(e.key==='Escape'){closeModal();closePvOverlay();}});
function closeModal(){document.getElementById('modalBack').classList.remove('open');}
function closePvOverlay(){document.getElementById('pvOverlay').classList.remove('open');}
window.openPreview=openPreview;window.switchPvTab=switchPvTab;
})();
</script>
</body>
</html>`;
  await writeFile(join(outDir, 'index.html'), html, 'utf8');
}
