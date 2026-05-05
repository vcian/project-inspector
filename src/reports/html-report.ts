import { writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

import type { Issue, ScanResult } from '../core/types.js';
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

function buildTrustedPayload(result: ScanResult, rules: readonly CodeOwnersRule[]): unknown {
  const trusted = result.trustedIssues ?? [];
  const cap = 500;
  return trusted.slice(0, cap).map((i: Issue) => ({
    sev: i.severity,
    eng: i.engine,
    path: rel(result.cwd, i.file),
    line: i.line,
    title: i.title,
    conf: i.confidence ?? '',
    ev: (i.codeSnippet ?? i.code ?? '').slice(0, 220),
    own: ownerForPath(rules, rel(result.cwd, i.file)) ?? '',
  }));
}

/**
 * Static HTML hub: verdict, scores, baseline delta, filterable trusted table, links to bundle files.
 */
export async function writeReportIndexHtml(result: ScanResult, outDir: string): Promise<void> {
  const verdict = result.productionDecision?.verdict ?? '—';
  const gateOk = result.productionDecision?.gateOk;
  const gateLabel = gateOk === true ? 'PASS' : gateOk === false ? 'FAIL' : '—';
  const sc = result.scores;
  const diag = result.scoreDiagnostics;
  const top = result.productionDecision?.topCritical.slice(0, 7) ?? [];
  const mode = result.mode;
  const online = result.online ? 'yes' : 'no';
  const rules = await loadCodeOwnersRules(result.cwd);
  const payload = {
    trusted: buildTrustedPayload(result, rules),
    trustedTruncated: (result.trustedIssues?.length ?? 0) > 500,
    baseline: result.baselineComparison ?? null,
  };

  const axisRows = [
    ['Security', String(sc.security), diag?.axes.security],
    ['Performance', String(sc.performance), diag?.axes.performance],
    ['Code quality', String(sc.codeQuality), diag?.axes.codeQuality],
    ['Compliance', String(sc.compliance), diag?.axes.compliance],
    ['Tests', String(sc.tests), diag?.axes.tests],
  ] as const;

  const axisTable = axisRows
    .map(([label, val, ax]) => {
      const cnt = ax !== undefined ? String(ax.contributingTrustedIssueCount) : '—';
      const eng =
        ax !== undefined && ax.enginesRepresented.length > 0 ? esc(ax.enginesRepresented.join(', ')) : '—';
      return `<tr><td>${esc(label)}</td><td class="num">${esc(val)}</td><td class="meta">${cnt}</td><td class="meta">${eng}</td></tr>`;
    })
    .join('\n');

  const topRows = top
    .map(
      (t) =>
        `<tr><td>${esc(t.severity)}</td><td><code>${esc(t.relFile)}:${String(t.line)}</code></td><td>${esc(t.title)}</td></tr>`,
    )
    .join('\n');

  const baselineBlock =
    result.baselineComparison !== undefined
      ? `<h2>Baseline delta</h2><p class="note">Compared to baseline saved <code>${esc(result.baselineComparison.baselineSavedAt)}</code>. Run <code>project-inspector scan --save-baseline</code> to refresh.</p><table><thead><tr><th>New (trusted)</th><th>Resolved</th><th>Unchanged</th></tr></thead><tbody><tr><td class="num">${String(result.baselineComparison.newCount)}</td><td class="num">${String(result.baselineComparison.resolvedCount)}</td><td class="num">${String(result.baselineComparison.unchangedCount)}</td></tr></tbody></table>`
      : '<h2>Baseline delta</h2><p class="note">No baseline file yet. Run <code>project-inspector scan --save-baseline</code> once, then future scans show new vs resolved fingerprints.</p>';

  const jsonPayload = JSON.stringify(payload).replaceAll('</script>', '<\\/script>');
  const diagNote = diag !== undefined ? esc(diag.readinessWeightNotes) : '';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>project-inspector — ${esc(verdict)}</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, Segoe UI, Roboto, sans-serif; margin: 0; padding: 1rem 1.25rem; line-height: 1.45; max-width: 58rem; }
    h1 { font-size: 1.35rem; margin: 0 0 0.5rem; }
    h2 { font-size: 1.05rem; margin: 1.25rem 0 0.5rem; }
    .pill { display: inline-block; padding: 0.2rem 0.55rem; border-radius: 0.35rem; font-weight: 600; font-size: 0.9rem; }
    .ready { background: #14532d; color: #ecfccb; }
    .notready { background: #7f1d1d; color: #fee2e2; }
    table { border-collapse: collapse; width: 100%; font-size: 0.88rem; }
    th, td { border: 1px solid #8884; padding: 0.35rem 0.45rem; text-align: left; vertical-align: top; }
    th { background: #0001; }
    td.num { font-variant-numeric: tabular-nums; font-weight: 600; }
    td.meta { font-size: 0.82rem; opacity: 0.9; }
    ul.links { padding-left: 1.1rem; }
    .note { font-size: 0.86rem; opacity: 0.92; margin-top: 0.5rem; }
    code { font-size: 0.84rem; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; margin: 0.5rem 0; }
    .toolbar input[type="search"] { flex: 1; min-width: 12rem; padding: 0.35rem 0.5rem; }
    .toolbar select { padding: 0.35rem 0.5rem; }
    #trustedTable tbody tr.hidden { display: none; }
    .ev { font-size: 0.78rem; opacity: 0.88; max-width: 22rem; white-space: pre-wrap; word-break: break-word; }
  </style>
</head>
<body>
  <h1>Production readiness</h1>
  <p>
    <span class="pill ${verdict === 'READY' ? 'ready' : 'notready'}">${esc(verdict)}</span>
    &nbsp; Readiness <strong>${String(sc.productionReadiness)}</strong>/100
    &nbsp;· CI gate <strong>${esc(gateLabel)}</strong>
  </p>
  <p class="note">Static analysis only. Mode <code>${esc(mode)}</code>, online <code>${esc(online)}</code>, finished <code>${esc(result.finishedAt)}</code>. <strong>No telemetry</strong> is sent by this page.</p>

  <h2>Scores</h2>
  <p class="note">Axes start at 100; trusted findings deduct. <strong>0</strong> means heavy deductions, not “skipped”.</p>
  <table>
    <thead><tr><th>Axis</th><th>Score</th><th>Hits</th><th>Engines</th></tr></thead>
    <tbody>${axisTable}</tbody>
  </table>
  ${diagNote.length > 0 ? `<p class="note">${diagNote}</p>` : ''}

  ${baselineBlock}

  <h2>Top issues (decision)</h2>
  <table>
    <thead><tr><th>Sev</th><th>Where</th><th>Title</th></tr></thead>
    <tbody>${topRows.length > 0 ? topRows : '<tr><td colspan="3">—</td></tr>'}</tbody>
  </table>

  <h2>Trusted findings (filter)</h2>
  <p class="note">${payload.trustedTruncated ? 'Showing first <strong>500</strong> trusted rows. See security.md for full narrative.' : `Trusted rows: <strong>${String(result.trustedIssues?.length ?? 0)}</strong>.`}</p>
  <div class="toolbar">
    <label>Severity <select id="sev"><option value="">All</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>
    <input type="search" id="q" placeholder="Search path, title, engine, owner…" />
  </div>
  <table id="trustedTable">
    <thead><tr><th>Sev</th><th>Conf</th><th>Engine</th><th>Owner</th><th>Where</th><th>Title</th><th>Evidence</th></tr></thead>
    <tbody></tbody>
  </table>

  <h2>Report bundle</h2>
  <ul class="links">
    <li><a href="summary.md">summary.md</a></li>
    <li><a href="production-decision.md">production-decision.md</a></li>
    <li><a href="action-plan.md">action-plan.md</a></li>
    <li><a href="for-users.md">for-users.md</a></li>
    <li><a href="security.md">security.md</a></li>
    <li><a href="decision.json">decision.json</a> (<a href="schemas/decision.schema.json">JSON Schema</a>)</li>
    <li><a href="scores.json">scores.json</a></li>
    <li><a href="results.sarif">results.sarif</a></li>
  </ul>
  <p class="note">Open via <code>file://</code>. CI example: <code>examples/github-actions-project-inspector.yml</code> in the package repo.</p>

  <script type="application/json" id="pi-data">${jsonPayload}</script>
  <script>
(function () {
  var raw = document.getElementById('pi-data');
  if (!raw || !raw.textContent) return;
  var data = JSON.parse(raw.textContent);
  var tbody = document.querySelector('#trustedTable tbody');
  var sev = document.getElementById('sev');
  var q = document.getElementById('q');
  function row(t) {
    var tr = document.createElement('tr');
    tr.dataset.sev = t.sev;
    tr.dataset.q = (t.sev + ' ' + t.eng + ' ' + t.path + ' ' + t.title + ' ' + t.conf + ' ' + t.own + ' ' + t.ev).toLowerCase();
    tr.innerHTML = '<td>' + escapeHtml(t.sev) + '</td><td>' + escapeHtml(t.conf || '—') + '</td><td>' + escapeHtml(t.eng) + '</td><td>' + escapeHtml(t.own || '—') + '</td><td><code>' + escapeHtml(t.path) + ':' + String(t.line) + '</code></td><td>' + escapeHtml(t.title) + '</td><td class="ev">' + escapeHtml(t.ev || '—') + '</td>';
    return tr;
  }
  function escapeHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
  (data.trusted || []).forEach(function (t) { tbody.appendChild(row(t)); });
  function apply() {
    var f = (sev && sev.value) || '';
    var needle = (q && q.value || '').toLowerCase().trim();
    tbody.querySelectorAll('tr').forEach(function (tr) {
      var ok = true;
      if (f && tr.dataset.sev !== f) ok = false;
      if (ok && needle && tr.dataset.q.indexOf(needle) === -1) ok = false;
      tr.classList.toggle('hidden', !ok);
    });
  }
  if (sev) sev.addEventListener('change', apply);
  if (q) q.addEventListener('input', apply);
})();
  </script>
</body>
</html>
`;

  await writeFile(join(outDir, 'index.html'), html, 'utf8');
}
