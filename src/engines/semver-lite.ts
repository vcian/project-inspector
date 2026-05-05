/** Minimal semver helpers (no external dependency). */

export function declaredMajorFromRange(range: string): number | null {
  const t = range.trim();
  if (t === '*' || t === 'latest' || t === 'x') {
    return null;
  }
  const stripped = t.replace(/^[\^~>=<]+\s*/, '');
  const m = stripped.match(/^(\d+)/);
  return m?.[1] ? Number(m[1]) : null;
}

export function majorGap(declared: number | null, knownLatestMajor: number): number | null {
  if (declared === null) {
    return null;
  }
  return knownLatestMajor - declared;
}
