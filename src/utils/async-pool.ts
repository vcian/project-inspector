/**
 * Bounded-concurrency async pool (queue) without extra dependencies.
 */
export async function runPool<T, R>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) {
    return [];
  }

  const safeConcurrency = Math.max(1, Math.floor(concurrency));
  // Track completion per slot; the pool must not care whether `R` is `void`
  // or a value that happens to be `undefined`.
  const completed: boolean[] = Array.from({ length: items.length }, () => false);
  const slots: Array<R | undefined> = Array.from({ length: items.length }, (): R | undefined => undefined);
  let nextIndex = 0;

  const runners = Array.from({ length: Math.min(safeConcurrency, items.length) }, async () => {
    for (;;) {
      const current = nextIndex;
      nextIndex += 1;
      if (current >= items.length) {
        return;
      }
      const item = items[current];
      if (item === undefined) {
        completed[current] = true;
        continue;
      }
      slots[current] = await worker(item, current);
      completed[current] = true;
    }
  });

  await Promise.all(runners);

  const results: R[] = [];
  for (let i = 0; i < slots.length; i += 1) {
    if (completed[i] !== true) {
      throw new Error(`Internal pool error: missing result for index ${String(i)}`);
    }
    // Non-null assertion is safe for defined R types; void/undefined R is
    // passed through to callers unchanged.
    results.push(slots[i] as R);
  }

  return results;
}
