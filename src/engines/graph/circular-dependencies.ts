import type { ImportEdge } from '../../core/types.js';

/**
 * Find circular dependency chains using a GRAY/WHITE/BLACK DFS (directed graph).
 */
export function findCircularDependencyChains(
  edges: readonly ImportEdge[],
  maxChains: number,
): string[][] {
  const adjacency = new Map<string, string[]>();
  for (const e of edges) {
    const list = adjacency.get(e.from);
    if (list) {
      list.push(e.to);
    } else {
      adjacency.set(e.from, [e.to]);
    }
  }

  type Color = 0 | 1 | 2;
  const color = new Map<string, Color>();
  const stack: string[] = [];
  const cycles: string[][] = [];

  const dfs = (node: string): void => {
    if (cycles.length >= maxChains) {
      return;
    }

    color.set(node, 1);
    stack.push(node);

    for (const next of adjacency.get(node) ?? []) {
      const nextColor = color.get(next) ?? 0;
      if (nextColor === 0) {
        dfs(next);
        if (cycles.length >= maxChains) {
          return;
        }
      } else if (nextColor === 1) {
        const idx = stack.indexOf(next);
        if (idx >= 0) {
          cycles.push(stack.slice(idx));
        }
        if (cycles.length >= maxChains) {
          return;
        }
      }
    }

    stack.pop();
    color.set(node, 2);
  };

  for (const node of adjacency.keys()) {
    if ((color.get(node) ?? 0) === 0) {
      dfs(node);
    }
    if (cycles.length >= maxChains) {
      break;
    }
  }

  return cycles;
}
