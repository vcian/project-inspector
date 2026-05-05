import type { Node } from 'ts-morph';
import { SyntaxKind } from 'ts-morph';

export function estimateCyclomaticComplexity(root: Node): number {
  let complexity = 1;

  root.forEachDescendant((node) => {
    switch (node.getKind()) {
      case SyntaxKind.IfStatement:
      case SyntaxKind.ForStatement:
      case SyntaxKind.ForInStatement:
      case SyntaxKind.ForOfStatement:
      case SyntaxKind.WhileStatement:
      case SyntaxKind.DoStatement:
        complexity += 1;
        return;
      case SyntaxKind.CatchClause:
        complexity += 1;
        return;
      case SyntaxKind.CaseClause: {
        const clause = node.asKindOrThrow(SyntaxKind.CaseClause);
        if (clause.getExpression().getText() !== 'default') {
          complexity += 1;
        }
        return;
      }
      case SyntaxKind.ConditionalExpression:
        complexity += 1;
        return;
      case SyntaxKind.BinaryExpression: {
        const op = node.asKindOrThrow(SyntaxKind.BinaryExpression).getOperatorToken().getKind();
        if (op === SyntaxKind.AmpersandAmpersandToken || op === SyntaxKind.BarBarToken) {
          complexity += 1;
        }
        return;
      }
      default:
        return;
    }
  });

  return complexity;
}

export function maxBlockNestingDepth(root: Node): number {
  let maxDepth = 0;

  const visit = (node: Node, depth: number): void => {
    maxDepth = Math.max(maxDepth, depth);

    for (const child of node.getChildren()) {
      switch (child.getKind()) {
        case SyntaxKind.Block:
        case SyntaxKind.IfStatement:
        case SyntaxKind.ForStatement:
        case SyntaxKind.ForInStatement:
        case SyntaxKind.ForOfStatement:
        case SyntaxKind.WhileStatement:
        case SyntaxKind.DoStatement:
        case SyntaxKind.SwitchStatement:
        case SyntaxKind.TryStatement:
        case SyntaxKind.CatchClause:
          visit(child, depth + 1);
          break;
        default:
          visit(child, depth);
      }
    }
  };

  visit(root, 0);
  return maxDepth;
}
