import { readFile, readdir } from 'node:fs/promises';
import { join, normalize } from 'node:path';

import type { DatabaseIntelligence, InventoryFile } from '../core/types.js';

interface MutableModel {
  name: string;
  source: 'prisma' | 'typeorm' | 'mongoose' | 'sql' | 'inventory';
  fields: { name: string; typeToken: string }[];
}

type RelationEdge = {
  from: string;
  to: string;
  cardinality: DatabaseIntelligence['relations'][number]['cardinality'];
};

const PRISMA_SCALARS = new Set([
  'String',
  'Int',
  'Boolean',
  'DateTime',
  'Json',
  'Float',
  'Decimal',
  'Bytes',
  'BigInt',
  'Unsupported',
]);

function pushRelation(rels: RelationEdge[], from: string, to: string, cardinality: RelationEdge['cardinality']): void {
  if (from.length === 0 || to.length === 0 || from === to) {
    return;
  }
  const key = `${from}->${to}`;
  if (rels.some((r) => `${r.from}->${r.to}` === key)) {
    return;
  }
  rels.push({ from, to, cardinality });
}

function extractPrismaModels(text: string): Array<{ name: string; body: string }> {
  const out: Array<{ name: string; body: string }> = [];
  const re = /^model\s+(\w+)\s*\{/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const name = m[1];
    if (name === undefined) {
      continue;
    }
    const openBraceIdx = text.indexOf('{', m.index);
    if (openBraceIdx < 0) {
      continue;
    }
    let depth = 1;
    let i = openBraceIdx + 1;
    while (i < text.length && depth > 0) {
      const ch = text[i];
      if (ch === '{') {
        depth += 1;
      } else if (ch === '}') {
        depth -= 1;
      }
      i += 1;
    }
    const body = text.slice(openBraceIdx + 1, i - 1);
    out.push({ name, body });
  }
  return out;
}

function parsePrismaModelBody(
  modelName: string,
  body: string,
): { fields: { name: string; typeToken: string }[]; relations: RelationEdge[]; hints: string[] } {
  const fields: { name: string; typeToken: string }[] = [];
  const relations: RelationEdge[] = [];
  const hints: string[] = [];
  const lines = body.split(/\r?\n/);
  let buf = '';
  const flushBuf = (): void => {
    const raw = buf.trim();
    buf = '';
    if (raw.length === 0) {
      return;
    }
    if (raw.startsWith('@@')) {
      hints.push(`Prisma ${modelName}: ${raw.slice(0, 140)}`);
      return;
    }
    const fieldMatch = /^(\w+)\s+(\S+)/.exec(raw);
    if (fieldMatch?.[1] === undefined || fieldMatch[2] === undefined) {
      return;
    }
    const fieldName = fieldMatch[1];
    const typeTokFull = fieldMatch[2];
    if (['model', 'enum', 'generator', 'datasource', 'import'].includes(fieldName)) {
      return;
    }
    const typeHead = typeTokFull.replace(/\?$/u, '').replace(/\[\]$/u, '').split('@')[0]?.trim() ?? typeTokFull;
    const isList = typeTokFull.includes('[]') || /\[\s*\]\s*$/u.test(typeTokFull);
    fields.push({ name: fieldName, typeToken: raw.replace(/\s+/gu, ' ').slice(0, 96) });

    if (typeHead.length > 0 && /^[A-Z]\w*$/u.test(typeHead) && !PRISMA_SCALARS.has(typeHead)) {
      const card: RelationEdge['cardinality'] = isList ? '1:N' : 'N:1';
      pushRelation(relations, modelName, typeHead, card);
    }
    if (/@relation\s*\(/iu.test(raw)) {
      const rm = /@relation\s*\(([\s\S]*)\)/iu.exec(raw);
      const inner = rm?.[1];
      if (inner !== undefined && /fields\s*:/iu.test(inner) && /references\s*:/iu.test(inner)) {
        hints.push(`Prisma @relation ${modelName}.${fieldName} → ${typeHead} (FK fields/references)`);
      }
    }
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('//')) {
      continue;
    }
    buf += (buf.length > 0 ? ' ' : '') + trimmed;
    const opens = (buf.match(/\(/gu) ?? []).length;
    const closes = (buf.match(/\)/gu) ?? []).length;
    if (opens > closes) {
      continue;
    }
    flushBuf();
  }
  if (buf.trim().length > 0) {
    flushBuf();
  }

  return { fields, relations, hints };
}

/**
 * Best-effort Prisma `schema.prisma` model + relation extraction (no engine dependency).
 */
function parsePrismaSchema(text: string): { models: MutableModel[]; hints: string[]; relations: RelationEdge[] } {
  const models: MutableModel[] = [];
  const hints: string[] = [];
  const relations: RelationEdge[] = [];
  for (const { name, body } of extractPrismaModels(text)) {
    const parsed = parsePrismaModelBody(name, body);
    models.push({ name, source: 'prisma', fields: parsed.fields });
    hints.push(...parsed.hints);
    for (const r of parsed.relations) {
      pushRelation(relations, r.from, r.to, r.cardinality);
    }
  }
  return { models, hints, relations };
}

const TYPEORM_COL_DECORATORS =
  /@(?:PrimaryGeneratedColumn|PrimaryColumn|Column|CreateDateColumn|UpdateDateColumn|DeleteDateColumn|VersionColumn)\b(?:\([^)]*\))?\s*(?:\r?\n\s*)*(\w+)\??\s*:\s*([^;\n]+)/g;

const TYPEORM_ENTITY_HEAD =
  /@Entity\s*(?:\(\s*['"](\w+)['"]\s*\))?\s*(?:export\s+)?(?:abstract\s+)?class\s+(\w+)/g;

function parseTypeORMBlock(
  content: string,
  fileRel: string,
): { models: MutableModel[]; rels: RelationEdge[] } {
  const models: MutableModel[] = [];
  const rels: RelationEdge[] = [];
  const entityMatches = [...content.matchAll(TYPEORM_ENTITY_HEAD)];
  for (let i = 0; i < entityMatches.length; i += 1) {
    const m = entityMatches[i];
    if (m === undefined) {
      continue;
    }
    const cls = m[2] ?? m[1];
    if (cls === undefined) {
      continue;
    }
    const start = m.index;
    const next = entityMatches[i + 1];
    const end = next?.index ?? content.length;
    const entitySlice = content.slice(start, end);
    const fields: { name: string; typeToken: string }[] = [];
    const colRe = new RegExp(TYPEORM_COL_DECORATORS.source, 'g');
    for (const col of entitySlice.matchAll(colRe)) {
      if (col[1] !== undefined && col[2] !== undefined) {
        fields.push({ name: col[1].trim(), typeToken: col[2].trim().slice(0, 48) });
      }
    }
    for (const fk of entitySlice.matchAll(/@ManyToOne\(\s*\(\)\s*=>\s*(\w+)/g)) {
      const target = fk[1];
      if (target !== undefined) {
        pushRelation(rels, cls, target, 'N:1');
      }
    }
    models.push({ name: cls, source: 'typeorm', fields: fields.slice(0, 24) });
  }
  if (models.length === 0 && /@Entity\b/.test(content)) {
    models.push({
      name: fileRel.replace(/\.[^.]+$/u, '').replaceAll(/[^A-Za-z0-9]+/gu, '_').toUpperCase(),
      source: 'typeorm',
      fields: [],
    });
  }
  return { models, rels };
}

function extractMongooseSchemaObjectLiteral(content: string): string | undefined {
  const idx = content.search(/(?:mongoose\.)?Schema\s*\(\s*\{/iu);
  if (idx < 0) {
    return undefined;
  }
  const braceIdx = content.indexOf('{', idx);
  if (braceIdx < 0) {
    return undefined;
  }
  let depth = 1;
  let i = braceIdx + 1;
  while (i < content.length && depth > 0) {
    const c = content[i];
    if (c === '{') {
      depth += 1;
    } else if (c === '}') {
      depth -= 1;
    }
    i += 1;
  }
  return content.slice(braceIdx + 1, i - 1);
}

function parseMongooseSchema(content: string, fileRel: string): { models: MutableModel[]; rels: RelationEdge[] } {
  const models: MutableModel[] = [];
  const rels: RelationEdge[] = [];
  if (!/mongoose\.(Schema|model)|new\s+Schema\s*\(|mongoose\.model\s*\(/iu.test(content)) {
    return { models, rels };
  }

  let schemaName = '';
  const varM = content.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:new\s+)?(?:mongoose\.)?Schema\s*\(/iu);
  if (varM?.[1] !== undefined) {
    schemaName = varM[1].replace(/Schema$/iu, '');
  }
  if (schemaName.length === 0) {
    const tail = fileRel.split('/').pop() ?? '';
    schemaName = tail.replace(/\.[^.]+$/u, '').replace(/\.schema$/iu, '') || 'Document';
  }
  schemaName = schemaName.replace(/[^A-Za-z0-9]+/gu, '');
  if (schemaName.length === 0) {
    schemaName = 'Document';
  }
  schemaName = schemaName.charAt(0).toUpperCase() + schemaName.slice(1);

  const body = extractMongooseSchemaObjectLiteral(content);
  const fields: { name: string; typeToken: string }[] = [];

  if (body === undefined) {
    const stub: MutableModel = { name: schemaName, source: 'mongoose', fields: [] };
    for (const ref of content.matchAll(/ref\s*:\s*['"](\w+)['"]/gu)) {
      const to = ref[1];
      if (to !== undefined) {
        pushRelation(rels, schemaName, to, 'N:1');
      }
    }
    return { models: [stub], rels };
  }

  for (const m of body.matchAll(/(\w+)\s*:\s*\{[\s\S]*?ref\s*:\s*['"](\w+)['"][\s\S]*?\}/gu)) {
    if (m[1] !== undefined && m[2] !== undefined) {
      fields.push({ name: m[1], typeToken: 'ObjectId(ref)' });
      pushRelation(rels, schemaName, m[2], 'N:1');
    }
  }
  for (const m of body.matchAll(/(\w+)\s*:\s*\[[\s\S]*?ref\s*:\s*['"](\w+)['"][\s\S]*?\]/gu)) {
    if (m[1] !== undefined && m[2] !== undefined) {
      fields.push({ name: m[1], typeToken: 'ObjectId[](ref)' });
      pushRelation(rels, schemaName, m[2], '1:N');
    }
  }
  for (const m of body.matchAll(/(\w+)\s*:\s*(String|Boolean|Number|Date|Buffer|ObjectId|Schema\.Types\.\w+)\b/gu)) {
    if (m[1] !== undefined && m[2] !== undefined) {
      fields.push({ name: m[1], typeToken: m[2] });
    }
  }

  const fmap = new Map<string, { name: string; typeToken: string }>();
  for (const f of fields) {
    const prev = fmap.get(f.name);
    if (prev === undefined || f.typeToken.length > prev.typeToken.length) {
      fmap.set(f.name, f);
    }
  }
  const mergedFields = [...fmap.values()].slice(0, 40);

  for (const ref of body.matchAll(/ref\s*:\s*['"](\w+)['"]/gu)) {
    const to = ref[1];
    if (to !== undefined && !rels.some((r) => r.from === schemaName && r.to === to)) {
      pushRelation(rels, schemaName, to, 'N:1');
    }
  }

  models.push({ name: schemaName, source: 'mongoose', fields: mergedFields });
  return { models, rels };
}

/**
 * Parses NestJS class-based Mongoose schemas (@Schema / @Prop from @nestjs/mongoose).
 * Traditional `new Schema({})` is handled by parseMongooseSchema above.
 */
function parseNestjsMongooseSchema(content: string, fileRel: string): { models: MutableModel[]; rels: RelationEdge[] } {
  const models: MutableModel[] = [];
  const rels: RelationEdge[] = [];

  const isNestMongoose =
    /@nestjs\/mongoose/.test(content) ||
    /SchemaFactory\.createForClass/.test(content) ||
    (/@Schema\s*\(/.test(content) && /@Prop\s*\(/.test(content));
  if (!isNestMongoose) {
    return { models, rels };
  }

  const classRe = /@Schema\s*\([^)]*\)\s*(?:export\s+)?(?:abstract\s+)?class\s+(\w+)/g;
  for (const m of content.matchAll(classRe)) {
    const className = m[1];
    if (className === undefined || className.length === 0) {
      continue;
    }

    // `RegExpMatchArray#index` is guaranteed by the TS lib types for `matchAll()` here.
    const searchFrom = m.index + m[0].length;
    const braceIdx = content.indexOf('{', searchFrom);
    if (braceIdx < 0) {
      continue;
    }
    let depth = 1;
    let i = braceIdx + 1;
    while (i < content.length && depth > 0) {
      const ch = content[i];
      if (ch === '{') {
        depth += 1;
      } else if (ch === '}') {
        depth -= 1;
      }
      i += 1;
    }
    const classBody = content.slice(braceIdx + 1, i - 1);

    const fields: { name: string; typeToken: string }[] = [];

    const propRe = /@Prop\s*\(([^)]*)\)\s+(?:readonly\s+)?(\w+)\??\s*:\s*([^\n;]+)/g;
    for (const p of classBody.matchAll(propRe)) {
      const propOptions = p[1] ?? '';
      const propName = p[2];
      const rawType = (p[3] ?? '').trim();
      const propType = rawType.split(/\s*[;/]/u)[0]?.trim() ?? rawType;
      if (propName === undefined) {
        continue;
      }

      fields.push({ name: propName, typeToken: propType.slice(0, 48) });

      const refM = /ref\s*:\s*['"](\w+)['"]/iu.exec(propOptions);
      if (refM?.[1] !== undefined) {
        const isArray = /\[/.test(propOptions) || /\[\]/.test(propType);
        pushRelation(rels, className, refM[1], isArray ? '1:N' : 'N:1');
      }
    }

    if (models.length === 0 && fields.length === 0) {
      const fallback = fileRel.split('/').pop()?.replace(/\.schema\.[^.]+$/iu, '').replace(/[^A-Za-z0-9]/gu, '') ?? '';
      const name = fallback.length > 0 ? fallback.charAt(0).toUpperCase() + fallback.slice(1) : className;
      models.push({ name, source: 'mongoose', fields: [] });
      continue;
    }

    models.push({ name: className, source: 'mongoose', fields: fields.slice(0, 40) });
  }

  return { models, rels };
}

function extractParenBody(text: string, openParenIdx: number): string {
  let depth = 1;
  let i = openParenIdx + 1;
  while (i < text.length && depth > 0) {
    const ch = text[i];
    if (ch === '(') {
      depth += 1;
    } else if (ch === ')') {
      depth -= 1;
    }
    i += 1;
  }
  return text.slice(openParenIdx + 1, i - 1);
}

/** CREATE TABLE + REFERENCES / FOREIGN KEY — line-oriented, tolerates multi-line DDL. */
function parseSqlDdl(text: string): { models: MutableModel[]; rels: RelationEdge[]; hints: string[] } {
  const models: MutableModel[] = [];
  const rels: RelationEdge[] = [];
  const hints: string[] = [];
  const createRe = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"']?(\w+)[`"']?\s*\(/giu;
  let m: RegExpExecArray | null;
  while ((m = createRe.exec(text)) !== null) {
    const table = m[1];
    if (table === undefined) {
      continue;
    }
    const openParen = text.indexOf('(', m.index);
    if (openParen < 0) {
      continue;
    }
    const body = extractParenBody(text, openParen);
    const cols: { name: string; typeToken: string }[] = [];
    for (const line of body.split(/\r?\n/u)) {
      const t = line.trim();
      if (t.length === 0 || t.startsWith('--')) {
        continue;
      }
      const fk =
        /FOREIGN\s+KEY\s*\(\s*(\w+)\s*\)\s*REFERENCES\s+[`"']?(\w+)[`"']?\s*\(\s*[`"']?(\w+)[`"']?\s*\)/giu.exec(
          t,
        );
      if (fk?.[2] !== undefined) {
        pushRelation(rels, table, fk[2], 'N:1');
        continue;
      }
      const ref = /[`"']?(\w+)[`"']?\s+[^,]+REFERENCES\s+[`"']?(\w+)[`"']?\s*\(\s*[`"']?(\w+)[`"']?\s*\)/giu.exec(t);
      if (ref?.[2] !== undefined) {
        pushRelation(rels, table, ref[2], 'N:1');
      }
      const col = /^[`"']?(\w+)[`"']?\s+(\S+)/u.exec(t);
      if (
        col?.[1] !== undefined &&
        col[2] !== undefined &&
        !/^(PRIMARY|FOREIGN|UNIQUE|CONSTRAINT|KEY|CHECK|INDEX)/iu.test(col[1])
      ) {
        cols.push({ name: col[1], typeToken: col[2].replace(/,$/u, '').slice(0, 48) });
      }
    }
    models.push({ name: table, source: 'sql', fields: cols.slice(0, 32) });
  }
  if (/CREATE\s+INDEX/iu.test(text)) {
    hints.push('SQL: CREATE INDEX detected — align with hot query paths in services.');
  }
  return { models, rels, hints };
}

async function collectPrismaMigrationSql(cwd: string): Promise<string[]> {
  const out: string[] = [];
  try {
    const root = join(cwd, 'prisma', 'migrations');
    const entries = await readdir(root, { withFileTypes: true });
    for (const e of entries) {
      if (!e.isDirectory()) {
        continue;
      }
      try {
        const sql = await readFile(join(root, e.name, 'migration.sql'), 'utf8');
        out.push(sql);
      } catch {
        /* migration.sql missing */
      }
    }
  } catch {
    /* no prisma/migrations */
  }
  return out;
}

function inventoryStubFromFile(f: InventoryFile): MutableModel {
  const base =
    f.relPath
      .split('/')
      .pop()
      ?.replace(/\.[^.]+$/u, '')
      .replace(/[^A-Za-z0-9]+/gu, '_')
      .toUpperCase() ?? 'ENTITY';
  return { name: base, source: 'inventory', fields: [] };
}

function sourceRank(source: MutableModel['source']): number {
  if (source === 'prisma') {
    return 5;
  }
  if (source === 'typeorm') {
    return 4;
  }
  if (source === 'sql') {
    return 3;
  }
  if (source === 'mongoose') {
    return 2;
  }
  return 1;
}

/** Collapse inventory filename stubs into richer Prisma/TypeORM rows with the same business key. */
function canonicalModelKey(name: string): string {
  let n = name.trim();
  n = n.replace(/_ENTITY$/iu, '').replace(/Entity$/u, '');
  return n.replace(/[_-]+/gu, '').toLowerCase();
}

function fieldQualityScore(m: MutableModel): number {
  return m.fields.filter((f) => f.typeToken.length > 0 && f.typeToken !== 'unknown').length;
}

function mergeModelsPreferringRicher(
  models: readonly MutableModel[],
): { merged: MutableModel[]; rename: ReadonlyMap<string, string> } {
  const buckets = new Map<string, MutableModel[]>();
  for (const m of models) {
    const k = canonicalModelKey(m.name);
    const list = buckets.get(k) ?? [];
    list.push(m);
    buckets.set(k, list);
  }
  const rename = new Map<string, string>();
  const merged: MutableModel[] = [];
  for (const [, group] of buckets) {
    const sorted = [...group].sort((a, b) => {
      const fq = fieldQualityScore(b) - fieldQualityScore(a);
      if (fq !== 0) {
        return fq;
      }
      return sourceRank(b.source) - sourceRank(a.source);
    });
    const best = sorted[0];
    if (best === undefined) {
      continue;
    }
    merged.push(best);
    for (const m of sorted) {
      if (m.name !== best.name) {
        rename.set(m.name, best.name);
      }
    }
  }
  merged.sort((a, b) => a.name.localeCompare(b.name));
  return { merged, rename };
}

function remapRelationEndpoints(
  rels: readonly RelationEdge[],
  rename: ReadonlyMap<string, string>,
): RelationEdge[] {
  const out: RelationEdge[] = [];
  for (const r of rels) {
    const from = rename.get(r.from) ?? r.from;
    const to = rename.get(r.to) ?? r.to;
    if (from === to) {
      continue;
    }
    pushRelation(out, from, to, r.cardinality);
  }
  return out;
}

/**
 * Workspace-level database/schema intelligence for ER diagrams and architecture maps.
 */
export async function extractDatabaseIntelligence(
  cwd: string,
  inventoryFiles: readonly InventoryFile[],
  ormSignals: readonly string[],
): Promise<DatabaseIntelligence> {
  const sources = new Set<DatabaseIntelligence['sources'][number]>();
  const models: MutableModel[] = [];
  const relations: RelationEdge[] = [];
  const indexingHints: string[] = [];

  const prismaPath = join(cwd, 'prisma', 'schema.prisma');
  try {
    const prismaText = await readFile(prismaPath, 'utf8');
    sources.add('prisma');
    const parsed = parsePrismaSchema(prismaText);
    models.push(...parsed.models);
    indexingHints.push(...parsed.hints);
    for (const r of parsed.relations) {
      pushRelation(relations, r.from, r.to, r.cardinality);
    }
  } catch {
    /* no prisma schema */
  }

  const migrationSqlTexts = await collectPrismaMigrationSql(cwd);
  for (const sql of migrationSqlTexts) {
    sources.add('sql');
    const p = parseSqlDdl(sql);
    models.push(...p.models);
    for (const r of p.rels) {
      pushRelation(relations, r.from, r.to, r.cardinality);
    }
    indexingHints.push(...p.hints);
  }

  if (ormSignals.includes('typeorm')) {
    sources.add('typeorm');
  }
  if (ormSignals.includes('mongoose')) {
    sources.add('mongoose');
  }

  for (const f of inventoryFiles) {
    const rel = f.relPath.replaceAll('\\', '/').toLowerCase();
    if (rel.endsWith('.sql')) {
      try {
        const sql = await readFile(normalize(join(cwd, f.relPath)), 'utf8');
        sources.add('sql');
        const p = parseSqlDdl(sql);
        models.push(...p.models);
        for (const r of p.rels) {
          pushRelation(relations, r.from, r.to, r.cardinality);
        }
        indexingHints.push(...p.hints);
      } catch {
        /* unreadable */
      }
    }
  }

  for (const f of inventoryFiles) {
    if (f.kind !== 'entity' && f.kind !== 'schema') {
      continue;
    }
    try {
      const text = await readFile(normalize(join(cwd, f.relPath)), 'utf8');
      if (ormSignals.includes('typeorm') || /@Entity\b/u.test(text)) {
        const parsed = parseTypeORMBlock(text, f.relPath);
        models.push(...parsed.models);
        for (const r of parsed.rels) {
          pushRelation(relations, r.from, r.to, r.cardinality);
        }
      }
      const mg = parseMongooseSchema(text, f.relPath);
      models.push(...mg.models);
      for (const r of mg.rels) {
        pushRelation(relations, r.from, r.to, r.cardinality);
      }
      const nmg = parseNestjsMongooseSchema(text, f.relPath);
      models.push(...nmg.models);
      for (const r of nmg.rels) {
        pushRelation(relations, r.from, r.to, r.cardinality);
      }
    } catch {
      sources.add('inventory');
      models.push(inventoryStubFromFile(f));
    }
  }

  if (indexingHints.length === 0 && models.length > 0) {
    indexingHints.push('No @@index / SQL index hints parsed — review large filter columns and FKs in migrations.');
  }

  const seenName = new Map<string, MutableModel>();
  for (const m of models) {
    const k = `${m.source}:${m.name}`;
    const prev = seenName.get(k);
    if (prev === undefined) {
      seenName.set(k, m);
      continue;
    }
    const mergedFields = [...prev.fields];
    for (const f of m.fields) {
      if (!mergedFields.some((x) => x.name === f.name)) {
        mergedFields.push(f);
      }
    }
    seenName.set(k, { ...prev, fields: mergedFields.slice(0, 40) });
  }
  const uniq = [...seenName.values()];

  const { merged, rename } = mergeModelsPreferringRicher(uniq);
  const mergedRels = remapRelationEndpoints(relations, rename);

  return {
    sources: [...sources],
    models: merged.slice(0, 48).map((m) => ({ ...m, fields: [...m.fields] })),
    relations: mergedRels.slice(0, 80) as DatabaseIntelligence['relations'],
    indexingHints: indexingHints.slice(0, 24),
  };
}
