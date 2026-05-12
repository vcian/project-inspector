import { stdout } from 'node:process';
import pino from 'pino';

const VALID_LEVELS = ['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent'] as const;
type LogLevel = (typeof VALID_LEVELS)[number];

function isValidLevel(raw: string): raw is LogLevel {
  return (VALID_LEVELS as readonly string[]).includes(raw);
}

const isTTY = stdout.isTTY;
const rawLevel = process.env['LOG_LEVEL'] ?? 'info';

if (!isValidLevel(rawLevel)) {
  process.stderr.write(`[project-inspector] Invalid LOG_LEVEL "${rawLevel}", using "info"\n`);
}

const level: LogLevel = isValidLevel(rawLevel) ? rawLevel : 'info';
const usePretty = isTTY && process.env['NODE_ENV'] !== 'test';

export const logger = pino({
  level,
  ...(usePretty
    ? {
        transport: {
          target: 'pino-pretty',
          options: { colorize: true, translateTime: 'SYS:standard' },
        },
      }
    : {}),
});
