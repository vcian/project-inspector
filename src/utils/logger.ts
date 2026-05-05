import { stdout } from 'node:process';
import pino from 'pino';

const isTTY = stdout.isTTY;

const usePretty = isTTY && process.env.NODE_ENV !== 'test';

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  ...(usePretty
    ? {
        transport: {
          target: 'pino-pretty',
          options: { colorize: true, translateTime: 'SYS:standard' },
        },
      }
    : {}),
});
