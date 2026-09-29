import type { Config } from './config.js';

/** Per-IP rate limit config for @fastify/rate-limit. The multiplier exists only for automated tests. */
export function rl(cfg: Config, max: number, timeWindow: string) {
  return { max: Math.max(1, Math.round(max * cfg.RATE_LIMIT_MULTIPLIER)), timeWindow };
}
