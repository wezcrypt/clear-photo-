import { z } from 'zod';

const hex32 = z.string().regex(/^[0-9a-f]{64}$/i, 'must be 64 hex characters (32 bytes)');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  DATABASE_URL: z.string().min(1),
  MAIL_DOMAIN: z.string().min(3).default('voidmail.test'),
  PUBLIC_ORIGIN: z.string().url().default('http://localhost:8080'),
  HTTP_HOST: z.string().default('127.0.0.1'),
  HTTP_PORT: z.coerce.number().int().default(8080),
  TRUST_PROXY: z.enum(['true', 'false']).default('false'),
  APP_SECRET: hex32,
  AUTH_PEPPER: hex32,
  QUEUE_KEY: hex32,
  TOTP_KEY: hex32,
  BLOB_DIR: z.string().default('./data/blobs'),
  WEB_DIST: z.string().default('./dist/web'),
  LMTP_HOST: z.string().default('0.0.0.0'),
  LMTP_PORT: z.coerce.number().int().default(2424),
  LOOKUP_PORT: z.coerce.number().int().default(2425),
  SMTP_RELAY_HOST: z.string().default('127.0.0.1'),
  SMTP_RELAY_PORT: z.coerce.number().int().default(10025),
  DKIM_SELECTOR: z.string().default('vm1'),
  DKIM_PRIVATE_KEY_FILE: z.string().optional(),
  MAX_MESSAGE_BYTES: z.coerce.number().int().default(25 * 1024 * 1024),
  MAX_RECIPIENTS_PER_MESSAGE: z.coerce.number().int().default(50),
  EXTERNAL_RECIPIENTS_PER_DAY: z.coerce.number().int().default(200),
  INTERNAL_RECIPIENTS_PER_DAY: z.coerce.number().int().default(2000),
  SENDS_PER_MINUTE: z.coerce.number().int().default(10),
  DEFAULT_QUOTA_BYTES: z.coerce.number().int().default(1024 * 1024 * 1024),
  REGISTRATION_OPEN: z.enum(['true', 'false']).default('true'),
  // Server-side Argon2id cost for verifying the (already Argon2id-derived) authKey.
  ARGON2_MEMORY_KIB: z.coerce.number().int().default(19456),
  ARGON2_TIME: z.coerce.number().int().default(2),
  // Client KDF parameters issued to new accounts. Lower only for tests.
  CLIENT_KDF_M: z.coerce.number().int().default(65536),
  CLIENT_KDF_T: z.coerce.number().int().default(3),
  TRASH_RETENTION_DAYS: z.coerce.number().int().default(30),
  SECURITY_EVENT_RETENTION_DAYS: z.coerce.number().int().default(30),
  // Username that receives postmaster@ and abuse@ mail (required by RFC 5321 in production).
  POSTMASTER_USER: z.string().optional(),
  RATE_LIMIT_MULTIPLIER: z.coerce.number().positive().default(1),
});

export type Config = z.infer<typeof schema> & {
  secure: boolean;
  keys: { app: Buffer; pepper: Buffer; queue: Buffer; totp: Buffer };
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n  ');
    throw new Error(`Invalid configuration:\n  ${issues}`);
  }
  const c = parsed.data;
  const keys = {
    app: Buffer.from(c.APP_SECRET, 'hex'),
    pepper: Buffer.from(c.AUTH_PEPPER, 'hex'),
    queue: Buffer.from(c.QUEUE_KEY, 'hex'),
    totp: Buffer.from(c.TOTP_KEY, 'hex'),
  };
  const distinct = new Set([c.APP_SECRET, c.AUTH_PEPPER, c.QUEUE_KEY, c.TOTP_KEY].map((s) => s.toLowerCase()));
  if (distinct.size !== 4) throw new Error('APP_SECRET, AUTH_PEPPER, QUEUE_KEY and TOTP_KEY must all differ');
  if (c.NODE_ENV === 'production' && !c.PUBLIC_ORIGIN.startsWith('https://')) {
    throw new Error('PUBLIC_ORIGIN must be https:// in production');
  }
  return { ...c, secure: c.PUBLIC_ORIGIN.startsWith('https://'), keys };
}
