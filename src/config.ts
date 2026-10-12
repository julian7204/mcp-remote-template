import { z } from 'zod';

const ConfigSchema = z.object({
  PUBLIC_URL: z
    .string()
    .url()
    .transform((value) => value.replace(/\/+$/, '')),
  PORT: z.coerce.number().int().positive().default(3000),
  OWNER_PASSWORD: z.string().min(12, 'OWNER_PASSWORD must be at least 12 characters'),
  ACCESS_TOKEN_TTL: z.coerce.number().int().positive().default(3600),
  REFRESH_TOKEN_TTL: z.coerce
    .number()
    .int()
    .positive()
    .default(60 * 60 * 24 * 30),
  TRUST_PROXY: z
    .enum(['0', '1', 'true', 'false'])
    .default('0')
    .transform((value) => value === '1' || value === 'true'),
});

export type Config = z.infer<typeof ConfigSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = ConfigSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`);
    throw new Error(`Invalid configuration:\n${issues.join('\n')}`);
  }
  return parsed.data;
}
