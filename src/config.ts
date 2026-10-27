import { z } from 'zod';

const interval = z.number().int().min(60);

const positive = z.number().positive();

const httpsUrl = z.url().refine((s) => new URL(s).protocol === 'https:', 'HTTPS required');

const sourceSchema = z.object({
  id: z.string().regex(/^[a-z0-9_-]+$/),
  kind: z.enum(['rss', 'kev', 'nvd']),
  url: httpsUrl,
  enabled: z.boolean().default(true),
  pollIntervalSeconds: interval,
  articleHosts: z.array(z.string()).default([]),
  apiKeySecret: z.string().optional(),
});

const targetSchema = z.object({
  id: z.string().regex(/^[a-z0-9_-]+$/),
  provider: z.literal('misskey').default('misskey'),
  enabled: z.boolean().default(false),
  baseUrl: httpsUrl,
  tokenSecret: z.string().regex(/^[A-Z][A-Z0-9_]*$/),
  qualityGate: z.object({ enabled: z.boolean().default(true) }).default({ enabled: true }),
  maxCharacters: z.number().int().min(200).max(10000).default(500),
  normalIntervalSeconds: interval.default(3600),
  urgentIntervalSeconds: interval.default(300),
  minimumIntervalSeconds: interval.default(300),
  normalDailyLimit: z.number().int().nonnegative().default(10),
  urgentDailyLimit: z.number().int().nonnegative().default(10),
  visibility: z.enum(['public', 'home', 'followers']).default('public'),
});

const presets = {
  free: { maxCalls: 20, concurrency: 1, neurons: 8000 },
  balanced: { maxCalls: 100, concurrency: 2, neurons: 30000 },
  performance: { maxCalls: 500, concurrency: 5, neurons: 100000 },
} as const;

const modeSchema = z.enum(['free', 'balanced', 'performance']);

export const configSchema = z.object({
  mode: modeSchema,
  dryRun: z.boolean(),
  pollIntervalSeconds: interval,
  sources: z.array(sourceSchema),
  targets: z.array(targetSchema),
  budget: z.object({
    maxCalls: z.number().int().positive(),
    concurrency: z.number().int().min(1).max(20),
    neurons: positive,
    queueOperations: z.number().int().positive().default(8000),
  }),
  llm: z.object({
    model: z.string().min(1),
    maxInputCharacters: z.number().int().min(1000).max(24000),
    maxOutputTokens: z.number().int().min(256).max(4096),
    inputNeuronsPerMillion: positive,
    outputNeuronsPerMillion: positive,
  }),
  freshnessSeconds: positive,
  initialLookbackSeconds: positive,
  retentionDays: z.number().int().positive(),
});

export type Config = z.infer<typeof configSchema>;
export type SourceConfig = Config['sources'][number];
export type TargetConfig = Config['targets'][number];
export type Environment = Record<string, unknown>;

function booleanEnv(value: unknown, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }
  throw new Error('Boolean environment value must be true or false');
}

/** ファイル設定と環境変数を検証し、既定値を補った実行設定を返す。 */
export function loadConfig(input: unknown = {}, env: Environment = {}): Config {
  const raw = z.record(z.string(), z.unknown()).parse(input);
  const mode = modeSchema.parse(env.BOT_MODE ?? raw.mode ?? 'free');
  const poll = interval.parse(
    env.POLL_INTERVAL_SECONDS === undefined ? (raw.pollIntervalSeconds ?? 900) : Number(env.POLL_INTERVAL_SECONDS),
  );
  const defaults = [
    {
      id: 'jvn',
      kind: 'rss',
      url: 'https://jvn.jp/rss/jvn.rdf',
      articleHosts: ['jvn.jp'],
    },
    {
      id: 'jpcert',
      kind: 'rss',
      url: 'https://www.jpcert.or.jp/rss/jpcert.rdf',
      articleHosts: ['www.jpcert.or.jp'],
    },
    {
      id: 'kev',
      kind: 'kev',
      url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    },
    {
      id: 'nvd',
      kind: 'nvd',
      url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      pollIntervalSeconds: 7200,
      apiKeySecret: 'NVD_API_KEY',
    },
  ];

  const budgetRaw = z.record(z.string(), z.unknown()).parse(raw.budget ?? {});
  const llmRaw = z.record(z.string(), z.unknown()).parse(raw.llm ?? {});
  const model = env.LLM_MODEL ?? llmRaw.model ?? '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
  if (
    model !== '@cf/meta/llama-3.3-70b-instruct-fp8-fast' &&
    (llmRaw.inputNeuronsPerMillion === undefined || llmRaw.outputNeuronsPerMillion === undefined)
  ) {
    throw new Error('Custom model requires explicit neuron pricing coefficients');
  }

  const sourceRaw = z.array(z.record(z.string(), z.unknown())).parse(raw.sources ?? defaults);
  const config = configSchema.parse({
    mode,
    dryRun: booleanEnv(env.DRY_RUN, z.boolean().parse(raw.dryRun ?? true)),
    pollIntervalSeconds: poll,
    sources: sourceRaw.map((s) => ({
      ...s,
      pollIntervalSeconds: s.pollIntervalSeconds ?? poll,
    })),
    targets: raw.targets ?? [],
    budget: {
      ...presets[mode],
      ...budgetRaw,
      ...(env.LLM_MAX_CALLS === undefined ? {} : { maxCalls: Number(env.LLM_MAX_CALLS) }),
      ...(env.LLM_NEURON_BUDGET === undefined ? {} : { neurons: Number(env.LLM_NEURON_BUDGET) }),
    },
    llm: {
      maxInputCharacters: 16000,
      maxOutputTokens: 1024,
      inputNeuronsPerMillion: 26668,
      outputNeuronsPerMillion: 204805,
      ...llmRaw,
      model,
    },
    freshnessSeconds: raw.freshnessSeconds ?? 259200,
    initialLookbackSeconds: raw.initialLookbackSeconds ?? 86400,
    retentionDays: raw.retentionDays ?? 90,
  });

  for (const entries of [config.sources, config.targets]) {
    if (new Set(entries.map((s) => s.id)).size !== entries.length) {
      throw new Error('Duplicate source or target id');
    }
  }

  return config;
}
