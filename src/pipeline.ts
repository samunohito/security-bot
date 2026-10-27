import { z } from 'zod';
import type { Config, Environment, SourceConfig, TargetConfig } from './config';
import { classify, digest, type PostIntent, type Summary, type Validation } from './domain';
import { HttpError } from './http';
import {
  SUMMARY_SYSTEM,
  VERIFY_SYSTEM,
  WorkersAiProvider,
  type AiBinding,
  type LlmProvider,
  type LlmRequest,
} from './llm';
import { summarySchema, validateSummary, validateVerdict, verdictSchema } from './quality';
import { MisskeyProvider, PublishError, type PreparedPost, type SocialProvider } from './social';
import { sourceProvider, type SourceProvider } from './sources';
import { Store, type Job, type Revision } from './store';

export interface BotEnv extends Environment {
  DB: D1Database;
  JOBS: { send(body: { id: string }): Promise<unknown> };
  AI?: AiBinding;
}
export interface Providers {
  llm?: LlmProvider;
  source?: (config: SourceConfig) => SourceProvider;
  social?: (target: TargetConfig) => SocialProvider;
}
class Deferred extends Error {
  constructor(
    public until: number,
    reason: string,
  ) {
    super(reason);
  }
}
const tomorrowUtc = (now: number) => Math.floor(now / 86400000) * 86400000 + 86400000;

export class Bot {
  readonly store: Store;
  private llm: LlmProvider | undefined;
  constructor(
    public env: BotEnv,
    public config: Config,
    public providers: Providers = {},
  ) {
    this.store = new Store(env.DB);
    this.llm = providers.llm ?? (env.AI ? new WorkersAiProvider(env.AI, config.llm) : undefined);
  }
  private async analyzeKey(revisionId: string, evidenceHash: string) {
    const policy = await digest(
      JSON.stringify({
        targets: this.config.targets,
        dryRun: this.config.dryRun,
        model: this.config.llm.model,
      }),
    );
    return `analyze:${revisionId}:${evidenceHash}:${policy}`;
  }
  async tick(now = Date.now()) {
    await this.store.bootstrapTime(now);
    await this.store.recover(now);
    await this.store.syncTargets(this.config.targets);
    await this.store.syncSources(this.config.sources, now);
    for (const revision of await this.store.currentRevisions())
      await this.store.enqueue(
        await this.analyzeKey(revision.id, revision.evidence_hash),
        'analyze',
        { revisionId: revision.id },
        now,
      );
    for (const delivery of await this.store.dueDeliveries(now))
      await this.store.enqueue(
        `publish:${delivery.id}:${delivery.available_at}`,
        'publish',
        { deliveryId: delivery.id },
        now,
      );
    await this.flush(now);
    await this.store.cleanup(now, this.config.retentionDays);
  }
  async flush(now: number) {
    for (const job of await this.store.outbox(now)) {
      if (!(await this.store.reserveQueueOperations(now, this.config.budget.queueOperations))) break;
      try {
        await this.env.JOBS.send({ id: job.id });
        await this.store.markDispatched(job.id, now);
      } catch {
        console.warn(JSON.stringify({ event: 'queue_enqueue_failed', job: job.id }));
        break;
      }
    }
  }
  async preview(id: string) {
    const revision = await this.store.getRevision(id);
    if (!revision) throw new Error('revision_not_found');
    const cached = await this.store.getSummary(revision);
    if (!cached) throw new Error('verified_summary_not_available');
    const results = [];
    for (const target of this.config.targets) {
      const intent: PostIntent = {
        kind: revision.kind,
        key: revision.threat_key,
        title: revision.snapshot.title,
        severity: classify(revision.snapshot).severity,
        summary: cached.summary,
        sources: [...new Set(revision.snapshot.evidence.map((e) => e.url))].slice(0, 2),
        previousPost: await this.store.previousPost(target.id, revision.threat_key),
      };
      const provider = this.providers.social?.(target) ?? new MisskeyProvider(target, '');
      try {
        results.push({
          targetId: target.id,
          allowed: cached.validation.valid && (!target.qualityGate.enabled || cached.validation.complete),
          ...provider.prepare(intent),
          reasons: cached.validation.reasons,
        });
      } catch (error) {
        results.push({
          targetId: target.id,
          allowed: false,
          error: error instanceof Error ? error.message : 'format_error',
        });
      }
    }
    return results;
  }
  async runJob(id: string, now = Date.now()) {
    const job = await this.store.claimJob(id, now);
    if (!job) return;
    try {
      const payload: unknown = JSON.parse(job.payload);
      if (job.type === 'collect')
        await this.collect(job, z.object({ sourceId: z.string() }).parse(payload).sourceId, now);
      else if (job.type === 'ingest') {
        const parsed = z.object({ sourceId: z.string(), item: z.unknown() }).parse(payload);
        const config = this.config.sources.find((s) => s.id === parsed.sourceId && s.enabled);
        if (config) {
          const provider =
            this.providers.source?.(config) ??
            sourceProvider(config, this.env, undefined, {
              initialLookbackSeconds: this.config.initialLookbackSeconds,
            });
          const item = parsed.item as Parameters<Store['ingest']>[0];
          const hydrated = provider.hydrate ? await provider.hydrate(item) : item;
          for (const revisionId of await this.store.ingest(hydrated, now)) {
            const revision = await this.store.getRevision(revisionId);
            if (revision)
              await this.store.enqueue(
                await this.analyzeKey(revision.id, revision.evidence_hash),
                'analyze',
                { revisionId },
                now,
              );
          }
        }
      } else if (job.type === 'analyze')
        await this.analyze(z.object({ revisionId: z.string() }).parse(payload).revisionId, now);
      else if (job.type === 'publish')
        await this.publish(z.object({ deliveryId: z.string() }).parse(payload).deliveryId, now);
      else throw new Error('unknown_job_type');
      await this.store.finishJob(job);
    } catch (error) {
      const reason = error instanceof Error ? error.message.slice(0, 300) : 'unknown_error';
      if (error instanceof Deferred) await this.store.failJob(job, 'deferred', reason, error.until);
      else {
        const retry =
          error instanceof HttpError
            ? error.retryable
            : error instanceof TypeError ||
              /network|fetch failed|temporarily|timeout|threat_concurrency_retry/i.test(reason);
        const state = retry && job.attempts < 5 ? 'deferred' : 'held';
        const delay =
          error instanceof HttpError
            ? Math.max(error.retryAfterMs, 60000 * 2 ** Math.min(job.attempts - 1, 6))
            : 60000 * 2 ** Math.min(job.attempts - 1, 6);
        await this.store.failJob(job, state, reason, now + delay);
        if (job.type === 'collect') {
          const p = JSON.parse(job.payload) as { sourceId: string };
          await this.store.sourceError(p.sourceId, reason, false, now, job);
        }
        console.warn(JSON.stringify({ event: 'job_held_or_deferred', id, state, reason }));
      }
    }
  }
  private async collect(job: Job, id: string, now: number) {
    const source = this.config.sources.find((s) => s.id === id && s.enabled);
    const state = await this.store.sourceState(id);
    if (!state || state.active_job !== job.id) return;
    if (!source) {
      await this.store.sourceError(id, 'source_disabled', true, now, job);
      return;
    }
    const cursor = await this.store.sourceCursor(id);
    const batch = await (
      this.providers.source?.(source) ??
      sourceProvider(source, this.env, undefined, {
        initialLookbackSeconds: this.config.initialLookbackSeconds,
      })
    ).collect(cursor, now);
    for (const item of batch.items) {
      const hash = await digest(JSON.stringify({ ...item, fetchedAt: 0 }));
      await this.store.enqueue(`ingest:${source.id}:${hash}`, 'ingest', { sourceId: source.id, item }, now);
    }
    const continuation = batch.more
      ? {
          id: `collect:${id}:${await digest(JSON.stringify(batch.cursor))}`,
          payload: { sourceId: id },
        }
      : undefined;
    await this.store.completeSource(id, batch.cursor, now + source.pollIntervalSeconds * 1000, now, continuation, job);
  }
  private promptEvidence(revision: Revision) {
    return {
      key: revision.threat_key,
      evidence: revision.snapshot.evidence.slice(0, 4).map((e) => ({
        id: e.evidenceId,
        scope: e.scope,
        cves: e.cves,
        url: e.url,
        text: `${e.affected ?? ''}\n${e.remediation ?? ''}\n${e.text}`.slice(0, 2200),
      })),
    };
  }
  private async generate<T>(request: LlmRequest, schema: z.ZodType<T>, now: number): Promise<T> {
    if (!this.llm) throw new Error('missing_AI_binding');
    const input = JSON.stringify(request.data) + request.system;
    if (input.length > this.config.llm.maxInputCharacters) throw new Error('resource_limit: LLM input');
    const estimate =
      ((new TextEncoder().encode(input).length + 1024) * this.config.llm.inputNeuronsPerMillion) / 1e6 +
      ((request.maxOutputTokens ?? this.config.llm.maxOutputTokens) * this.config.llm.outputNeuronsPerMillion) / 1e6;
    const id = crypto.randomUUID();
    if (!(await this.store.reserveBudget(id, now, estimate, this.config.budget))) {
      const used = await this.store.budgetStatus(now);
      const exhausted =
        (used?.calls ?? 0) >= this.config.budget.maxCalls ||
        (used?.neurons ?? 0) + estimate > this.config.budget.neurons;
      throw new Deferred(
        exhausted ? tomorrowUtc(now) : now + 60000,
        exhausted ? 'AI_daily_budget_exhausted' : 'AI_concurrency_limit',
      );
    }
    try {
      const response = await this.llm.generateStructured(request, schema);
      if (response.usage)
        await this.store.settleBudget(
          id,
          (response.usage.inputTokens * this.config.llm.inputNeuronsPerMillion) / 1e6 +
            (response.usage.outputTokens * this.config.llm.outputNeuronsPerMillion) / 1e6,
        );
      return schema.parse(response.value);
    } catch (error) {
      if (error instanceof Error && /quota|429|neurons|rate.limit/i.test(error.message))
        throw new Deferred(tomorrowUtc(now), 'AI_provider_quota');
      throw error;
    }
  }
  private async analyze(id: string, now: number) {
    const revision = await this.store.getRevision(id);
    if (!revision || !revision.eligible || !(await this.store.isCurrent(id))) return;
    const start = await this.store.bootstrapTime(now);
    if (
      revision.event_at < now - this.config.freshnessSeconds * 1000 ||
      (revision.kind === 'new' && revision.event_at < start - this.config.initialLookbackSeconds * 1000)
    )
      return;
    let cached = await this.store.getSummary(revision);
    if (!cached) {
      const summary = await this.generate(
        { system: SUMMARY_SYSTEM, data: this.promptEvidence(revision) },
        summarySchema,
        now,
      );
      const validation = validateSummary(summary, revision.snapshot.evidence, revision.threat_key);
      if (validation.valid) validation.reasons = ['verification_pending'];
      validation.valid = false;
      await this.store.saveSummary(revision, summary, validation, now);
      cached = { summary, validation };
    }
    if (cached.validation.reasons.includes('verification_pending')) {
      const verdict = await this.generate(
        {
          system: VERIFY_SYSTEM,
          data: { ...this.promptEvidence(revision), summary: cached.summary },
        },
        verdictSchema,
        now,
      );
      cached.validation = {
        ...cached.validation,
        valid: validateVerdict(verdict),
        reasons: [
          ...verdict.contradictions,
          ...verdict.unsupportedClaims,
          ...(!verdict.supported ? ['unsupported_summary'] : []),
        ],
      };
      await this.store.saveSummary(revision, cached.summary, cached.validation, now);
    }
    if (!(await this.store.isCurrent(id))) return;
    const current = await this.store.getRevision(id);
    if (current?.evidence_hash !== revision.evidence_hash) throw new Deferred(now + 60000, 'evidence_changed');
    for (const target of this.config.targets) {
      if (!target.enabled && !this.config.dryRun) continue;
      if (revision.snapshot.rejected && !(await this.store.previousPost(target.id, revision.threat_key))) continue;
      const deliveryId = await digest(`${target.id}:${id}`);
      const allowed = cached.validation.valid && (!target.qualityGate.enabled || cached.validation.complete);
      await this.store.createDelivery(
        deliveryId,
        target.id,
        id,
        Boolean(revision.urgent),
        now,
        allowed ? 'ready' : 'held',
        allowed ? null : cached.validation.reasons.join(';') || 'incomplete_information',
      );
      if (allowed) await this.store.enqueue(`publish:${deliveryId}:${now}`, 'publish', { deliveryId }, now);
    }
  }
  private async prepare(
    provider: SocialProvider,
    intent: PostIntent,
    revision: Revision,
    deliveryId: string,
    strict: boolean,
    now: number,
  ): Promise<PreparedPost> {
    try {
      return provider.prepare(intent);
    } catch (error) {
      if (!(error instanceof Error) || error.message !== 'post_too_long') throw error;
      let cached = await this.store.getShortened(deliveryId, revision.evidence_hash);
      if (!cached) {
        const shorter = await this.generate(
          {
            system:
              SUMMARY_SYSTEM +
              ' Make each Japanese field at most 45 characters. Preserve all critical version boundaries and exact supporting quotes. The template including sources must fit the target limit; do not drop safety-critical facts to fit.',
            data: {
              ...this.promptEvidence(revision),
              previousSummary: intent.summary,
            },
          },
          summarySchema,
          now,
        );
        const check = validateSummary(shorter, revision.snapshot.evidence, revision.threat_key);
        cached = {
          summary: shorter,
          validation: {
            ...check,
            valid: false,
            reasons: check.valid ? ['verification_pending'] : check.reasons,
          },
        };
        await this.store.saveShortened(deliveryId, revision.evidence_hash, cached.summary, cached.validation);
      }
      if (cached.validation.reasons.includes('verification_pending')) {
        const verdict = await this.generate(
          {
            system: VERIFY_SYSTEM,
            data: { ...this.promptEvidence(revision), summary: cached.summary },
          },
          verdictSchema,
          now,
        );
        cached.validation = {
          ...cached.validation,
          valid: validateVerdict(verdict),
          reasons: [...verdict.contradictions, ...verdict.unsupportedClaims],
        };
        await this.store.saveShortened(deliveryId, revision.evidence_hash, cached.summary, cached.validation);
      }
      if (!cached.validation.valid || (strict && !cached.validation.complete))
        throw new Error('shortened_summary_quality_gate');
      return provider.prepare({ ...intent, summary: cached.summary });
    }
  }
  private async publish(id: string, now: number) {
    const delivery = await this.store.getDelivery(id);
    if (!delivery || delivery.state !== 'ready') return;
    const target = this.config.targets.find((t) => t.id === delivery.target_id);
    const revision = await this.store.getRevision(delivery.revision_id);
    if (
      !target ||
      (!target.enabled && !this.config.dryRun) ||
      !revision ||
      !(await this.store.isCurrent(revision.id)) ||
      revision.event_at < now - this.config.freshnessSeconds * 1000
    ) {
      await this.store.holdDelivery(id, 'disabled_superseded_or_stale', now);
      return;
    }
    const cached = await this.store.getSummary(revision);
    if (!cached?.validation.valid || (target.qualityGate.enabled && !cached.validation.complete)) {
      await this.store.holdDelivery(id, 'quality_gate', now);
      return;
    }
    const provider =
      this.providers.social?.(target) ?? new MisskeyProvider(target, String(this.env[target.tokenSecret] ?? ''));
    const previousPost = await this.store.previousPost(target.id, revision.threat_key);
    const intent: PostIntent = {
      kind: previousPost ? (revision.kind === 'correction' ? 'correction' : 'update') : 'new',
      key: revision.threat_key,
      title: revision.snapshot.title,
      severity: classify(revision.snapshot).severity,
      summary: cached.summary,
      sources: [...new Set(revision.snapshot.evidence.map((e) => e.url))].slice(0, 2),
      previousPost,
    };
    let prepared: PreparedPost;
    try {
      prepared = await this.prepare(provider, intent, revision, id, target.qualityGate.enabled, now);
    } catch (error) {
      if (error instanceof Deferred) throw error;
      await this.store.holdDelivery(id, error instanceof Error ? error.message : 'format_error', now);
      return;
    }
    if (this.config.dryRun) {
      await this.store.previewDelivery(id, prepared, now);
      return;
    }
    const reservation = await this.store.reserveDelivery(id, target, now, revision.evidence_hash, prepared);
    if (!reservation) throw new Deferred(now + 60000, 'publication_slot_or_current_evidence_unavailable');
    try {
      const post = await provider.publish(prepared);
      // A failure here remains unknown; success at SNS and D1 cannot be atomic.
      await this.store.finishDelivery(id, post, now, reservation.lease_token!);
    } catch (error) {
      if (error instanceof PublishError) {
        await this.store.deliveryError(
          id,
          error.kind === 'unknown' ? 'unknown' : error.kind === 'retry' ? 'retry' : 'held',
          error.message,
          now,
          now + Math.max(error.retryAfterMs, 60000),
          reservation.lease_token!,
        );
        if (error.kind === 'auth')
          await this.store.pauseTarget(target.id, true, 'social_auth_failed', {
            deliveryId: id,
            token: reservation.lease_token!,
          });
      } else
        await this.store.deliveryError(
          id,
          'unknown',
          'publication_or_recording_result_unknown',
          now,
          now + 60000,
          reservation.lease_token!,
        );
    }
  }
}
