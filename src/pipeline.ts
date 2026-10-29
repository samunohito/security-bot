import { z } from 'zod';
import type { Config, Environment, SourceConfig, TargetConfig } from './config';
import { classify, digest, type PostIntent, type Summary, type Validation } from './domain';
import { HttpError } from './http';
import { SUMMARY_SYSTEM, VERIFY_SYSTEM } from './llm/prompts';
import type { AiBinding, LlmProvider, LlmRequest } from './llm/provider';
import { createLlmProvider } from './llm';
import { evidencePrompt } from './llm/evidence';
import { summarySchema, validateSummary, validateVerdict, verdictSchema, type Verdict } from './quality';
import { createSocialProvider } from './social';
import { PublishError, type PreparedPost, type SocialProvider } from './social/provider';
import { describePublishFailure } from './social/diagnostics';
import { sourceProvider } from './sources';
import type { SourceProvider } from './sources/provider';
import { Store, type Job, type Revision, type Delivery } from './store';
import { digestWindow } from './publication';
import { formatDigest } from './social/digest';
import { formatPost } from './social/format';
import type { DigestMember } from './publication-store';

export interface BotEnv extends Environment {
  DB: D1Database;
  JOBS: {
    /** ジョブIDをQueuesへ送る。 */
    send(body: { id: string }): Promise<unknown>;
  };
  AI?: AiBinding;
}

export interface Providers {
  llm?: LlmProvider;
  /** 情報源設定に対応するプロバイダーを生成する。 */
  source?: (config: SourceConfig) => SourceProvider;
  /** 投稿先設定に対応するSNSプロバイダーを生成する。 */
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

  /** 環境設定と任意の外部プロバイダーからボットを構成する。 */
  constructor(
    public env: BotEnv,
    public config: Config,
    public providers: Providers = {},
  ) {
    this.store = new Store(env.DB, config);
    this.llm = providers.llm ?? createLlmProvider(config.llm, env.AI);
  }

  private async analysisPolicy() {
    return digest(
      JSON.stringify({
        targets: this.config.targets,
        dryRun: this.config.dryRun,
        model: this.config.llm.model,
        llmProvider: this.config.llm.provider,
        publishing: this.config.publishing,
      }),
    );
  }

  private async analyzeKey(revisionId: string, evidenceHash: string) {
    return `analyze:${revisionId}:${evidenceHash}:${await this.analysisPolicy()}`;
  }

  /** 定期実行として状態を同期し、作業をキューへ送る。 */
  async tick(now = Date.now()) {
    await this.store.bootstrapTime(now);
    await this.store.publications.initialize(now);
    await this.store.recover(now);
    await this.store.syncTargets(this.config.targets);
    await this.store.syncSources(this.config.sources, now);
    await this.store.publications.reconcileDeliveries(now);

    for (const revision of await this.store.currentRevisions(50, await this.analysisPolicy())) {
      await this.store.enqueue(
        await this.analyzeKey(revision.id, revision.evidence_hash),
        'analyze',
        { revisionId: revision.id },
        now,
      );
    }

    if (this.store.publications.enabled) {
      await this.buildDigests(now);
    }

    for (const delivery of await this.store.dueDeliveries(now)) {
      await this.store.enqueue(
        `publish:${delivery.id}:${delivery.available_at}`,
        'publish',
        { deliveryId: delivery.id },
        now,
      );
    }

    await this.flush(now);
    await this.store.cleanup(now, this.config.retentionDays);
  }

  /** OutboxのジョブをQueuesへ送り、送信結果を記録する。 */
  async flush(now: number) {
    const started = Date.now();
    const currentTime = () => now + Math.max(0, Date.now() - started);
    await this.store.skipOldWork(now);
    await this.store.deferAiJobs(now, this.config.budget, this.config.llm.provider === 'fake' && !this.providers.llm);

    for (const job of await this.store.outbox(now)) {
      const token = await this.store.reserveDispatch(job.id, currentTime(), this.config.budget.queueOperations);
      if (!token) {
        continue;
      }

      if (!(await this.store.beginDispatch(job.id, token, currentTime()))) {
        continue;
      }
      let accepted = false;
      try {
        await this.env.JOBS.send({ id: job.id });
        accepted = true;
        await this.store.markDispatched(job.id, currentTime(), token);
      } catch (error) {
        // 送信成功後の記録失敗を、同じ文言のQueue拒否と混同しない。
        const rejected =
          !accepted &&
          error instanceof Error &&
          /(?:^|:\s*)(?:Too Many Requests|Storage Limit Exceeded)(?:\s+\(\d+\))?(?:$|[.!])/i.test(error.message);
        if (rejected) {
          await this.store.retryDispatch(job.id, token, currentTime() + 60000);
        }
        console.warn(
          JSON.stringify({ event: rejected ? 'queue_enqueue_rejected' : 'queue_enqueue_unknown', job: job.id }),
        );
        break;
      }
    }
  }

  /** 検証不合格を含む保存済み要約を取得し、未生成と改訂不存在を区別する。 */
  async summary(id: string) {
    const revision = await this.store.getRevision(id);
    if (!revision) {
      return null;
    }

    const cached = await this.store.getSummary(revision);

    return {
      revisionId: id,
      key: revision.threat_key,
      evidenceHash: revision.evidence_hash,
      status: cached ? 'generated' : 'not_generated',
      summary: cached?.summary ?? null,
      validation: cached?.validation ?? null,
    };
  }

  /** 保存済み根拠で要約を再生成・検証し、明示指定時だけ合格した現在改訂の要約を保存する。 */
  async generateSummary(id: string, now = Date.now(), options: { save?: boolean } = {}) {
    const revision = await this.store.getRevision(id);
    if (!revision) {
      throw new Error('revision_not_found');
    }

    const input = this.promptEvidence(revision);
    const summary = await this.generate({ system: SUMMARY_SYSTEM, data: input }, summarySchema, now);
    const validation = validateSummary(summary, revision.snapshot.evidence, revision.threat_key, {
      requireActionKind: true,
    });
    let verdict: Verdict | null = null;
    if (this.config.llm.provider === 'fake' && !this.providers.llm) {
      validation.valid = false;
      validation.reasons.push('fake_provider');
    } else if (validation.valid) {
      verdict = await this.generate({ system: VERIFY_SYSTEM, data: { ...input, summary } }, verdictSchema, now);
      validation.valid = validateVerdict(verdict);
      validation.reasons.push(
        ...verdict.contradictions,
        ...verdict.unsupportedClaims,
        ...(!verdict.supported ? ['unsupported_summary'] : []),
      );
    }

    const current = await this.store.getRevision(id);
    if (!current || current.evidence_hash !== revision.evidence_hash || !(await this.store.isCurrent(id))) {
      validation.valid = false;
      validation.reasons.push('evidence_changed');
    }

    let saved = false;
    if (options.save && validation.valid) {
      saved = await this.store.saveCurrentSummary(revision, summary, validation, now);
      if (!saved) {
        validation.valid = false;
        validation.reasons.push('evidence_changed');
      }
    }

    return {
      revisionId: id,
      key: revision.threat_key,
      evidenceHash: revision.evidence_hash,
      saved,
      provider: this.config.llm.provider,
      model: this.config.llm.provider === 'fake' ? null : this.config.llm.model,
      summary,
      validation,
      verdict,
    };
  }

  /** 改訂の保存済み要約から投稿先ごとの本文と投稿可否のプレビューを作る。 */
  async preview(id: string) {
    const delivery = await this.store.getDelivery(id);
    if (delivery?.mode === 'digest') {
      const current = await this.store.publications.digestCurrent(delivery);
      return [
        {
          targetId: delivery.target_id,
          allowed: current,
          members: await this.store.publications.members(id),
          ...JSON.parse(delivery.prepared ?? '{}'),
          reasons: current ? [] : ['digest_members_changed'],
        },
      ];
    }
    const revision = await this.store.getRevision(id);
    if (!revision) {
      throw new Error('revision_not_found');
    }

    const cached = await this.store.getSummary(revision);
    if (!cached) {
      throw new Error('verified_summary_not_available');
    }

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
      const provider = this.providers.social?.(target) ?? createSocialProvider(target);
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

  /** ジョブをリースし、種別ごとの処理と結果状態の記録を行う。 */
  async runJob(id: string, now = Date.now()) {
    const job = await this.store.claimJob(id, now);
    if (!job) {
      return;
    }

    try {
      const payload: unknown = JSON.parse(job.payload);

      if (job.type === 'collect') {
        await this.collect(job, z.object({ sourceId: z.string() }).parse(payload).sourceId, now);
      } else if (job.type === 'ingest') {
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
            if (revision) {
              await this.store.enqueue(
                await this.analyzeKey(revision.id, revision.evidence_hash),
                'analyze',
                { revisionId },
                now,
              );
            }
          }
        }
      } else if (job.type === 'analyze') {
        const { revisionId } = z.object({ revisionId: z.string() }).parse(payload);
        const policy = /^analyze:[0-9a-f]{64}:.+:([0-9a-f]{64})$/.exec(job.id)?.[1];
        if (policy && policy !== (await this.analysisPolicy())) {
          const revision = await this.store.getRevision(revisionId);
          if (revision && (await this.store.isCurrent(revision.id))) {
            await this.store.enqueue(
              await this.analyzeKey(revision.id, revision.evidence_hash),
              'analyze',
              { revisionId },
              now,
            );
            throw new Error('analysis_policy_changed');
          }
        }
        await this.analyze(revisionId, now);
      } else if (job.type === 'publish') {
        await this.publish(z.object({ deliveryId: z.string() }).parse(payload).deliveryId, now);
      } else {
        throw new Error('unknown_job_type');
      }

      await this.store.finishJob(job);
    } catch (error) {
      const reason = error instanceof Error ? error.message.slice(0, 300) : 'unknown_error';
      if (error instanceof Deferred) {
        await this.store.failJob(job, 'deferred', reason, error.until);
      } else {
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
    if (!state || state.active_job !== job.id) {
      return;
    }
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
    return evidencePrompt(revision.threat_key, revision.snapshot.evidence);
  }

  private async generate<T>(request: LlmRequest, schema: z.ZodType<T>, now: number): Promise<T> {
    if (!this.llm) {
      throw new Error('missing_AI_binding');
    }
    const input = JSON.stringify(request.data) + request.system;
    if (input.length > this.config.llm.maxInputCharacters) {
      throw new Error('resource_limit: LLM input');
    }

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
      if (response.usage) {
        await this.store.settleBudget(
          id,
          (response.usage.inputTokens * this.config.llm.inputNeuronsPerMillion) / 1e6 +
            (response.usage.outputTokens * this.config.llm.outputNeuronsPerMillion) / 1e6,
        );
      }

      return schema.parse(response.value);
    } catch (error) {
      if (error instanceof Error && /quota|429|neurons|rate.limit/i.test(error.message)) {
        throw new Deferred(tomorrowUtc(now), 'AI_provider_quota');
      }
      throw error;
    }
  }

  private async analyze(id: string, now: number) {
    const revision = await this.store.getRevision(id);
    if (
      !revision ||
      !revision.eligible ||
      !(await this.store.isCurrent(id)) ||
      (!this.store.publications.enabled && (await this.store.isBeforeCutoff(revision.snapshot.eventAt)))
    ) {
      return;
    }

    if (revision.evidence_hash.startsWith('updating:')) {
      throw new Deferred(now + 60000, 'evidence_updating');
    }

    const decisions = await Promise.all(
      this.config.targets
        .filter((target) => target.enabled || this.config.dryRun)
        .map((target) => this.store.publications.decision(revision, target.id)),
    );
    const eventAt = Math.max(0, ...decisions.flatMap((decision) => (decision ? [decision.eventAt] : [])));
    const pendingDecisions = await Promise.all(
      this.config.targets
        .filter((target) => target.enabled || this.config.dryRun)
        .map((target, index) =>
          decisions[index] ? null : this.store.publications.decision(revision, target.id, false),
        ),
    );
    const awaitingResult = pendingDecisions.some(Boolean);
    const pendingAt = Math.max(
      eventAt,
      ...pendingDecisions.flatMap((decision) => (decision ? [decision.eventAt] : [])),
    );
    if (this.store.publications.enabled && pendingAt > 0 && pendingAt < now - this.config.freshnessSeconds * 1000) {
      throw new Error('publication_event_expired');
    }
    if ((this.store.publications.enabled || decisions.length > 0) && !decisions.some(Boolean)) {
      if (awaitingResult) {
        throw new Deferred(now + 60000, 'publication_result_pending');
      }
      return;
    }
    const start = await this.store.bootstrapTime(now);
    const effectiveAt = this.store.publications.enabled ? eventAt : revision.snapshot.eventAt;
    if (
      effectiveAt < now - this.config.freshnessSeconds * 1000 ||
      (await this.store.isBeforeCutoff(effectiveAt)) ||
      (revision.kind === 'new' && effectiveAt < start - this.config.initialLookbackSeconds * 1000)
    ) {
      return;
    }

    let cached = await this.store.getSummary(revision);
    const fakeLlm = this.config.llm.provider === 'fake' && !this.providers.llm;
    if (cached?.validation.reasons.includes('fake_provider') && !fakeLlm) {
      cached = null;
    }

    if (!cached) {
      const summary = await this.generate(
        { system: SUMMARY_SYSTEM, data: this.promptEvidence(revision) },
        summarySchema,
        now,
      );
      const validation = validateSummary(summary, revision.snapshot.evidence, revision.threat_key, {
        requireActionKind: true,
      });
      if (fakeLlm) {
        validation.reasons = ['fake_provider', ...validation.reasons];
      } else if (validation.valid) {
        validation.reasons = ['verification_pending'];
      }
      validation.valid = false;
      await this.store.saveSummary(revision, summary, validation, now);
      cached = { summary, validation };
    }

    if (cached.validation.reasons.includes('verification_pending')) {
      if (await this.store.isBeforeCutoff(effectiveAt)) {
        return;
      }
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

    if (!(await this.store.isCurrent(id))) {
      return;
    }
    const current = await this.store.getRevision(id);
    if (current?.evidence_hash !== revision.evidence_hash) {
      throw new Deferred(now + 60000, 'evidence_changed');
    }

    for (const target of this.config.targets) {
      if (!target.enabled && !this.config.dryRun) {
        continue;
      }
      if (revision.snapshot.rejected && !(await this.store.previousPost(target.id, revision.threat_key))) {
        continue;
      }
      const decision = await this.store.publications.decision(revision, target.id);
      if (!decision || (this.store.publications.enabled && decision.route === 'digest')) {
        continue;
      }
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
        decision?.eventAt,
      );
      if (allowed) {
        await this.store.enqueue(`publish:${deliveryId}:${now}`, 'publish', { deliveryId }, now);
      }
    }
    if (awaitingResult) {
      throw new Deferred(now + 60000, 'publication_result_pending');
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
      if (!(error instanceof Error) || error.message !== 'post_too_long') {
        throw error;
      }
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
        const check = validateSummary(shorter, revision.snapshot.evidence, revision.threat_key, {
          requireActionKind: true,
        });
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

      if (!cached.validation.valid || (strict && !cached.validation.complete)) {
        throw new Error('shortened_summary_quality_gate');
      }
      return provider.prepare({ ...intent, summary: cached.summary });
    }
  }

  private async publish(id: string, now: number) {
    const delivery = await this.store.getDelivery(id);
    if (!delivery || delivery.state !== 'ready') {
      return;
    }

    const target = this.config.targets.find((t) => t.id === delivery.target_id);
    if (delivery.mode === 'digest') {
      await this.publishDigest(delivery, target, now);
      return;
    }
    const revision = delivery.revision_id ? await this.store.getRevision(delivery.revision_id) : null;
    if (
      !target ||
      (!target.enabled && !this.config.dryRun) ||
      !revision ||
      !(await this.store.isCurrent(revision.id)) ||
      (await this.store.isBeforeCutoff(delivery.event_at ?? revision.snapshot.eventAt)) ||
      (delivery.event_at ?? revision.snapshot.eventAt) < now - this.config.freshnessSeconds * 1000
    ) {
      await this.store.holdDelivery(id, 'disabled_superseded_or_stale', now);
      return;
    }

    if (revision.evidence_hash.startsWith('updating:')) {
      throw new Deferred(now + 60000, 'evidence_updating');
    }

    const decision = await this.store.publications.decision(revision, target.id);
    if (!decision || (this.store.publications.enabled && decision.route !== 'individual')) {
      await this.store.staleDelivery(
        id,
        decision?.route === 'digest' ? 'individual_to_digest' : 'publication_policy_changed',
        now,
      );
      return;
    }
    const cached = await this.store.getSummary(revision);
    if (!cached) {
      const key = await this.analyzeKey(revision.id, revision.evidence_hash);
      await this.store.enqueue(key, 'analyze', { revisionId: revision.id }, now);
      await this.store.reopenCompletedAnalysis(key, now);
      const analysis = await this.store.getJob(key);
      if (analysis?.state === 'held' || analysis?.state === 'failed') {
        await this.store.holdDelivery(id, 'summary_analysis_held', now);
        return;
      }
      throw new Deferred(Math.max(now + 60000, analysis?.available_at ?? now), 'summary_not_current');
    }
    if (!cached.validation.valid || (target.qualityGate.enabled && !cached.validation.complete)) {
      await this.store.holdDelivery(id, 'quality_gate', now);
      return;
    }

    const provider = this.providers.social?.(target) ?? createSocialProvider(target, this.env);
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
      if (error instanceof Deferred) {
        throw error;
      }
      await this.store.holdDelivery(id, error instanceof Error ? error.message : 'format_error', now);
      return;
    }

    await this.sendPrepared(delivery, target, provider, prepared, now, revision.evidence_hash);
  }

  private async buildDigests(now: number) {
    const window = digestWindow(now, this.config.publishing.digestIntervalSeconds);
    for (const target of this.config.targets) {
      if (!target.enabled && !this.config.dryRun) {
        continue;
      }
      if (
        await this.env.DB.prepare('SELECT 1 FROM digest_windows WHERE target_id=? AND window_end=?')
          .bind(target.id, window.end)
          .first()
      ) {
        continue;
      }
      // 検証済みHighは個別候補の上限とは別に取得し、既報の更新がまとめを圧迫しないようにする。
      const cutoff = await this.store.eventCutoff();
      const rows =
        await this.env.DB.prepare(`SELECT r.*,s.summary,s.validation,o.high_at,o.high_reason FROM revisions r JOIN threats t ON t.revision_id=r.id
        JOIN publication_observations o ON o.threat_key=r.threat_key
        JOIN summaries s ON s.revision_id=r.id AND s.evidence_hash=r.evidence_hash
        WHERE o.nvd_only=1 AND o.high_at IS NOT NULL AND o.high_at<? AND r.priority=2 AND r.urgent=0
        AND json_extract(r.snapshot,'$.rejected')=0 AND json_extract(s.validation,'$.valid')=1
        AND (?=0 OR json_extract(s.validation,'$.complete')=1)
        AND NOT EXISTS(SELECT 1 FROM delivery_items i JOIN deliveries d ON d.id=i.delivery_id WHERE d.target_id=? AND i.threat_key=r.threat_key AND i.level>=2 AND (d.state IN ('sent','sending','unknown') OR (d.state IN ('ready','held','preview') AND i.revision_id=r.id AND i.evidence_hash=r.evidence_hash)))
        ORDER BY (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores')) DESC,o.high_at,r.threat_key`)
          .bind(window.end, target.qualityGate.enabled ? 1 : 0, target.id)
          .all<
            Omit<Revision, 'snapshot'> & {
              snapshot: string;
              summary: string;
              validation: string;
              high_at: number;
              high_reason: string | null;
            }
          >();
      const members = new Map<string, DigestMember>();
      const entries: { id: string; text: string }[] = [];
      for (const row of rows.results) {
        const revision: Revision = { ...row, snapshot: JSON.parse(row.snapshot) as Revision['snapshot'] };
        const decision = {
          route: 'digest' as const,
          level: 2,
          eventAt: row.high_at,
          reason: row.high_reason ?? 'High昇格',
        };
        if (decision.eventAt < now - this.config.freshnessSeconds * 1000 || decision.eventAt < cutoff) {
          await this.store.createDelivery(
            await digest(`${target.id}:${revision.id}`),
            target.id,
            revision.id,
            false,
            now,
            'held',
            'publication_event_expired',
            decision.eventAt,
          );
          continue;
        }
        const summary = JSON.parse(row.summary) as Summary;
        const intent: PostIntent = {
          kind: 'new',
          key: revision.threat_key,
          title: revision.snapshot.title,
          severity: 'High',
          summary: { ...summary, tags: [] },
          sources: [...new Set(revision.snapshot.evidence.map((entry) => entry.url))].slice(0, 2),
        };
        const score = Math.max(...revision.snapshot.scores.map((value) => value.score));
        const text = `${decision.reason} / CVSS ${score}\n${formatPost(intent)}`;
        try {
          formatDigest([{ id: revision.id, text }], window, target.maxCharacters, rows.results.length);
        } catch {
          await this.store.createDelivery(
            await digest(`${target.id}:${revision.id}`),
            target.id,
            revision.id,
            false,
            now,
            'held',
            'digest_item_too_long',
            decision.eventAt,
          );
          continue;
        }
        members.set(revision.id, { revision, decision, summary });
        entries.push({ id: revision.id, text });
      }
      const pages = formatDigest(entries, window, target.maxCharacters).map((page) => ({
        text: page.text,
        members: page.ids.map((id) => members.get(id)!),
      }));
      await this.store.publications.createWindow(target.id, window, pages, now);
    }
  }

  private async publishDigest(delivery: Delivery, target: TargetConfig | undefined, now: number) {
    if (!target || (!target.enabled && !this.config.dryRun) || !this.store.publications.enabled) {
      await this.store.holdDelivery(delivery.id, 'digest_disabled', now);
      return;
    }
    if (!(await this.store.publications.digestCurrent(delivery))) {
      await this.store.staleDelivery(delivery.id, 'digest_members_changed', now);
      return;
    }
    if (
      (await this.store.isBeforeCutoff(delivery.event_at ?? 0)) ||
      (delivery.event_at ?? 0) < now - this.config.freshnessSeconds * 1000
    ) {
      await this.store.holdDelivery(delivery.id, 'publication_event_expired', now);
      return;
    }
    const prepared = JSON.parse(delivery.prepared ?? '{}') as PreparedPost;
    if (typeof prepared.text !== 'string' || [...prepared.text].length > target.maxCharacters) {
      await this.store.holdDelivery(delivery.id, 'digest_format_error', now);
      return;
    }
    const provider = this.providers.social?.(target) ?? createSocialProvider(target, this.env);
    await this.sendPrepared(delivery, target, provider, prepared, now);
  }

  private async sendPrepared(
    delivery: Delivery,
    target: TargetConfig,
    provider: SocialProvider,
    prepared: PreparedPost,
    now: number,
    expectedEvidenceHash?: string,
  ) {
    const id = delivery.id;
    if (this.config.dryRun) {
      await this.store.previewDelivery(id, prepared, now);
      return;
    }

    const reservation = await this.store.reserveDelivery(id, target, now, expectedEvidenceHash, prepared);
    if (!reservation) {
      const until = await this.store.nextPublicationAt(delivery, target, now);
      await this.store.deferDelivery(id, until, now);
      throw new Deferred(until, 'publication_slot_or_current_evidence_unavailable');
    }

    let phase: 'request' | 'recording' = 'request';
    const started = Date.now();
    try {
      const post = await provider.publish(prepared);
      phase = 'recording';
      // SNSの受理とD1記録は同一トランザクションにできないため、この記録で失敗した場合も送信結果は不明として扱う。
      await this.store.finishDelivery(id, post, now, reservation.lease_token!);
    } catch (error) {
      const failure =
        error instanceof PublishError
          ? error
          : new PublishError(
              'unknown',
              'publication_or_recording_result_unknown',
              0,
              describePublishFailure(error, phase),
            );
      const detail = failure.diagnostics
        ? JSON.stringify({ reason: failure.message, diagnostics: failure.diagnostics })
        : failure.message;
      console.warn(
        JSON.stringify({
          event: 'publication_failed',
          deliveryId: id,
          targetId: target.id,
          revisionId: delivery.revision_id,
          kind: failure.kind,
          reason: failure.message,
          diagnostics: failure.diagnostics,
          elapsedMs: Date.now() - started,
        }),
      );

      await this.store.deliveryError(
        id,
        failure.kind === 'unknown' ? 'unknown' : failure.kind === 'retry' ? 'retry' : 'held',
        detail,
        now,
        now + Math.max(failure.retryAfterMs, 60000),
        reservation.lease_token!,
      );
      if (failure.kind === 'auth') {
        await this.store.pauseTarget(target.id, true, 'social_auth_failed', {
          deliveryId: id,
          token: reservation.lease_token!,
        });
      }
    }
  }
}
