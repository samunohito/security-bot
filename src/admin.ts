import { z } from 'zod';
import type { Bot } from './pipeline';

async function authorized(request: Request, token: string | undefined) {
  if (!token) {
    return false;
  }

  const header = request.headers.get('Authorization') ?? '';
  const encoder = new TextEncoder();
  const [actualDigest, expectedDigest] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(header)),
    crypto.subtle.digest('SHA-256', encoder.encode(`Bearer ${token}`)),
  ]);
  const actualHash = new Uint8Array(actualDigest);
  const expectedHash = new Uint8Array(expectedDigest);
  let difference = 0;
  for (let i = 0; i < actualHash.length; i++) {
    difference |= actualHash[i]! ^ expectedHash[i]!;
  }

  return difference === 0;
}

/** 管理APIの要求を認証・処理し、対象外のパスでは null を返す。 */
export async function adminRequest(request: Request, bot: Bot, token?: string): Promise<Response | null> {
  const url = new URL(request.url);
  if (!url.pathname.startsWith('/admin/')) {
    return null;
  }

  const json = (data: unknown, status = 200) =>
    Response.json(data, { status, headers: { 'Cache-Control': 'no-store' } });
  if (!(await authorized(request, token))) {
    return json({ error: 'unauthorized' }, 401);
  }

  try {
    if (request.method === 'GET' && url.pathname === '/admin/dry-run') {
      return json(await bot.preview(z.string().min(1).parse(url.searchParams.get('id'))));
    }

    if (request.method === 'GET' && url.pathname === '/admin/status') {
      return json({
        mode: bot.config.mode,
        dryRun: bot.config.dryRun,
        budget: await bot.store.budgetStatus(Date.now()),
        sources: await bot.store.list('sources'),
        targets: await bot.store.list('targets'),
        jobs: await bot.store.list('jobs'),
        deliveries: await bot.store.list('deliveries'),
      });
    }

    const summaryMatch = url.pathname.match(/^\/admin\/summaries\/([^/]+)$/);
    if (request.method === 'GET' && summaryMatch) {
      const result = await bot.summary(decodeURIComponent(summaryMatch[1]!));

      return result ? json(result) : json({ error: 'not_found' }, 404);
    }

    const tableMatch = url.pathname.match(/^\/admin\/(jobs|deliveries|sources|targets|revisions)$/);
    if (request.method === 'GET' && tableMatch) {
      return json(await bot.store.list(tableMatch[1] as 'jobs' | 'deliveries' | 'sources' | 'targets' | 'revisions'));
    }

    const detailMatch = url.pathname.match(/^\/admin\/(jobs|deliveries|revisions)\/([^/]+)$/);
    if (request.method === 'GET' && detailMatch) {
      const table = detailMatch[1]!,
        id = decodeURIComponent(detailMatch[2]!);
      const row =
        table === 'revisions'
          ? await bot.store.getRevision(id)
          : table === 'jobs'
            ? await bot.store.getJob(id)
            : await bot.store.getDelivery(id);

      return row ? json(row) : json({ error: 'not_found' }, 404);
    }

    if (request.method !== 'POST') {
      return json({ error: 'not_found' }, 404);
    }

    const text = await request.text();
    if (text.length > 16384) {
      return json({ error: 'body_too_large' }, 413);
    }

    const body = z
      .object({
        id: z.string().min(1).max(500),
        postId: z.string().max(200).optional(),
        postUrl: z.url().optional(),
        acknowledgeDuplicateRisk: z.boolean().optional(),
      })
      .strict()
      .parse(JSON.parse(text));
    const now = Date.now();

    if (url.pathname === '/admin/summaries/generate') {
      if (!(await bot.store.getRevision(body.id))) {
        return json({ error: 'not_found' }, 404);
      }

      return json(await bot.generateSummary(body.id));
    }
    if (url.pathname === '/admin/targets/pause' || url.pathname === '/admin/targets/resume') {
      await bot.store.pauseTarget(body.id, url.pathname.endsWith('/pause'));
    } else if (url.pathname === '/admin/jobs/retry') {
      await bot.store.retryJob(body.id, now);
    } else if (url.pathname === '/admin/deliveries/retry') {
      const delivery = await bot.store.getDelivery(body.id);
      if (!delivery) {
        return json({ error: 'not_found' }, 404);
      }
      if (delivery.state === 'unknown' && !body.acknowledgeDuplicateRisk) {
        return json({ error: 'duplicate_risk_acknowledgement_required' }, 409);
      }

      await bot.store.retryDelivery(body.id, now);
    } else if (url.pathname === '/admin/deliveries/resolve') {
      const delivery = await bot.store.getDelivery(body.id);
      const target = bot.config.targets.find((t) => t.id === delivery?.target_id);
      if (
        delivery?.state !== 'unknown' ||
        !target ||
        target.provider !== 'misskey' ||
        !body.postId ||
        !body.postUrl ||
        new URL(body.postUrl).origin !== new URL(target.baseUrl).origin ||
        !new URL(body.postUrl).pathname.startsWith('/notes/')
      ) {
        return json({ error: 'invalid_resolution' }, 400);
      }

      await bot.store.finishDelivery(body.id, { id: body.postId, url: body.postUrl }, now, delivery.lease_token!);
    } else {
      return json({ error: 'not_found' }, 404);
    }

    return json({ ok: true });
  } catch {
    return json({ error: 'invalid_request' }, 400);
  }
}
