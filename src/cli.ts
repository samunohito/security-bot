import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { loadConfig } from './config';
import { preview } from './preview';
import { StdoutSocialProvider } from './social/stdout';

async function main() {
  const { positionals: args, values } = parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string' },
      source: { type: 'string' },
      item: { type: 'string' },
      key: { type: 'string' },
      'post-id': { type: 'string' },
      'post-url': { type: 'string' },
      'ack-duplicate-risk': { type: 'boolean' },
      state: { type: 'string' },
    },
  });
  const [command, resource, id] = args;
  if (command === 'preview') {
    if (!values.source || args.length !== 1 || values.item === '' || values.key === '') {
      throw new Error('Usage: preview --source SOURCE_ID [--item ITEM_ID] [--key THREAT_KEY] [--config path]');
    }

    const raw = JSON.parse(await readFile(values.config ?? 'bot.config.json', 'utf8')) as unknown;
    const result = await preview(loadConfig(raw, process.env), {
      source: values.source,
      item: values.item,
      key: values.key,
    });
    if (!result.validation.valid) {
      console.log(JSON.stringify(result, null, 2));
      process.exitCode = 1;
      return;
    }

    const social = new StdoutSocialProvider(3000, (text) => {
      console.log(JSON.stringify({ ...result, post: { ...result.post, text } }, null, 2));
    });
    await social.publish(result.post);
    return;
  }

  if (command === 'config') {
    const raw = JSON.parse(await readFile(values.config ?? 'bot.config.json', 'utf8')) as unknown;
    const config = loadConfig(raw, process.env);
    if (resource !== 'validate' && resource !== 'show') {
      throw new Error('Usage: config validate|show [--config path]');
    }
    console.log(
      JSON.stringify(
        resource === 'show'
          ? config
          : {
              valid: true,
              mode: config.mode,
              dryRun: config.dryRun,
              targets: config.targets.length,
            },
        null,
        2,
      ),
    );
    return;
  }

  if (!command || command === 'help') {
    console.log(
      'Commands: preview --source SOURCE_ID [--item ITEM_ID] [--key THREAT_KEY] [--config path]; config validate|show; status; list jobs|deliveries|sources|targets|revisions; show jobs|deliveries|revisions|summaries ID; generate-summary REVISION_ID; dry-run REVISION_ID; retry-job ID; retry-delivery ID [--ack-duplicate-risk]; resolve ID --post-id NOTE_ID --post-url HTTPS_URL; pause TARGET_ID; resume TARGET_ID',
    );
    return;
  }

  const base = process.env.SECURITY_BOT_URL,
    token = process.env.SECURITY_BOT_ADMIN_TOKEN;
  if (!base || !token) {
    throw new Error('Set SECURITY_BOT_URL and SECURITY_BOT_ADMIN_TOKEN');
  }
  const url = new URL(base);
  if (
    url.protocol !== 'https:' &&
    !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
  ) {
    throw new Error('SECURITY_BOT_URL must use HTTPS (or local HTTP)');
  }

  let path = '',
    method = 'GET';
  let body: Record<string, unknown> | undefined;
  if (command === 'status') {
    path = '/admin/status';
  } else if (command === 'list' && ['jobs', 'deliveries', 'sources', 'targets', 'revisions'].includes(resource ?? '')) {
    path = `/admin/${resource}`;
  } else if (command === 'show' && ['jobs', 'deliveries', 'revisions', 'summaries'].includes(resource ?? '') && id) {
    path = `/admin/${resource}/${encodeURIComponent(id)}`;
  } else if (command === 'dry-run' && resource) {
    path = `/admin/dry-run?id=${encodeURIComponent(resource)}`;
  } else {
    const paths: Record<string, string> = {
      'retry-job': '/admin/jobs/retry',
      'generate-summary': '/admin/summaries/generate',
      'retry-delivery': '/admin/deliveries/retry',
      resolve: '/admin/deliveries/resolve',
      pause: '/admin/targets/pause',
      resume: '/admin/targets/resume',
    };
    if (!paths[command] || !resource) {
      throw new Error('Invalid command. Run npm run cli -- help');
    }
    path = paths[command]!;
    method = 'POST';
    body = {
      id: resource,
      ...(values['post-id'] ? { postId: values['post-id'] } : {}),
      ...(values['post-url'] ? { postUrl: values['post-url'] } : {}),
      ...(values['ack-duplicate-risk'] ? { acknowledgeDuplicateRisk: true } : {}),
    };
  }

  const response = await fetch(new URL(path, url), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(command === 'generate-summary' ? 120000 : 30000),
    redirect: 'error',
  });
  if (!response.ok) {
    throw new Error(`Management API ${response.status}: ${await response.text()}`);
  }

  let data: unknown = await response.json();
  if (values.state && Array.isArray(data)) {
    data = data.filter((row) => row.state === values.state);
  }

  console.log(JSON.stringify(data, null, 2));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : 'CLI failed');
  process.exitCode = 1;
});
