import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { loadConfig } from '../src/config';
import { parseKev, parseFeed } from '../src/sources/parsers';
import { sourceProvider } from '../src/sources';

const { values } = parseArgs({
  options: {
    file: { type: 'string' },
    source: { type: 'string', default: 'kev' },
    save: { type: 'string' },
  },
});

const source = loadConfig().sources.find((s) => s.id === values.source);
if (!source || source.kind === 'nvd') {
  throw new Error('Use --source kev|jvn|jpcert');
}

const text = values.file
  ? await readFile(values.file, 'utf8')
  : await (async () => {
      const response = await fetch(source.url, {
        signal: AbortSignal.timeout(15000),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      return response.text();
    })();
if (values.save) {
  await mkdir('benchmark-data', { recursive: true });
  await writeFile(values.save, text);
}

const timings = [];
let count = 0;
for (let i = 0; i < 6; i++) {
  const start = process.cpuUsage();
  const items =
    source.kind === 'kev' ? parseKev(JSON.parse(text), source.id, Date.now()) : parseFeed(text, source, Date.now());
  const elapsed = process.cpuUsage(start);
  count = items.length;
  if (i) {
    timings.push((elapsed.user + elapsed.system) / 1000);
  }
}

const cpu = timings.sort((a, b) => a - b)[2]!;
const start = process.cpuUsage();
const initial = await sourceProvider(source, {}, async () => new Response(text)).collect({}, Date.now());
const elapsed = process.cpuUsage(start);

console.log(
  JSON.stringify(
    {
      source: source.id,
      bytes: Buffer.byteLength(text),
      records: count,
      parseMedianCpuMs: cpu,
      baselineCpuMs: (elapsed.user + elapsed.system) / 1000,
      initialIngestJobs: initial.items.length,
      cursorBytes: Buffer.byteLength(JSON.stringify(initial.cursor)),
      freeCpuTargetMs: 10,
      note: 'Local Node CPU measurement only; validate actual Worker CPU with Cloudflare invocation metrics. Network waits excluded from parse median.',
    },
    null,
    2,
  ),
);
