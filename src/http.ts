export type Fetcher = typeof fetch;
export class HttpError extends Error {
  constructor(
    public status: number,
    public retryAfterMs = 0,
  ) {
    super(`http_${status}`);
  }
  get retryable() {
    return this.status === 429 || this.status >= 500;
  }
}
export interface TextResult {
  text: string;
  etag?: string;
  lastModified?: string;
  notModified: boolean;
}
export async function getText(
  url: string,
  options: {
    headers?: Record<string, string>;
    maxBytes?: number;
    allowedHosts?: string[];
  } = {},
  fetcher: Fetcher = fetch,
): Promise<TextResult> {
  const parsed = new URL(url);
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    (options.allowedHosts && !options.allowedHosts.includes(parsed.hostname))
  )
    throw new Error('source_url_not_allowed');
  const response = await fetcher(url, {
    headers: {
      'User-Agent': 'security-bot/0.1 (+security advisory aggregation)',
      ...options.headers,
    },
    signal: AbortSignal.timeout(15000),
    redirect: 'error',
  });
  if (response.status === 304) return { text: '', notModified: true };
  if (!response.ok) {
    const retry = response.headers.get('retry-after');
    const ms = retry
      ? /^\d+$/.test(retry)
        ? Number(retry) * 1000
        : Math.max(0, Date.parse(retry) - Date.now())
      : 0;
    await response.body?.cancel();
    throw new HttpError(response.status, Number.isFinite(ms) ? ms : 0);
  }
  const max = options.maxBytes ?? 262144;
  if (Number(response.headers.get('content-length')) > max) {
    await response.body?.cancel();
    throw new Error('resource_limit: response too large');
  }
  const reader = response.body?.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) {
        await reader.cancel();
        throw new Error('resource_limit: response too large');
      }
      chunks.push(value);
    }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return {
    text: new TextDecoder().decode(bytes),
    notModified: false,
    etag: response.headers.get('etag') ?? undefined,
    lastModified: response.headers.get('last-modified') ?? undefined,
  };
}
