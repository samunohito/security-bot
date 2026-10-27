export type Fetcher = typeof fetch;

export class HttpError extends Error {
  /** HTTPステータスと再試行までの待ち時間（ミリ秒）を保持する。 */
  constructor(
    public status: number,
    public retryAfterMs = 0,
  ) {
    super(`http_${status}`);
  }

  /** ステータスに基づき、自動再試行の対象かを返す。 */
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

/** 許可されたHTTPS URLから本文を上限付きで取得する。 */
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
  ) {
    throw new Error('source_url_not_allowed');
  }

  const response = await fetcher(url, {
    headers: {
      'User-Agent': 'security-bot/0.1 (+security advisory aggregation)',
      ...options.headers,
    },
    signal: AbortSignal.timeout(15000),
    redirect: 'error',
  });
  if (response.status === 304) {
    return { text: '', notModified: true };
  }
  if (!response.ok) {
    const retryAfter = response.headers.get('retry-after');
    const retryAfterMs = retryAfter
      ? /^\d+$/.test(retryAfter)
        ? Number(retryAfter) * 1000
        : Math.max(0, Date.parse(retryAfter) - Date.now())
      : 0;
    await response.body?.cancel();
    throw new HttpError(response.status, Number.isFinite(retryAfterMs) ? retryAfterMs : 0);
  }

  const maxBytes = options.maxBytes ?? 262144;
  if (Number(response.headers.get('content-length')) > maxBytes) {
    await response.body?.cancel();
    throw new Error('resource_limit: response too large');
  }

  const reader = response.body?.getReader();
  let receivedBytes = 0;
  const chunks: Uint8Array[] = [];
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      receivedBytes += value.byteLength;
      if (receivedBytes > maxBytes) {
        await reader.cancel();
        throw new Error('resource_limit: response too large');
      }
      chunks.push(value);
    }
  }

  const bytes = new Uint8Array(receivedBytes);
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
