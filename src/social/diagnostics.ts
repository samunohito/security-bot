export interface PublishDiagnostics {
  phase: 'request' | 'response' | 'response_body' | 'recording';
  reason?: 'illegal_invocation' | 'timeout' | 'aborted' | 'dns' | 'tls' | 'connection' | 'network' | 'unknown';
  exception?: string;
  code?: string;
  status?: number;
  apiCode?: string;
}

const transportReasons: Record<string, PublishDiagnostics['reason']> = {
  ENOTFOUND: 'dns',
  EAI_AGAIN: 'dns',
  ETIMEDOUT: 'timeout',
  UND_ERR_CONNECT_TIMEOUT: 'timeout',
  UND_ERR_HEADERS_TIMEOUT: 'timeout',
  UND_ERR_BODY_TIMEOUT: 'timeout',
  ECONNRESET: 'connection',
  ECONNREFUSED: 'connection',
  EPIPE: 'connection',
  UND_ERR_SOCKET: 'connection',
  CERT_HAS_EXPIRED: 'tls',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'tls',
  SELF_SIGNED_CERT_IN_CHAIN: 'tls',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'tls',
  ERR_TLS_CERT_ALTNAME_INVALID: 'tls',
};
const exceptionNames = new Set(['Error', 'TypeError', 'SyntaxError', 'TimeoutError', 'AbortError', 'ZodError']);
const apiCodes = new Set([
  'AUTHENTICATION_FAILED',
  'CREDENTIAL_REQUIRED',
  'INVALID_TOKEN',
  'PERMISSION_DENIED',
  'INVALID_PARAM',
  'RATE_LIMIT_EXCEEDED',
  'NO_SUCH_USER',
  'INTERNAL_ERROR',
  'NO_SUCH_RENOTE_TARGET',
  'CANNOT_RENOTE_DUE_TO_VISIBILITY',
  'CANNOT_RENOTE_OUTSIDE_OF_CHANNEL',
]);

function property(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }

  return Reflect.get(value, key);
}

/** 例外の本文を複製せず、既知の例外名・通信コードと処理段階で失敗を分類する。 */
export function describePublishFailure(
  error: unknown,
  phase: PublishDiagnostics['phase'],
  status?: number,
): PublishDiagnostics {
  const name = property(error, 'name');
  const exception = typeof name === 'string' && exceptionNames.has(name) ? name : 'Error';
  const message = property(error, 'message');
  let reason: PublishDiagnostics['reason'] = 'unknown';
  if (exception === 'TimeoutError') {
    reason = 'timeout';
  } else if (exception === 'AbortError') {
    reason = 'aborted';
  } else if (typeof message === 'string' && /^Illegal invocation\b/.test(message)) {
    reason = 'illegal_invocation';
  } else if (phase === 'request' && typeof message === 'string' && /\bdns\b/i.test(message)) {
    reason = 'dns';
  } else if (phase === 'request' && typeof message === 'string' && /\b(tls|ssl)\b/i.test(message)) {
    reason = 'tls';
  } else if (phase === 'request' && exception === 'TypeError') {
    reason = 'network';
  }

  // causeやメッセージにはURL・本文・Secretsが含まれ得るため、許可したコードだけを取り出す。
  let cause = error;
  let code: string | undefined;
  for (let depth = 0; depth < 3 && cause; depth++) {
    const candidate = property(cause, 'code');
    if (typeof candidate === 'string' && Object.hasOwn(transportReasons, candidate)) {
      code = candidate;
      reason = transportReasons[candidate];
      break;
    }
    cause = property(cause, 'cause');
  }

  return { phase, reason, exception, ...(code ? { code } : {}), ...(status === undefined ? {} : { status }) };
}

/** APIの応答値をそのまま記録せず、既知のMisskeyエラーコードだけを返す。 */
export function describeMisskeyCode(code: string | undefined): string | undefined {
  return code === undefined ? undefined : apiCodes.has(code) ? code : 'unrecognized';
}
