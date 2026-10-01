// Retry read-only transport failures; deterministic RPC/contract errors escape.
export function isTransientRpcError(error) {
  let current = error;
  for (let depth = 0; current && depth < 6; depth++, current = current.cause) {
    const status = Number(current.status || current.statusCode);
    if (status === 429 || (status >= 500 && status <= 599)) return true;
    if (status >= 400 && status <= 499) return false;
    if (current.code === -32603) return true; // Server internal error on a read-only RPC.
    if (typeof current.code === 'number' && current.code < 0) return false;
    if (['ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 'ECONNREFUSED', 'EPIPE',
         'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_SOCKET'].includes(current.code)) return true;
    const message = String(current.shortMessage || current.message || '');
    if (/fetch failed|network (?:error|request failed)|socket hang up|connection (?:reset|closed)|HTTP request failed/i.test(message)) return true;
  }
  return false;
}

export async function retryRpcRead(operation, {attempts = 4, sleep = (ms) => new Promise(r => setTimeout(r, ms)), onRetry = () => {}} = {}) {
  for (let attempt = 1; ; attempt++) {
    try {return await operation();}
    catch (error) {
      if (!isTransientRpcError(error) || attempt >= attempts) throw error;
      onRetry(attempt, attempts);
      await sleep(Math.min(500 * 2 ** (attempt - 1), 4000));
    }
  }
}
