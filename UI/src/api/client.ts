// Shared fetch and error handling for the scanner API.

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function readErrorMessage(value: unknown): string | null {
  if (typeof value !== 'object' || value === null || !('error' in value)) return null;
  const error = (value as { error?: unknown }).error;
  return typeof error === 'string' ? error : null;
}

/**
 * Fetch helper with uniform error mapping. Prefers the server-provided
 * `error` field, then the caller's per-status message, then `HTTP <code>`.
 */
export async function apiFetch<T>(
  url: string,
  init: RequestInit,
  statusMessages: Record<number, string> = {},
): Promise<T> {
  const response = await fetch(url, init);

  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    // non-JSON response body
  }

  if (!response.ok) {
    const message = readErrorMessage(data) ?? statusMessages[response.status] ?? `HTTP ${response.status}`;
    throw new ApiError(response.status, message);
  }

  return data as T;
}
