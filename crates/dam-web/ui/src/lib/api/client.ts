import { trayPostToken } from '@/lib/surface'

type ErrorEnvelope = {
  ok: false
  code?: string
  retriable?: boolean
}

type OkEnvelope<T> = {
  ok: true
  data: T
}

type RequestOptions = {
  signal?: AbortSignal
  method?: 'GET' | 'POST'
  body?: unknown
}

export class ApiError extends Error {
  status: number
  retriable: boolean

  constructor(status: number, envelope?: ErrorEnvelope) {
    super(envelope?.code ?? 'unknown')
    this.status = status
    this.retriable = envelope?.retriable ?? true
  }
}

export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    accept: 'application/json',
  }
  if (opts.body !== undefined) headers['content-type'] = 'application/json'

  const trayToken = trayPostToken()
  if (trayToken) headers['x-dam-web-tray-token'] = trayToken

  const response = await fetch(`/api/v1${path}`, {
    method: opts.method ?? 'GET',
    headers,
    signal: opts.signal,
    credentials: 'same-origin',
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  })

  let payload: unknown = null
  try {
    payload = await response.json()
  } catch {
    payload = null
  }

  if (!response.ok || (payload as { ok?: boolean } | null)?.ok === false) {
    throw new ApiError(response.status, payload as ErrorEnvelope)
  }

  return (payload as OkEnvelope<T>).data
}

export function apiPost<T>(path: string, body: unknown, opts: RequestOptions = {}): Promise<T> {
  return api<T>(path, { ...opts, method: 'POST', body })
}
