import type {
  AnalysisPage,
  AnalysisResult,
  CampaignGraph,
  CustodyEvent,
  Health,
  MailboxStatus,
  Stats,
} from './types'

const BASE = import.meta.env.VITE_API_BASE ?? '/api'

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, init)
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`
    try {
      const body = await response.json()
      if (typeof body.detail === 'string') message = body.detail
      else if (Array.isArray(body.detail)) message = body.detail.map((d: { msg: string }) => d.msg).join('; ')
    } catch {
      // non-JSON error body; keep the status line
    }
    throw new ApiError(response.status, message)
  }
  return response.status === 204 ? (undefined as T) : response.json()
}

export interface ListParams {
  q?: string
  level?: string
  verdict?: string
  limit?: number
  offset?: number
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') search.set(key, String(value))
  }
  const text = search.toString()
  return text ? `?${text}` : ''
}

export const api = {
  health: (signal?: AbortSignal) => request<Health>('/health', { signal }),

  analyzeFile: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return request<AnalysisResult>('/analyses', { method: 'POST', body: form })
  },

  analyzeRaw: (raw: string) => {
    const form = new FormData()
    form.append('raw', raw)
    return request<AnalysisResult>('/analyses', { method: 'POST', body: form })
  },

  list: (params: ListParams, signal?: AbortSignal) =>
    request<AnalysisPage>(`/analyses${query({ ...params })}`, { signal }),

  get: (id: string, signal?: AbortSignal) => request<AnalysisResult>(`/analyses/${id}`, { signal }),

  remove: (id: string) => request<void>(`/analyses/${id}`, { method: 'DELETE' }),

  custody: (id: string, signal?: AbortSignal) => request<CustodyEvent[]>(`/analyses/${id}/custody`, { signal }),

  graph: (analysisId?: string, signal?: AbortSignal) =>
    request<CampaignGraph>(`/graph${query({ analysis_id: analysisId })}`, { signal }),

  stats: (signal?: AbortSignal) => request<Stats>('/stats', { signal }),

  mailbox: (signal?: AbortSignal) => request<MailboxStatus>('/mailbox', { signal }),

  mailboxAction: (action: 'check' | 'pause' | 'resume') =>
    request<MailboxStatus>(`/mailbox/${action}`, { method: 'POST' }),

  mailboxScan: (count: number) => request<MailboxStatus>(`/mailbox/scan${query({ count })}`, { method: 'POST' }),

  reportUrl: (id: string) => `${BASE}/analyses/${id}/report.pdf`,
  evidenceUrl: (id: string) => `${BASE}/analyses/${id}/evidence`,
}
