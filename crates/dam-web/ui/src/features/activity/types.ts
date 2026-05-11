export type ActivityDecision = 'granted' | 'sealed' | 'denied'

export type ActivityView = {
  events: ActivityEvent[]
  summary: {
    total: number
    granted: number
    sealed: number
    denied: number
  }
}

export type ActivityEvent = {
  id: number
  ts: number
  day: string
  actor: string
  kind: string
  decision: ActivityDecision
  purpose?: string
  audit_id: string
}
