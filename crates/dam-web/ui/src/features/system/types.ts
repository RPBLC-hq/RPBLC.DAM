export type Severity = 'info' | 'warn' | 'error'

export type SystemScope =
  | 'issues'
  | 'all'
  | 'daemon'
  | 'network'
  | 'filter'
  | 'mcp'
  | 'provider'

export type SystemFeed = {
  events: SystemLogEvent[]
  counts: SystemCounts
}

export type SystemCounts = {
  info: number
  warn: number
  error: number
}

export type SystemLogEvent = {
  id: number
  ts: number
  module: string
  severity: Severity
  message: string
  details: SystemDetail[]
}

export type SystemDetail = {
  label: string
  value: string
}
