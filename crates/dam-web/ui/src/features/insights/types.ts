export type InsightsRange = 'today' | '7d' | '30d' | 'all'

export type InsightsView = {
  range: string
  summary: InsightsSummary
  apps: AppRank[]
  kinds: KindRank[]
  events: SignificantEvent[]
}

export type InsightsSummary = {
  total: number
  kind_count: number
  app_count: number
  sentence: string
}

export type AppRank = {
  actor: string
  total: number
  redacted: number
  allowed: number
  denied: number
}

export type KindRank = {
  kind: string
  total: number
}

export type SignificantEvent = {
  id: number
  ts: number
  summary: string
}
