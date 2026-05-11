export type HealthView = {
  summary: HealthSummary
  daemon: DaemonSection
  network: NetworkSection
  trust: TrustSection
  integrations: IntegrationsSection
  recent: RecentSection
}

export type HealthSummaryState = 'healthy' | 'degraded' | 'not_connected'

export type HealthSummary = {
  state: HealthSummaryState
  message: string
}

export type DaemonSection = {
  connected: boolean
  pid?: number
  version?: string
  listen?: string
}

export type NetworkSection = {
  mode: string
}

export type TrustSection = {
  mode: string
  local_ca_installed: boolean
}

export type IntegrationsSection = {
  profiles: IntegrationStatus[]
}

export type IntegrationStatus = {
  id: string
  install_state: string
}

export type RecentSection = {
  events: RecentEvent[]
}

export type Severity = 'info' | 'warn' | 'error'

export type RecentEvent = {
  ts: number
  message: string
  severity: Severity
}
