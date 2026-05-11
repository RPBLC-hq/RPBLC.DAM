export type ConnectState = 'protected' | 'paused' | 'disconnected' | 'degraded' | 'needs_setup'

export type ConnectView = {
  state: ConnectState
  message: string
  proxy_url: string | null
  protected_since_unix?: number | null
  pending_count: number
  counts: ConnectCounts
  setup_plan: SetupPlan | null
}

export type ConnectCounts = {
  grants: number
  blocked_today: number
  apps_mediated: number
}

export type PendingRequestsView = {
  items: PendingRequest[]
}

export type PendingRequest = {
  id: string
  actor: string
  value_label: string
  value_preview?: string
  purpose: string
  expires_in_sec: number
}

export type SetupPlan = {
  steps: SetupStep[]
  current_step_id: string | null
}

export type SetupStepState = 'todo' | 'current' | 'done' | 'blocked' | 'failed'

export type SetupStep = {
  id: string
  label: string
  state: SetupStepState
  reason_code?: string
}
