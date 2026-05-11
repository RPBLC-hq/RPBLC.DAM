export type AllowedView = {
  active: AllowedGrant[]
  expired: AllowedGrant[]
  revoked: AllowedGrant[]
}

export type AllowedGrant = {
  id: string
  party: string
  kind: string
  value: string
  since?: string
  expires_at?: string
}
