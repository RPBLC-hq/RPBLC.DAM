export type WalletItemState = 'protected' | 'allowed' | 'revoked' | 'expired'

export type WalletShare = {
  name: string
  since?: string
}

export type WalletItem = {
  id: string
  kind: string
  value: string
  state: WalletItemState
  shared_with: WalletShare[]
  last_seen?: string
}

export type WalletList = {
  items: WalletItem[]
  total: number
}

export type WalletMetaEntry = {
  key: string
  value: string
  emphasis?: boolean
}

export type WalletDetail = {
  item: WalletItem
  meta: WalletMetaEntry[]
  first_seen?: string
  reference: string
}
