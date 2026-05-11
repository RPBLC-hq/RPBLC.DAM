import { useMemo } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Button,
  ErrorTile,
  RedactionLoader,
  ValueDetail,
  type ProtectionState,
  type ValueDetailMetaItem,
} from '@rpblc/design'

import { ApiError, api, apiPost } from '@/lib/api/client'
import { useI18n, type MessageKey } from '@/lib/i18n'
import type { WalletDetail, WalletItem } from './types'

/**
 * WalletInlineDetail — the detail surface that expands under an active
 * WalletCard row. Same data and mutations as a route-level detail page,
 * laid out as an inline panel so the row above stays visible (the
 * wallet metaphor: open the card without leaving the wallet).
 *
 * Seeded with the list item via `placeholderData` so the panel renders
 * immediately on open — no flicker — while the full detail (meta,
 * first_seen, reference) streams in behind it.
 */
export function WalletInlineDetail({ id, seed }: { id: string; seed: WalletItem }) {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const queryKey = ['wallet', 'detail', id] as const
  const placeholder = useMemo<WalletDetail>(
    () => ({
      item: seed,
      meta: [],
      first_seen: undefined,
      reference: `[${seed.id}]`,
    }),
    [seed],
  )
  const detail = useQuery({
    queryKey,
    queryFn: ({ signal }) =>
      api<WalletDetail>(`/wallet/${encodeURIComponent(id)}`, { signal }),
    placeholderData: placeholder,
  })

  const allow = useMutation({
    mutationFn: (party: string) =>
      apiPost<WalletDetail>(`/wallet/${encodeURIComponent(id)}/allow`, {
        party,
      }),
    onSuccess: (next) => queryClient.setQueryData(queryKey, next),
  })
  const revoke = useMutation({
    mutationFn: (party: string) =>
      apiPost<WalletDetail>(`/wallet/${encodeURIComponent(id)}/revoke`, {
        party,
      }),
    onSuccess: (next) => queryClient.setQueryData(queryKey, next),
  })
  const protectAll = useMutation({
    mutationFn: () =>
      apiPost<WalletDetail>(`/wallet/${encodeURIComponent(id)}/protect`, {}),
    onSuccess: (next) => queryClient.setQueryData(queryKey, next),
  })

  const mutationError =
    allow.error ?? revoke.error ?? protectAll.error ?? null
  const mutationCode =
    mutationError instanceof ApiError ? mutationError.message : undefined

  // With placeholderData seeded from the list item, `data` is available
  // immediately on first open. We render the panel right away and let the
  // real fetch fill in meta + reference in the background.
  if (!detail.data) {
    if (detail.isError) {
      const code = detail.error instanceof ApiError ? detail.error.message : undefined
      return (
        <ErrorTile
          message={t(detailErrorKey(code))}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => void detail.refetch()}
            >
              {t('walletDetail.tryAgain')}
            </Button>
          }
        />
      )
    }
    return (
      <div className="dam-wallet__inline-loading">
        <RedactionLoader
          redacted
          bars={4}
          width="11em"
          reason={t('walletDetail.loadingReason')}
          aria-label={t('walletDetail.loadingReason')}
          verbose
        />
      </div>
    )
  }

  return (
    <div className="dam-wallet__inline-detail">
      <ValueDetail
        kind={detail.data.item.kind}
        value={detail.data.item.value}
        state={detail.data.item.state as ProtectionState}
        meta={detailMeta(detail.data, t)}
        sharedWith={detail.data.item.shared_with.map((s) => ({
          name: s.name,
          since: s.since,
        }))}
        onAllow={(party) => allow.mutate(party)}
        onRevoke={(party) => revoke.mutate(party)}
        onProtectAll={() => protectAll.mutate()}
      />

      {mutationError && (
        <ErrorTile
          message={t(mutationErrorKey(mutationCode))}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => {
                allow.reset()
                revoke.reset()
                protectAll.reset()
              }}
            >
              {t('walletDetail.dismiss')}
            </Button>
          }
        />
      )}
    </div>
  )
}

function detailMeta(
  detail: WalletDetail,
  t: (key: MessageKey) => string,
): ValueDetailMetaItem[] {
  const items: ValueDetailMetaItem[] = detail.meta.map((m) => ({
    key: m.key,
    value: m.value,
    emphasis: m.emphasis,
  }))
  if (detail.item.last_seen) {
    items.push({
      key: t('walletDetail.lastSeen'),
      value: detail.item.last_seen,
    })
  }
  if (detail.first_seen) {
    items.push({
      key: t('walletDetail.firstSeen'),
      value: detail.first_seen,
    })
  }
  items.push({
    key: t('walletDetail.reference'),
    value: detail.reference,
  })
  return items
}

function detailErrorKey(code: string | undefined): MessageKey {
  if (code === 'wallet_value_missing') return 'walletDetail.error.missing'
  if (code === 'wallet_unreachable') return 'wallet.error.unreachable'
  if (code === 'daemon_unreachable') return 'wallet.error.daemon'
  return 'wallet.error.unknown'
}

function mutationErrorKey(code: string | undefined): MessageKey {
  if (code === 'consent_grant_failed') return 'walletDetail.error.grantFailed'
  if (code === 'consent_revoke_failed') return 'walletDetail.error.revokeFailed'
  if (code === 'not_implemented') return 'walletDetail.error.notImplemented'
  return 'walletDetail.error.unknown'
}
