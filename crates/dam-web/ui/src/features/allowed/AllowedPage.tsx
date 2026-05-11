import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Button,
  EmptyTile,
  ErrorTile,
  RedactionLoader,
  SearchBar,
  WalletCard,
} from '@rpblc/design'

import { api } from '@/lib/api/client'
import { useI18n } from '@/lib/i18n'
import { useUrlSearchString } from '@/lib/url-search'
import type { AllowedGrant, AllowedView } from './types'

const QUERY_KEY = 'allowed' as const

export function AllowedPage() {
  const { t } = useI18n()
  const [query, setQuery] = useUrlSearchString('q')
  const [showExpired, setShowExpired] = useState(false)

  const allowed = useQuery({
    queryKey: [QUERY_KEY, query] as const,
    queryFn: ({ signal }) =>
      api<AllowedView>(
        `/allowed${query ? `?q=${encodeURIComponent(query)}` : ''}`,
        { signal },
      ),
  })

  return (
    <section className="dam-allowed" aria-label={t('allowed.aria')}>
      <header className="dam-allowed__head">
        <h1 className="dam-allowed__heading">{t('allowed.heading')}</h1>
        <SearchBar
          value={query}
          onValueChange={setQuery}
          aria-label={t('allowed.searchAria')}
          placeholder={t('allowed.searchPlaceholder')}
        />
      </header>

      {allowed.isPending ? (
        <RedactionLoader
          redacted
          bars={4}
          width="14em"
          reason={t('allowed.loadingReason')}
          aria-label={t('allowed.loadingReason')}
          verbose
        />
      ) : allowed.isError || !allowed.data ? (
        <ErrorTile
          message={t('allowed.error.unknown')}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => void allowed.refetch()}
            >
              {t('allowed.tryAgain')}
            </Button>
          }
        />
      ) : allowed.data.active.length === 0 &&
        allowed.data.expired.length === 0 &&
        allowed.data.revoked.length === 0 ? (
        <EmptyTile message={t('allowed.empty')} />
      ) : (
        <AllowedBody
          view={allowed.data}
          showExpired={showExpired}
          onToggleExpired={() => setShowExpired((v) => !v)}
        />
      )}
    </section>
  )
}

function AllowedBody({
  view,
  showExpired,
  onToggleExpired,
}: {
  view: AllowedView
  showExpired: boolean
  onToggleExpired: () => void
}) {
  const { t } = useI18n()
  const archived = [...view.expired, ...view.revoked]

  return (
    <div className="dam-allowed__list">
      {view.active.length === 0 ? (
        <EmptyTile message={t('allowed.empty')} />
      ) : (
        <ul className="dam-allowed__rows">
          {view.active.map((grant) => (
            <li key={grant.id}>
              <AllowedRow grant={grant} />
            </li>
          ))}
        </ul>
      )}

      {archived.length > 0 && (
        <div className="dam-allowed__archive">
          <Button
            variant="ghost"
            size="sm"
            type="button"
            onClick={onToggleExpired}
            aria-expanded={showExpired}
          >
            {t('allowed.expiredDisclosure')} ({archived.length})
          </Button>
          {showExpired && (
            <ul className="dam-allowed__rows dam-allowed__rows--archive">
              {archived.map((grant) => (
                <li key={grant.id}>
                  <AllowedRow grant={grant} archived />
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}

function AllowedRow({
  grant,
  archived,
}: {
  grant: AllowedGrant
  archived?: boolean
}) {
  const { t } = useI18n()
  return (
    <WalletCard
      kind={grant.kind}
      value={grant.value}
      state={archived ? 'revoked' : 'allowed'}
      href={`/wallet/${encodeURIComponent(grant.id)}`}
      meta={
        grant.since && (
          <>
            {t('wallet.meta.sharedWith')} <b>{grant.party}</b>
            {grant.expires_at ? <> · {t('allowed.until')} {grant.expires_at}</> : null}
          </>
        )
      }
    />
  )
}
