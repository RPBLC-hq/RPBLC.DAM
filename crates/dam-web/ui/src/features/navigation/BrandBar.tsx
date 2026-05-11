import { Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { BracketMark, ProtectionMark } from '@rpblc/design'

import { api } from '@/lib/api/client'
import { useI18n } from '@/lib/i18n'
import type { Surface } from '@/lib/surface'
import type { ConnectView } from '@/features/connect/types'

const RPBLC_HOME = 'https://rpblc.com'
const CONNECT_QUERY_KEY = ['connect'] as const

export function BrandStamp({ surface }: { surface: Surface }) {
  const { t } = useI18n()
  const damLabel = surface === 'tray' ? t('nav.openDamInBrowser') : t('nav.damHome')

  return (
    <div className="dam-brand-stamp">
      <a
        className="dam-brand-stamp__mark"
        href={RPBLC_HOME}
        target="_blank"
        rel="noreferrer"
        aria-label={t('nav.rpblcHome')}
        data-tray-external={surface === 'tray' ? 'rpblc' : undefined}
      >
        {/* 14px matches the design system's canonical brand-bar mark
            (see TrayShell + DamConnect demos). Below the 24px optical-
            small threshold so the BracketMark auto-applies its `--sm`
            modifier and the colon renders in `--accent-bright` to
            survive at this size. */}
        <BracketMark size={14} />
      </a>
      <a
        className="dam-brand-stamp__product"
        href="/"
        target={surface === 'tray' ? '_blank' : undefined}
        rel={surface === 'tray' ? 'noreferrer' : undefined}
        aria-label={damLabel}
        data-tray-external={surface === 'tray' ? 'dam-web-tab' : undefined}
      >
        DAM
      </a>
    </div>
  )
}

export function BrandActions({ surface: _surface }: { surface: Surface }) {
  const { t } = useI18n()
  const connect = useQuery({
    queryKey: CONNECT_QUERY_KEY,
    queryFn: ({ signal }) => api<ConnectView>('/connect', { signal }),
  })

  const pendingCount = connect.data?.pending_count ?? 0
  const isProtected = connect.data?.state === 'protected'

  return (
    <div className="dam-brand-actions">
      {isProtected ? (
        <ProtectionMark
          className="dam-app-nav__protection"
          state="protected"
          label={t('nav.protected')}
        />
      ) : (
        <span className="dam-app-nav__off">{t('nav.off')}</span>
      )}
      {pendingCount > 0 && (
        <Link
          to="/connect"
          className="dam-app-nav__pending"
          aria-label={`${pendingCount} ${t('nav.pendingRequests')}`}
        >
          <span className="dam-app-nav__pending-bracket" aria-hidden="true">[</span>
          <span className="dam-app-nav__pending-count">{pendingCount}</span>
          <span className="dam-app-nav__pending-bracket" aria-hidden="true">]</span>
        </Link>
      )}
    </div>
  )
}
