import { Link, useRouterState } from '@tanstack/react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AppFooter, AppFooterSpacer, Button } from '@rpblc/design'

import { ApiError, api, apiPost } from '@/lib/api/client'
import { useI18n, type MessageKey } from '@/lib/i18n'
import type { ConnectView } from '@/features/connect/types'

const CONNECT_QUERY_KEY = ['connect'] as const

type Surface = 'wallet' | 'settings' | 'activity' | 'connect' | 'other'

/**
 * AppShellFooter — wallet-feel route-aware footer for the tray.
 *
 * On `/connect`: three items — wallet, settings, and (when protected)
 * the disconnect/⏻ icon to pause protection.
 *
 * On non-connect pages: two items — `[connect]` back affordance and the
 * alternate primary surface. From the wallet, the alternate is
 * `activity` (the inverse: values DAM has seen flying past). From any
 * other non-connect page (settings, activity, fallback), the wallet is
 * the natural pivot.
 *
 * The 3-vs-2 contract is documented in
 * `RPBLC.Architecture/dam/web/specs/navigation.md`.
 */
export function AppShellFooter() {
  const { t } = useI18n()
  const path = useRouterState({ select: (s) => s.location.pathname })
  const surface = surfaceFor(path)

  const queryClient = useQueryClient()
  const connect = useQuery({
    queryKey: CONNECT_QUERY_KEY,
    queryFn: ({ signal }) => api<ConnectView>('/connect', { signal }),
  })
  const pause = useMutation({
    mutationFn: () => apiPost<ConnectView>('/connect/action', { step_id: 'pause' }),
    onSuccess: (view) => {
      queryClient.setQueryData(CONNECT_QUERY_KEY, view)
    },
  })

  const protectedNow = connect.data?.state === 'protected'
  const pauseFailed = pause.error instanceof ApiError

  if (surface === 'connect') {
    return (
      <AppFooter aria-label={t('footer.aria')}>
        <Link
          to="/wallet"
          className="rpblc-button rpblc-button--ghost rpblc-button--sm"
        >
          {t('footer.wallet')}
        </Link>
        <Link
          to="/settings"
          className="rpblc-button rpblc-button--ghost rpblc-button--sm"
        >
          {t('footer.settings')}
        </Link>
        <AppFooterSpacer />
        {protectedNow && (
          <Button
            variant="danger"
            size="sm"
            type="button"
            disabled={pause.isPending}
            onClick={() => pause.mutate()}
            aria-label={
              pauseFailed
                ? t('footer.pauseFailed')
                : t('footer.pauseProtection')
            }
            title={t('footer.pauseProtection')}
            className="dam-footer__icon-button"
          >
            ⏻
          </Button>
        )}
      </AppFooter>
    )
  }

  const alt = alternateSurface(surface)
  return (
    <AppFooter aria-label={t('footer.aria')}>
      <Link
        to="/connect"
        className="rpblc-button rpblc-button--ghost rpblc-button--sm"
      >
        {t('footer.backToConnect')}
      </Link>
      <AppFooterSpacer />
      <Link
        to={alt.path}
        className="rpblc-button rpblc-button--ghost rpblc-button--sm"
      >
        {t(alt.labelKey)}
      </Link>
    </AppFooter>
  )
}

function surfaceFor(path: string): Surface {
  if (path === '/' || path === '/connect') return 'connect'
  if (path === '/wallet' || path.startsWith('/wallet/')) return 'wallet'
  if (path === '/settings' || path.startsWith('/settings/')) return 'settings'
  if (path === '/activity') return 'activity'
  return 'other'
}

function alternateSurface(
  current: Surface,
): { path: '/wallet' | '/activity'; labelKey: MessageKey } {
  // Activity is reached only from the wallet, by design (the user said
  // the wallet's neighbour surface). From settings / activity / blank,
  // the wallet is the natural pivot.
  if (current === 'wallet') {
    return { path: '/activity', labelKey: 'footer.activity' }
  }
  return { path: '/wallet', labelKey: 'footer.wallet' }
}
