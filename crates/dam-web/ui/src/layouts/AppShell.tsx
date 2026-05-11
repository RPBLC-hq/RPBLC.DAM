import { Outlet } from '@tanstack/react-router'

import { TrayNavigation } from '@/features/navigation/TrayNavigation'
import { WebNavigation } from '@/features/navigation/WebNavigation'
import { useTrayBridge } from '@/features/navigation/tray-bridge'
import { useEventStream } from '@/lib/api/events'
import { useI18n } from '@/lib/i18n'
import { resolveSurface } from '@/lib/surface'

export function AppShell() {
  const surface = resolveSurface()
  const { t } = useI18n()
  useTrayBridge(surface)
  useEventStream()

  if (surface === 'tray') {
    return (
      <TrayNavigation>
        <Outlet />
      </TrayNavigation>
    )
  }

  return (
    <div className="dam-web-frame">
      <WebNavigation />
      <main className="dam-app-content dam-app-content--web" aria-label={t('nav.content')}>
        <Outlet />
      </main>
    </div>
  )
}
