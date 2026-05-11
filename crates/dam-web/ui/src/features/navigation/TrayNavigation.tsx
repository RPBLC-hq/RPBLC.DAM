import { BrandActions, BrandStamp } from '@/features/navigation/BrandBar'
import { AppShellFooter } from '@/features/navigation/AppShellFooter'
import { useI18n } from '@/lib/i18n'
import type { ReactNode } from 'react'

export function TrayNavigation({ children }: { children?: ReactNode }) {
  const { t } = useI18n()

  return (
    <div className="dam-tray-frame dam-tray-frame--nav-only">
      <header className="dam-app-nav" data-surface="tray">
        <BrandStamp surface="tray" />
        <span className="dam-app-nav__rule" aria-hidden="true" />
        <BrandActions surface="tray" />
      </header>
      <main className="dam-app-content dam-app-content--tray" aria-label={t('nav.content')}>
        {children}
      </main>
      <AppShellFooter />
    </div>
  )
}
