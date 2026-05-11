import { useEffect, useRef, useState } from 'react'
import { Link, useRouterState } from '@tanstack/react-router'

import { BrandActions, BrandStamp } from '@/features/navigation/BrandBar'
import { useI18n, type MessageKey } from '@/lib/i18n'

type PrimaryRoute = '/insights' | '/wallet' | '/allowed' | '/activity'
type SecondaryRoute = '/settings' | '/system' | '/health'

const PRIMARY: { path: PrimaryRoute; labelKey: MessageKey }[] = [
  { path: '/insights', labelKey: 'nav.insights' },
  { path: '/wallet', labelKey: 'nav.wallet' },
  { path: '/allowed', labelKey: 'nav.allowed' },
  { path: '/activity', labelKey: 'nav.activity' },
]

const SECONDARY: { path: SecondaryRoute; labelKey: MessageKey }[] = [
  { path: '/settings', labelKey: 'nav.settings' },
  { path: '/system', labelKey: 'nav.system' },
  { path: '/health', labelKey: 'nav.health' },
]

export function WebNavigation() {
  return (
    <header className="dam-app-nav" data-surface="web">
      <BrandStamp surface="web" />
      <PrimaryNav />
      <span className="dam-app-nav__rule" aria-hidden="true" />
      <SecondaryMenu />
      <BrandActions surface="web" />
    </header>
  )
}

function PrimaryNav() {
  const { t } = useI18n()
  const path = useRouterState({ select: (s) => s.location.pathname })
  return (
    <nav className="dam-web-nav" aria-label={t('nav.content')}>
      {PRIMARY.map((entry) => {
        const isActive =
          path === entry.path || path.startsWith(`${entry.path}/`)
        return (
          <Link
            key={entry.path}
            to={entry.path}
            className={`dam-web-nav__link${
              isActive ? ' dam-web-nav__link--active' : ''
            }`}
            aria-current={isActive ? 'page' : undefined}
          >
            {t(entry.labelKey)}
          </Link>
        )
      })}
    </nav>
  )
}

function SecondaryMenu() {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement | null>(null)
  const path = useRouterState({ select: (s) => s.location.pathname })
  const activeEntry = SECONDARY.find(
    (entry) => path === entry.path || path.startsWith(`${entry.path}/`),
  )

  useEffect(() => {
    if (!open) return
    const onClick = (event: MouseEvent) => {
      if (!ref.current) return
      if (!ref.current.contains(event.target as Node)) setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  // Close the menu when navigating.
  useEffect(() => {
    setOpen(false)
  }, [path])

  return (
    <div className="dam-web-menu" ref={ref}>
      <button
        type="button"
        className={`dam-web-menu__trigger${
          activeEntry ? ' dam-web-menu__trigger--active' : ''
        }`}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        {activeEntry ? t(activeEntry.labelKey) : t('nav.more')}
        <span className="dam-web-menu__chev" aria-hidden="true">›</span>
      </button>
      {open && (
        <ul className="dam-web-menu__list" role="menu">
          {SECONDARY.map((entry) => (
            <li key={entry.path} role="none">
              <Link
                to={entry.path}
                role="menuitem"
                className="dam-web-menu__item"
              >
                {t(entry.labelKey)}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
