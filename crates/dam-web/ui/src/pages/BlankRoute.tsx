import { Link, useRouterState } from '@tanstack/react-router'
import { EmptyTile } from '@rpblc/design'

import { useI18n } from '@/lib/i18n'

export function BlankRoute() {
  const { t } = useI18n()
  const path = useRouterState({ select: (s) => s.location.pathname })

  return (
    <section className="dam-blank" aria-label={t('blank.aria')}>
      <EmptyTile
        message={`${t('blank.notReady')} ${path}`}
        action={
          <Link
            to="/connect"
            className="rpblc-button rpblc-button--ghost rpblc-button--sm"
          >
            {t('blank.backToConnect')}
          </Link>
        }
      />
    </section>
  )
}
