import { Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import {
  Button,
  EmptyTile,
  ErrorTile,
  RedactionLoader,
  Section,
} from '@rpblc/design'

import { api } from '@/lib/api/client'
import { useI18n, type MessageKey } from '@/lib/i18n'
import type {
  HealthSummaryState,
  HealthView,
  IntegrationStatus,
  RecentEvent,
  Severity,
} from './types'

const QUERY_KEY = 'health' as const

export function HealthPage() {
  const { t } = useI18n()
  const health = useQuery({
    queryKey: [QUERY_KEY] as const,
    queryFn: ({ signal }) => api<HealthView>('/health', { signal }),
  })

  return (
    <section className="dam-health" aria-label={t('health.aria')}>
      <h1 className="dam-health__heading">{t('health.heading')}</h1>

      {health.isPending ? (
        <RedactionLoader
          redacted
          bars={4}
          width="14em"
          reason={t('health.loadingReason')}
          aria-label={t('health.loadingReason')}
          verbose
        />
      ) : health.isError || !health.data ? (
        <ErrorTile
          message={t('health.error.unknown')}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => void health.refetch()}
            >
              {t('connect.checkAgain')}
            </Button>
          }
        />
      ) : (
        <HealthBody view={health.data} />
      )}
    </section>
  )
}

function HealthBody({ view }: { view: HealthView }) {
  const { t } = useI18n()
  return (
    <div className="dam-health__stack">
      <SummaryTile state={view.summary.state} />

      <Section title={t('health.section.daemon')} density="compact">
        <dl className="dam-health__rows">
          <Row
            label={t('health.daemon.connected')}
            value={view.daemon.connected ? '✓' : '—'}
          />
          {view.daemon.pid !== undefined && (
            <Row label={t('health.daemon.pid')} value={view.daemon.pid} />
          )}
          {view.daemon.version && (
            <Row label={t('health.daemon.version')} value={view.daemon.version} />
          )}
          {view.daemon.listen && (
            <Row label={t('health.daemon.listen')} value={view.daemon.listen} />
          )}
        </dl>
        {!view.daemon.connected && (
          <div className="dam-health__actions">
            <Link
              to="/connect"
              className="rpblc-button rpblc-button--primary rpblc-button--sm"
            >
              {t('health.connectAction')}
            </Link>
          </div>
        )}
      </Section>

      <Section title={t('health.section.network')} density="compact">
        <dl className="dam-health__rows">
          <Row
            label={t('health.network.mode')}
            value={view.network.mode || t('health.unknown')}
          />
        </dl>
      </Section>

      <Section title={t('health.section.trust')} density="compact">
        <dl className="dam-health__rows">
          <Row
            label={t('health.trust.mode')}
            value={view.trust.mode || t('health.unknown')}
          />
          <Row
            label={t('health.trust.localCa')}
            value={
              view.trust.local_ca_installed
                ? t('health.trust.installed')
                : t('health.trust.notInstalled')
            }
          />
        </dl>
        {!view.trust.local_ca_installed && (
          <div className="dam-health__actions">
            <Link
              to="/connect"
              className="rpblc-button rpblc-button--primary rpblc-button--sm"
            >
              {t('health.installCa')}
            </Link>
          </div>
        )}
      </Section>

      <Section title={t('health.section.integrations')} density="compact">
        {view.integrations.profiles.length === 0 ? (
          <EmptyTile message={t('health.empty.recent')} />
        ) : (
          <ul className="dam-health__profiles">
            {view.integrations.profiles.map((profile) => (
              <li key={profile.id}>
                <IntegrationRow profile={profile} />
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t('health.section.recent')} density="compact">
        {view.recent.events.length === 0 ? (
          <EmptyTile message={t('health.empty.recent')} />
        ) : (
          <ul className="dam-health__events">
            {view.recent.events.map((event, idx) => (
              <li key={`${event.ts}-${idx}`}>
                <RecentEventRow event={event} />
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  )
}

function SummaryTile({ state }: { state: HealthSummaryState }) {
  const { t } = useI18n()
  return (
    <div className={`dam-health__summary dam-health__summary--${state}`}>
      <span className="dam-health__summary-state">{state.replace('_', ' ')}</span>
      <p className="dam-health__summary-msg">{t(summaryMessageKey(state))}</p>
    </div>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="dam-health__row">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  )
}

function IntegrationRow({ profile }: { profile: IntegrationStatus }) {
  return (
    <div className="dam-health__profile">
      <span className="dam-health__profile-id">[{profile.id}]</span>
      <span className="dam-health__profile-state">{profile.install_state}</span>
    </div>
  )
}

function RecentEventRow({ event }: { event: RecentEvent }) {
  const { locale } = useI18n()
  const stamp = new Date(event.ts * 1000).toLocaleTimeString(locale, {
    hour: '2-digit',
    minute: '2-digit',
  })
  return (
    <article
      className={`dam-health__event dam-health__event--${event.severity}`}
      data-severity={event.severity}
    >
      <span className="dam-health__event-ts">{stamp}</span>
      <span className="dam-health__event-msg">{event.message}</span>
      <span className="dam-health__event-sev">{severityShort(event.severity)}</span>
    </article>
  )
}

function summaryMessageKey(state: HealthSummaryState): MessageKey {
  if (state === 'healthy') return 'health.summaryHealthy'
  if (state === 'degraded') return 'health.summaryDegraded'
  return 'health.summaryNotConnected'
}

function severityShort(severity: Severity): string {
  if (severity === 'error') return 'error'
  if (severity === 'warn') return 'warn'
  return 'info'
}
