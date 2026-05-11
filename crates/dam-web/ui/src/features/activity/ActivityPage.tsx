import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Button,
  EmptyTile,
  ErrorTile,
  RedactionLoader,
  SearchBar,
  SegmentedControl,
} from '@rpblc/design'

import { ApiError, api } from '@/lib/api/client'
import { useI18n, type MessageKey } from '@/lib/i18n'
import { resolveSurface } from '@/lib/surface'
import { useUrlSearchParam, useUrlSearchString } from '@/lib/url-search'
import type { ActivityDecision, ActivityEvent, ActivityView } from './types'

type Decision = 'all' | ActivityDecision
type Since = 'today' | '7d' | '30d' | 'all'

const DECISION_VALUES: Decision[] = ['all', 'granted', 'sealed', 'denied']
const SINCE_VALUES: Since[] = ['today', '7d', '30d', 'all']

const QUERY_KEY = 'activity' as const

export function ActivityPage() {
  const { t, locale } = useI18n()
  const surface = resolveSurface()
  const formatter = useMemo(
    () => new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }),
    [locale],
  )

  // Filters: q + decision + since. URL-stable so refresh and share
  // preserve state. Tray surface skips the URL plumbing (memory router)
  // but the same state shape applies — just no surfaced filter UI on
  // tray, since `recently-scanned` there is a fixed seed.
  const [query, setQuery] = useUrlSearchString('q')
  const [decision, setDecision] = useUrlSearchParam<Decision>(
    'decision',
    'all',
    isDecision,
  )
  const [since, setSince] = useUrlSearchParam<Since>('since', '7d', isSince)

  const activity = useQuery({
    queryKey: [QUERY_KEY, { query, decision, since }] as const,
    queryFn: ({ signal }) => {
      const params = new URLSearchParams()
      if (query) params.set('q', query)
      if (decision !== 'all') params.set('decision', decision)
      const sinceSeconds = sinceTimestamp(since)
      if (sinceSeconds !== null) params.set('since', String(sinceSeconds))
      const search = params.toString()
      return api<ActivityView>(
        `/activity${search ? `?${search}` : ''}`,
        { signal },
      )
    },
    refetchInterval: 5_000,
  })

  const decisionOptions = DECISION_VALUES.map((value) => ({
    value,
    label: t(decisionLabelKey(value)),
  }))
  const sinceOptions = SINCE_VALUES.map((value) => ({
    value,
    label: t(sinceLabelKey(value)),
  }))

  const errorCode =
    activity.error instanceof ApiError ? activity.error.message : undefined

  return (
    <section className="dam-activity" aria-label={t('activity.aria')}>
      <header className="dam-activity__header">
        <h1 className="dam-activity__heading">{t('activity.heading')}</h1>
        <p className="dam-activity__hint">{t('activity.hint')}</p>
        {surface === 'web' && (
          <div className="dam-activity__filters">
            <SearchBar
              value={query}
              onValueChange={setQuery}
              aria-label={t('activity.searchAria')}
              placeholder={t('activity.searchPlaceholder')}
            />
            <SegmentedControl<Decision>
              value={decision}
              onValueChange={setDecision}
              options={decisionOptions}
              aria-label={t('activity.decisionAria')}
            />
            <SegmentedControl<Since>
              value={since}
              onValueChange={setSince}
              options={sinceOptions}
              aria-label={t('activity.sinceAria')}
            />
          </div>
        )}
      </header>

      <div className="dam-activity__list">
        {activity.isPending ? (
          <LoadingState />
        ) : activity.isError ? (
          <ErrorTile
            message={t(errorMessageKey(errorCode))}
            action={
              <Button
                variant="ghost"
                size="sm"
                type="button"
                onClick={() => void activity.refetch()}
              >
                {t('activity.tryAgain')}
              </Button>
            }
          />
        ) : (activity.data?.events.length ?? 0) === 0 ? (
          <EmptyTile message={t('activity.empty')} />
        ) : (
          activity.data!.events.map((item) => (
            <ActivityRow
              key={item.id}
              item={item}
              relative={(seconds) => relativePast(formatter, seconds)}
            />
          ))
        )}
      </div>
    </section>
  )
}

function ActivityRow({
  item,
  relative,
}: {
  item: ActivityEvent
  relative: (secondsAgo: number) => string
}) {
  const { t } = useI18n()
  const ago = relative(Math.max(0, Math.floor(Date.now() / 1000) - item.ts))
  const decision = t(activityDecisionLabelKey(item.decision))

  return (
    <article className="dam-activity__row">
      <div className="dam-activity__lead">
        <span className="dam-activity__time">{ago}</span>
        <span className="dam-activity__kind">[{item.kind}]</span>
        <span className="dam-activity__value">{decision}</span>
      </div>
      <span className="dam-activity__actor">
        {t('activity.from')} <b>{item.actor}</b>
      </span>
      <div className="dam-activity__actions">
        <Button
          variant="primary"
          size="sm"
          bracketed
          type="button"
          disabled
          title={t('activity.actionParked')}
        >
          {t('activity.add')}
        </Button>
        <Button
          variant="secondary"
          size="sm"
          bracketed
          type="button"
          disabled
          title={t('activity.actionParked')}
        >
          {t('activity.allowOnce')}
        </Button>
      </div>
    </article>
  )
}

function LoadingState() {
  const { t } = useI18n()
  return (
    <div className="dam-activity__loading">
      <RedactionLoader
        redacted
        bars={4}
        width="11em"
        reason={t('activity.loadingReason')}
        aria-label={t('activity.loadingReason')}
        verbose
      />
    </div>
  )
}

function relativePast(formatter: Intl.RelativeTimeFormat, secondsAgo: number): string {
  if (secondsAgo < 60) return formatter.format(-secondsAgo, 'second')
  if (secondsAgo < 3_600) return formatter.format(-Math.floor(secondsAgo / 60), 'minute')
  if (secondsAgo < 86_400) return formatter.format(-Math.floor(secondsAgo / 3_600), 'hour')
  return formatter.format(-Math.floor(secondsAgo / 86_400), 'day')
}

function errorMessageKey(code: string | undefined): MessageKey {
  if (code === 'daemon_unreachable') return 'wallet.error.daemon'
  return 'activity.error.unknown'
}

function isDecision(value: string): value is Decision {
  return (DECISION_VALUES as readonly string[]).includes(value)
}

function isSince(value: string): value is Since {
  return (SINCE_VALUES as readonly string[]).includes(value)
}

function decisionLabelKey(value: Decision): MessageKey {
  if (value === 'granted') return 'activity.decision.granted'
  if (value === 'sealed') return 'activity.decision.sealed'
  if (value === 'denied') return 'activity.decision.denied'
  return 'activity.decision.all'
}

function activityDecisionLabelKey(value: ActivityDecision): MessageKey {
  if (value === 'granted') return 'activity.decision.granted'
  if (value === 'sealed') return 'activity.decision.sealed'
  return 'activity.decision.denied'
}

function sinceLabelKey(value: Since): MessageKey {
  if (value === 'today') return 'activity.since.today'
  if (value === '7d') return 'activity.since.7d'
  if (value === '30d') return 'activity.since.30d'
  return 'activity.since.all'
}

function sinceTimestamp(value: Since): number | null {
  if (value === 'all') return null
  const now = Math.floor(Date.now() / 1000)
  if (value === 'today') {
    const start = new Date()
    start.setHours(0, 0, 0, 0)
    return Math.floor(start.getTime() / 1000)
  }
  if (value === '30d') return now - 30 * 86_400
  return now - 7 * 86_400
}
