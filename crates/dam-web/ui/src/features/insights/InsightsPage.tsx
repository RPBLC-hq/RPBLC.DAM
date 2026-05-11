import { Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import {
  Button,
  EmptyTile,
  ErrorTile,
  RedactionLoader,
  SegmentedControl,
  Section,
  Stat,
} from '@rpblc/design'

import { api } from '@/lib/api/client'
import { useI18n, type MessageKey } from '@/lib/i18n'
import { useUrlSearchParam } from '@/lib/url-search'
import type {
  AppRank,
  InsightsRange,
  InsightsView,
  KindRank,
  SignificantEvent,
} from './types'

const RANGE_VALUES: InsightsRange[] = ['today', '7d', '30d', 'all']
const RANGE_PARAM = 'range'
const RANGE_DEFAULT: InsightsRange = '7d'

export function InsightsPage() {
  const { t } = useI18n()
  const [range, setRange] = useUrlSearchParam<InsightsRange>(
    RANGE_PARAM,
    RANGE_DEFAULT,
    isInsightsRange,
  )
  const insights = useQuery({
    queryKey: ['insights', range] as const,
    queryFn: ({ signal }) =>
      api<InsightsView>(`/insights?range=${encodeURIComponent(range)}`, { signal }),
  })

  const rangeOptions = RANGE_VALUES.map((value) => ({
    value,
    label: t(rangeLabelKey(value)),
  }))

  return (
    <section className="dam-insights" aria-label={t('insights.aria')}>
      <header className="dam-insights__head">
        <h1 className="dam-insights__heading">{t('insights.heading')}</h1>
        <SegmentedControl<InsightsRange>
          value={range}
          onValueChange={setRange}
          options={rangeOptions}
          aria-label={t('insights.rangeAria')}
        />
      </header>

      {insights.isPending ? (
        <RedactionLoader
          redacted
          bars={4}
          width="14em"
          reason={t('insights.loadingReason')}
          aria-label={t('insights.loadingReason')}
          verbose
        />
      ) : insights.isError || !insights.data ? (
        <ErrorTile
          message={t('insights.error.unknown')}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => void insights.refetch()}
            >
              {t('connect.checkAgain')}
            </Button>
          }
        />
      ) : insights.data.summary.total === 0 ? (
        <EmptyTile
          message={
            <>
              <span className="dam-insights__empty-title">
                {t('insights.empty.title')}
              </span>
              <span className="dam-insights__empty-body">
                {t('insights.empty.body')}
              </span>
            </>
          }
        />
      ) : (
        <InsightsBody view={insights.data} />
      )}
    </section>
  )
}

function InsightsBody({ view }: { view: InsightsView }) {
  const { locale, t } = useI18n()
  const formatter = new Intl.NumberFormat(locale)

  return (
    <div className="dam-insights__stack">
      <Stat
        className="dam-insights__hero"
        value={formatter.format(view.summary.total)}
        label={t('insights.metricLabel')}
        source={view.summary.sentence}
      />

      {view.apps.length > 0 && (
        <Section title={t('insights.appsHeading')} density="compact">
          <ol className="dam-insights__rank">
            {view.apps.map((app) => (
              <li key={app.actor}>
                <AppRankRow row={app} formatter={formatter} />
              </li>
            ))}
          </ol>
        </Section>
      )}

      {view.kinds.length > 0 && (
        <Section title={t('insights.kindsHeading')} density="compact">
          <ol className="dam-insights__rank">
            {view.kinds.map((kind) => (
              <li key={kind.kind}>
                <KindRankRow row={kind} formatter={formatter} />
              </li>
            ))}
          </ol>
        </Section>
      )}

      {view.events.length > 0 && (
        <Section title={t('insights.eventsHeading')} density="compact">
          <ol className="dam-insights__events">
            {view.events.map((event) => (
              <li key={event.id}>
                <SignificantEventRow event={event} />
              </li>
            ))}
          </ol>
        </Section>
      )}
    </div>
  )
}

function AppRankRow({
  row,
  formatter,
}: {
  row: AppRank
  formatter: Intl.NumberFormat
}) {
  const { t } = useI18n()
  const total = row.total || 1
  const redactedPct = (row.redacted / total) * 100
  const allowedPct = (row.allowed / total) * 100
  const deniedPct = Math.max(0, 100 - redactedPct - allowedPct)

  return (
    <Link
      to="/activity"
      search={{ q: row.actor }}
      className="dam-insights__rank-row"
    >
      <span className="dam-insights__rank-name">[{row.actor}]</span>
      <span className="dam-insights__rank-count">{formatter.format(row.total)}</span>
      <span
        className="dam-insights__rank-bar"
        role="img"
        aria-label={`${Math.round(redactedPct)}% ${t('insights.legendRedacted')}, ${Math.round(allowedPct)}% ${t('insights.legendAllowed')}`}
      >
        <span
          className="dam-insights__rank-bar-fill dam-insights__rank-bar-fill--redacted"
          style={{ flexBasis: `${redactedPct}%` }}
        />
        <span
          className="dam-insights__rank-bar-fill dam-insights__rank-bar-fill--allowed"
          style={{ flexBasis: `${allowedPct}%` }}
        />
        <span
          className="dam-insights__rank-bar-fill dam-insights__rank-bar-fill--denied"
          style={{ flexBasis: `${deniedPct}%` }}
        />
      </span>
      <span className="dam-insights__rank-legend">
        {`${Math.round(redactedPct)}% ${t('insights.legendRedacted')}`}
        {allowedPct > 0 && `, ${Math.round(allowedPct)}% ${t('insights.legendAllowed')}`}
        {deniedPct > 0 && `, ${Math.round(deniedPct)}% ${t('insights.legendDenied')}`}
      </span>
    </Link>
  )
}

function KindRankRow({
  row,
  formatter,
}: {
  row: KindRank
  formatter: Intl.NumberFormat
}) {
  return (
    <Link
      to="/wallet"
      search={{ q: row.kind }}
      className="dam-insights__rank-row dam-insights__rank-row--kind"
    >
      <span className="dam-insights__rank-name">[{row.kind}]</span>
      <span className="dam-insights__rank-count">{formatter.format(row.total)}</span>
    </Link>
  )
}

function SignificantEventRow({ event }: { event: SignificantEvent }) {
  const { locale } = useI18n()
  const stamp = new Date(event.ts * 1000).toLocaleString(locale, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
  return (
    <article className="dam-insights__event">
      <span className="dam-insights__event-ts">{stamp}</span>
      <span className="dam-insights__event-summary">{event.summary}</span>
    </article>
  )
}

function rangeLabelKey(value: InsightsRange): MessageKey {
  if (value === 'today') return 'insights.range.today'
  if (value === '7d') return 'insights.range.7d'
  if (value === '30d') return 'insights.range.30d'
  return 'insights.range.all'
}

function isInsightsRange(value: string): value is InsightsRange {
  return (RANGE_VALUES as readonly string[]).includes(value)
}
