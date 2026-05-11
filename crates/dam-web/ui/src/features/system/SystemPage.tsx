import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Button,
  EmptyTile,
  ErrorTile,
  RedactionLoader,
  SearchBar,
  SegmentedControl,
} from '@rpblc/design'

import { api } from '@/lib/api/client'
import { useI18n, type MessageKey } from '@/lib/i18n'
import { useUrlSearchParam, useUrlSearchString } from '@/lib/url-search'
import type {
  Severity,
  SystemFeed,
  SystemLogEvent,
  SystemScope,
} from './types'

const SCOPE_VALUES: SystemScope[] = [
  'issues',
  'all',
  'daemon',
  'network',
  'filter',
  'mcp',
  'provider',
]
const SCOPE_DEFAULT: SystemScope = 'issues'
const QUERY_KEY = 'system' as const

export function SystemPage() {
  const { t } = useI18n()
  const [scope, setScope] = useUrlSearchParam<SystemScope>(
    'scope',
    SCOPE_DEFAULT,
    isSystemScope,
  )
  const [query, setQuery] = useUrlSearchString('q')

  const feed = useQuery({
    queryKey: [QUERY_KEY, scope, query] as const,
    queryFn: ({ signal }) => {
      const params = new URLSearchParams()
      if (scope !== SCOPE_DEFAULT) params.set('scope', scope)
      if (query) params.set('q', query)
      const search = params.toString()
      return api<SystemFeed>(`/system${search ? `?${search}` : ''}`, { signal })
    },
  })

  const scopeOptions = SCOPE_VALUES.map((value) => ({
    value,
    label: t(scopeLabelKey(value)),
  }))

  const empty = feed.data?.events.length === 0
  const filterActive = scope !== SCOPE_DEFAULT || !!query

  return (
    <section className="dam-system" aria-label={t('system.aria')}>
      <header className="dam-system__head">
        <h1 className="dam-system__heading">{t('system.heading')}</h1>
        <SegmentedControl<SystemScope>
          value={scope}
          onValueChange={setScope}
          options={scopeOptions}
          aria-label={t('system.scopeAria')}
        />
        <SearchBar
          value={query}
          onValueChange={setQuery}
          aria-label={t('system.searchAria')}
          placeholder={t('system.searchPlaceholder')}
        />
      </header>

      {feed.isPending ? (
        <RedactionLoader
          redacted
          bars={4}
          width="14em"
          reason={t('system.loadingReason')}
          aria-label={t('system.loadingReason')}
          verbose
        />
      ) : feed.isError || !feed.data ? (
        <ErrorTile
          message={t('system.error.unknown')}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => void feed.refetch()}
            >
              {t('connect.checkAgain')}
            </Button>
          }
        />
      ) : empty ? (
        <EmptyTile
          message={t('system.empty.scope')}
          action={
            filterActive ? (
              <Button
                variant="ghost"
                size="sm"
                type="button"
                onClick={() => {
                  setScope(SCOPE_DEFAULT)
                  setQuery('')
                }}
              >
                {t('system.empty.clearFilter')}
              </Button>
            ) : null
          }
        />
      ) : (
        <SystemList feed={feed.data} />
      )}
    </section>
  )
}

function SystemList({ feed }: { feed: SystemFeed }) {
  const [openId, setOpenId] = useState<number | null>(null)
  return (
    <ul className="dam-system__events">
      {feed.events.map((event) => (
        <li key={event.id}>
          <SystemEventRow
            event={event}
            open={openId === event.id}
            onToggle={() => setOpenId((current) => (current === event.id ? null : event.id))}
          />
        </li>
      ))}
    </ul>
  )
}

function SystemEventRow({
  event,
  open,
  onToggle,
}: {
  event: SystemLogEvent
  open: boolean
  onToggle: () => void
}) {
  const { locale, t } = useI18n()
  const stamp = new Date(event.ts * 1000).toLocaleTimeString(locale, {
    hour: '2-digit',
    minute: '2-digit',
  })

  return (
    <article
      className={`dam-system__event dam-system__event--${event.severity}${
        open ? ' dam-system__event--open' : ''
      }`}
    >
      <button
        type="button"
        className="dam-system__event-head"
        onClick={onToggle}
        aria-expanded={open}
      >
        <span className="dam-system__event-ts">{stamp}</span>
        <span className="dam-system__event-module">[{event.module}]</span>
        <span className="dam-system__event-msg">{event.message}</span>
        <span className={`dam-system__event-sev dam-system__event-sev--${event.severity}`}>
          {t(severityLabelKey(event.severity))}
        </span>
      </button>
      {open && event.details.length > 0 && (
        <dl className="dam-system__event-details">
          {event.details.map((detail) => (
            <div key={detail.label} className="dam-system__event-detail">
              <dt>{detail.label}</dt>
              <dd>{detail.value}</dd>
            </div>
          ))}
        </dl>
      )}
    </article>
  )
}

function isSystemScope(value: string): value is SystemScope {
  return (SCOPE_VALUES as readonly string[]).includes(value)
}

function scopeLabelKey(value: SystemScope): MessageKey {
  if (value === 'issues') return 'system.scope.issues'
  if (value === 'all') return 'system.scope.all'
  if (value === 'daemon') return 'system.scope.daemon'
  if (value === 'network') return 'system.scope.network'
  if (value === 'filter') return 'system.scope.filter'
  if (value === 'mcp') return 'system.scope.mcp'
  return 'system.scope.provider'
}

function severityLabelKey(severity: Severity): MessageKey {
  if (severity === 'error') return 'system.severity.error'
  if (severity === 'warn') return 'system.severity.warn'
  return 'system.severity.info'
}
