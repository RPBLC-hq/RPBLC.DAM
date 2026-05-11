import { useEffect, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Button,
  ConsentRequestCard,
  ConnectMark,
  EmptyTile,
  ErrorTile,
  RedactionLoader,
  SetupChecklist,
  type SetupStep as ChecklistStep,
} from '@rpblc/design'

import { ApiError, api, apiPost } from '@/lib/api/client'
import { useI18n } from '@/lib/i18n'
import { resolveSurface } from '@/lib/surface'
import {
  errorMessageKey,
  stateMessageKey,
  stepActionKey,
  stepHintKey,
  stepLabelKey,
} from './connect-copy'
import type { ConnectView, PendingRequest, PendingRequestsView, SetupStep } from './types'

const CONNECT_QUERY_KEY = ['connect'] as const
const PENDING_REQUESTS_QUERY_KEY = ['pending-requests'] as const

export function ConnectPage() {
  const { locale, t } = useI18n()
  const queryClient = useQueryClient()
  const formatter = new Intl.NumberFormat(locale)

  const connect = useQuery({
    queryKey: CONNECT_QUERY_KEY,
    queryFn: ({ signal }) => api<ConnectView>('/connect', { signal }),
  })

  const action = useMutation({
    mutationFn: (stepId: string) => apiPost<ConnectView>('/connect/action', { step_id: stepId }),
    onSuccess: (view) => {
      queryClient.setQueryData(CONNECT_QUERY_KEY, view)
    },
  })

  const runAction = (stepId: string) => {
    if (!action.isPending) action.mutate(stepId)
  }

  return (
    <section className="dam-connect" aria-label={t('connect.mainLabel')}>
      <ConnectNotice />
      {connect.isPending ? (
        <LoadingState />
      ) : connect.isError || !connect.data ? (
        <ErrorTile
          message={t('connect.error.load')}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => void connect.refetch()}
            >
              {t('connect.checkAgain')}
            </Button>
          }
        />
      ) : (
        <ConnectBody
          view={connect.data}
          formatNumber={(value) => formatter.format(value)}
          mutationError={action.error}
          mutationPending={action.isPending}
          onAction={runAction}
        />
      )}
    </section>
  )
}

/**
 * Surface `?notice=` / `?error=` params that the native tray's
 * `connect_dam` flow leaves on the URL after running. The native side
 * redirects `/connect?notice=DAM connected` (success) or
 * `/connect?error=Action required: …` (failure / NE-needs-reboot etc.).
 * Without this banner the user sees only a flicker after clicking
 * `[CONNECT:DAM]` and can't tell what happened.
 *
 * The param is consumed at mount: we lift it into state, then strip it
 * from the URL via `replaceState` so refresh / back-navigate doesn't
 * re-fire the banner. The native error strings are curated banker copy
 * already; surfacing them as-is for now. Folding them through the
 * `WebErrorCode` catalog (so FR users get translated copy) is parked
 * — it requires the native to send a code instead of a sentence.
 */
function ConnectNotice() {
  const { t } = useI18n()
  const [notice, setNotice] = useState<{
    kind: 'notice' | 'error'
    message: string
  } | null>(() => readNoticeParam())

  useEffect(() => {
    if (!notice) return
    // Strip the param so refresh / back-nav doesn't replay the banner.
    try {
      const params = new URLSearchParams(window.location.search)
      params.delete('notice')
      params.delete('error')
      const search = params.toString()
      const url = `${window.location.pathname}${search ? `?${search}` : ''}${window.location.hash}`
      window.history.replaceState(null, '', url)
    } catch {
      // ignore
    }
  }, [notice])

  if (!notice) return null

  const dismiss = () => setNotice(null)

  if (notice.kind === 'error') {
    return (
      <ErrorTile
        className="dam-connect__notice"
        message={notice.message}
        action={
          <Button variant="ghost" size="sm" type="button" onClick={dismiss}>
            {t('connect.notice.dismiss')}
          </Button>
        }
      />
    )
  }

  return (
    <EmptyTile
      className="dam-connect__notice"
      message={notice.message}
      action={
        <Button variant="ghost" size="sm" type="button" onClick={dismiss}>
          {t('connect.notice.dismiss')}
        </Button>
      }
    />
  )
}

function readNoticeParam(): { kind: 'notice' | 'error'; message: string } | null {
  if (typeof window === 'undefined') return null
  const params = new URLSearchParams(window.location.search)
  const error = params.get('error')
  if (error) return { kind: 'error', message: error }
  const notice = params.get('notice')
  if (notice) return { kind: 'notice', message: notice }
  return null
}

function LoadingState() {
  const { t } = useI18n()

  return (
    <div className="dam-connect__loading">
      <RedactionLoader
        redacted
        bars={4}
        width="11em"
        reason={t('connect.loadingReason')}
        aria-label={t('connect.loadingReason')}
        verbose
      />
      <span>{t('connect.loading')}</span>
    </div>
  )
}

function ConnectBody({
  view,
  formatNumber,
  mutationError,
  mutationPending,
  onAction,
}: {
  view: ConnectView
  formatNumber: (value: number) => string
  mutationError: Error | null
  mutationPending: boolean
  onAction: (stepId: string) => void
}) {
  const { t } = useI18n()
  const mutationCode = mutationError instanceof ApiError ? mutationError.message : undefined

  const stackClass =
    view.state === 'disconnected'
      ? 'dam-connect__stack dam-connect__stack--welcome'
      : 'dam-connect__stack'

  return (
    <div className={stackClass}>
      {view.state === 'disconnected' ? (
        <DisconnectedState pending={mutationPending} onConnect={() => onAction('connect')} />
      ) : view.state === 'protected' ? (
        <ProtectedState view={view} formatNumber={formatNumber} />
      ) : (
        <>
          <StatusLine view={view} />
          {view.state === 'needs_setup' ? (
            <SetupState view={view} pending={mutationPending} onAction={onAction} />
          ) : (
            <ActionState view={view} pending={mutationPending} onAction={onAction} />
          )}
        </>
      )}

      {mutationError && (
        <ErrorTile
          message={t(errorMessageKey(mutationCode))}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => onAction(currentActionId(view))}
            >
              {t('connect.checkAgain')}
            </Button>
          }
        />
      )}

      {view.state !== 'disconnected' &&
        view.state !== 'protected' &&
        view.state !== 'needs_setup' && (
        <CountsRow view={view} formatNumber={formatNumber} />
      )}
    </div>
  )
}

function DisconnectedState({
  pending,
  onConnect,
}: {
  pending: boolean
  onConnect: () => void
}) {
  const { t } = useI18n()
  const surface = resolveSurface()
  // On tray, the click is handed to the native shell via the IPC bridge
  // (`data-tray-connect` → `dam-tray:connect`) so the macOS Network
  // Extension activation, local CA install, and `dam connect` spawn run
  // in the privileged tray binary. The HTTP fallback (`onConnect` →
  // POST `/connect/action`) only fires on the web surface, where the
  // user is in a browser tab without NE entitlement; the dam-web
  // handler will return NotImplemented for now and the user runs
  // `dam connect` from the CLI.
  const isTray = surface === 'tray'

  // Order: lede → fine → CTA. The natural read flow lands the user on
  // the CTA last, so the page channels toward the action instead of
  // opening with it. The intro container vertically centers the block
  // in the available viewport so the layout doesn't feel top-heavy.
  return (
    <div className="dam-connect__intro">
      <p className="dam-connect__lede">{t('connect.disconnectedLede')}</p>
      <p className="dam-connect__fine">{t('connect.disconnectedFine')}</p>
      <ConnectMark
        className="dam-connect__mark"
        target="DAM"
        size={32}
        caption={t('connect.connectCaption')}
        aria-label={t('connect.connectAria')}
        aria-disabled={pending ? true : undefined}
        data-tray-connect={isTray ? 'dam' : undefined}
        onClick={isTray || pending ? undefined : onConnect}
      />
    </div>
  )
}

function StatusLine({ view }: { view: ConnectView }) {
  const { t } = useI18n()
  const label = t(stateMessageKey(view.state))

  return (
    <div className="dam-connect__status">
      <span className="dam-connect__state-mark" data-state={view.state}>
        {label}
      </span>
    </div>
  )
}

function ProtectedState({
  view,
  formatNumber,
}: {
  view: ConnectView
  formatNumber: (value: number) => string
}) {
  const { locale, t } = useI18n()
  const queryClient = useQueryClient()
  const pending = useQuery({
    queryKey: PENDING_REQUESTS_QUERY_KEY,
    queryFn: ({ signal }) => api<PendingRequestsView>('/requests/pending', { signal }),
  })
  const decision = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'allow-once' | 'allow-always' | 'deny' }) =>
      apiPost<PendingRequestsView>(`/requests/${encodeURIComponent(id)}/${action}`, {}),
    onSuccess: (view) => {
      queryClient.setQueryData(PENDING_REQUESTS_QUERY_KEY, view)
      void queryClient.invalidateQueries({ queryKey: CONNECT_QUERY_KEY })
    },
  })
  const request = pending.data?.items[0]
  const protectedForSeconds = useElapsedSeconds(view.protected_since_unix)

  return (
    <div className="dam-connect__on">
      <p className="dam-connect__status-line">
        {t('connect.protectedFor')} <b>{formatDuration(locale, protectedForSeconds)}</b>.
        <span className="dam-connect__status-line-mode">{t('connect.systemMode')}</span>
      </p>

      {pending.isPending ? (
        <div className="dam-connect__loading dam-connect__loading--inline">
          <RedactionLoader
            redacted
            bars={4}
            width="11em"
            reason={t('connect.loadingReason')}
            aria-label={t('connect.loadingReason')}
            verbose
          />
        </div>
      ) : request ? (
        <PendingRequestCard
          request={request}
          disabled={decision.isPending}
          onDecision={(id, action) => decision.mutate({ id, action })}
        />
      ) : (
        <EmptyTile
          className="dam-connect__quiet"
          message={t('connect.nothingAsking')}
        />
      )}

      <CountsRow view={view} formatNumber={formatNumber} />
    </div>
  )
}

function PendingRequestCard({
  request,
  disabled,
  onDecision,
}: {
  request: PendingRequest
  disabled: boolean
  onDecision: (id: string, action: 'allow-once' | 'allow-always' | 'deny') => void
}) {
  const { t } = useI18n()

  return (
    <ConsentRequestCard
      actor={request.actor}
      valueLabel={request.value_label}
      valuePreview={request.value_preview}
      purpose={request.purpose}
      expiresInSec={request.expires_in_sec}
      incomingLabel={t('request.incoming')}
      countdownSuffix={t('request.toDecide')}
      ariaLabel={t('request.aria')}
      decisionAriaLabel={t('request.decision')}
      purposePrefix={t('request.purposePrefix')}
      allowOnceLabel={t('request.allowOnce')}
      allowAlwaysLabel={t('request.allowAlways')}
      denyLabel={t('request.deny')}
      sentence={
        <>
          <em>{request.actor}</em> {t('request.wantsToReadYour')} <b>{request.value_label}</b>
          {request.value_preview && (
            <>
              {' '}
              <span className="rpblc-consent-request-card__preview">
                ({request.value_preview})
              </span>
            </>
          )}
          .
        </>
      }
      onDeny={disabled ? undefined : () => onDecision(request.id, 'deny')}
      onAllowOnce={disabled ? undefined : () => onDecision(request.id, 'allow-once')}
      onAllowAlways={disabled ? undefined : () => onDecision(request.id, 'allow-always')}
    />
  )
}

function SetupState({
  view,
  pending,
  onAction,
}: {
  view: ConnectView
  pending: boolean
  onAction: (stepId: string) => void
}) {
  const { t } = useI18n()
  const surface = resolveSurface()
  const isTray = surface === 'tray'
  const steps = view.setup_plan?.steps ?? []
  const current = currentSetupStep(steps, view.setup_plan?.current_step_id ?? undefined)
  const currentId = current?.id ?? 'setup'

  return (
    <div className="dam-connect__setup">
      <h1 className="dam-connect__heading">{t('connect.setupHeading')}</h1>
      <SetupChecklist
        steps={steps.map((step): ChecklistStep => {
          const hintKey = stepHintKey(step)
          return {
            id: step.id,
            label: t(stepLabelKey(step)),
            state: step.state,
            hint: hintKey ? t(hintKey) : undefined,
            reason: step.reason_code ? t(errorMessageKey(step.reason_code)) : undefined,
          }
        })}
        doneAriaLabel={t('connect.stepDone')}
        currentAriaLabel={t('connect.stepCurrent')}
        failedAriaLabel={t('connect.stepFailed')}
        blockedAriaLabel={t('connect.stepBlocked')}
        hintAriaLabel={t('connect.hintAriaLabel')}
      />
      {renderSetupCta({ currentId, isTray, pending, onAction, t })}
    </div>
  )
}

/**
 * Pick the right CTA shape for the current setup step. Three flavours:
 *
 * - `launch_at_login`: tray-only, renders an explicit Add/Skip choice.
 *   Add hands off to native via `data-tray-register-login`; Skip records
 *   the user's choice via `data-tray-skip-login`. After either native
 *   action completes, the shell redirects back to `/connect` and the
 *   next setup-plan fetch advances.
 * - `ne_reboot`: tray-only, hands off via `data-tray-restart` — macOS
 *   opens its standard restart confirmation dialog.
 * - everything else: the all-in-one connect handoff (tray) or HTTP
 *   POST fallback (web; currently NotImplemented).
 *
 * On the web surface, `launch_at_login` and `ne_reboot` hide the CTA
 * entirely — neither action is reachable without the native binary.
 */
function renderSetupCta({
  currentId,
  isTray,
  pending,
  onAction,
  t,
}: {
  currentId: string
  isTray: boolean
  pending: boolean
  onAction: (stepId: string) => void
  t: (key: ReturnType<typeof stepActionKey>) => string
}) {
  if (currentId === 'launch_at_login') {
    return isTray ? (
      <div className="dam-connect__choice">
        <Button
          className="dam-connect__choice-primary"
          variant="primary"
          size="md"
          bracketed
          type="button"
          data-tray-register-login="dam"
        >
          {t(stepActionKey(currentId))}
        </Button>
        <Button
          className="dam-connect__choice-skip"
          variant="ghost"
          size="md"
          type="button"
          data-tray-skip-login="dam"
        >
          {t('connect.action.launch_at_login_skip')}
        </Button>
      </div>
    ) : null
  }
  if (currentId === 'ne_reboot') {
    return isTray ? (
      <Button
        variant="primary"
        size="md"
        bracketed
        type="button"
        data-tray-restart="dam"
      >
        {t(stepActionKey(currentId))}
      </Button>
    ) : null
  }
  return (
    <Button
      variant="primary"
      size="md"
      bracketed
      type="button"
      disabled={pending}
      data-tray-connect={isTray ? 'dam' : undefined}
      onClick={isTray ? undefined : () => onAction(currentId)}
    >
      {t(stepActionKey(currentId))}
    </Button>
  )
}

function ActionState({
  view,
  pending,
  onAction,
}: {
  view: ConnectView
  pending: boolean
  onAction: (stepId: string) => void
}) {
  const { t } = useI18n()
  const surface = resolveSurface()
  const isTray = surface === 'tray'
  const actionId = currentActionId(view)
  const label =
    view.state === 'protected'
      ? t('connect.pauseProtection')
      : view.state === 'paused'
        ? t('connect.resumeProtection')
        : t('connect.recoveryAction')

  // Pause/resume only flip the on-disk protection flag — both surfaces
  // can drive that through the dam-web HTTP path. Recovery from
  // `degraded` (e.g. trust rotated, NE removed) needs the same
  // privilege escalation as a fresh connect, so on tray it routes
  // through `dam-tray:connect` (which runs the full connect_dam).
  const useTrayBridgeForRecovery =
    isTray && (view.state === 'degraded' || view.state === 'needs_setup')

  return (
    <Button
      className="dam-connect__action"
      variant={view.state === 'protected' ? 'ghost' : 'primary'}
      size="md"
      bracketed
      type="button"
      disabled={pending}
      data-tray-connect={useTrayBridgeForRecovery ? 'dam' : undefined}
      onClick={useTrayBridgeForRecovery ? undefined : () => onAction(actionId)}
    >
      {label}
    </Button>
  )
}

function CountsRow({
  view,
  formatNumber,
}: {
  view: ConnectView
  formatNumber: (value: number) => string
}) {
  const { t } = useI18n()

  return (
    <ul className="dam-connect__counts" aria-label={t('connect.countsLabel')}>
      <li className="dam-connect__counts-cell--link">
        <Link
          to="/allowed"
          className="dam-connect__counts-link"
          aria-label={t('connect.grantsAria')}
        >
          <b>{formatNumber(view.counts.grants)}</b>
          <span>{t('connect.grants')}</span>
        </Link>
      </li>
      <li className="dam-connect__counts-cell--link">
        <Link
          to="/activity"
          search={{ decision: 'denied', since: 'today' }}
          className="dam-connect__counts-link"
          aria-label={t('connect.blockedTodayAria')}
        >
          <b>{formatNumber(view.counts.blocked_today)}</b>
          <span>{t('connect.blockedToday')}</span>
        </Link>
      </li>
      <li className="dam-connect__counts-cell--link">
        <Link
          to="/settings"
          hash="apps"
          className="dam-connect__counts-link"
          aria-label={t('connect.appsMediatedAria')}
        >
          <b>{formatNumber(view.counts.apps_mediated)}</b>
          <span>{t('connect.appsMediated')}</span>
        </Link>
      </li>
    </ul>
  )
}

function currentSetupStep(steps: SetupStep[], currentId?: string): SetupStep | undefined {
  return (
    steps.find((step) => step.id === currentId) ??
    steps.find((step) => step.state === 'current' || step.state === 'blocked' || step.state === 'failed')
  )
}

function currentActionId(view: ConnectView): string {
  if (view.state === 'protected') return 'pause'
  if (view.state === 'paused') return 'resume'
  if (view.state === 'degraded') return 'recover'
  if (view.state === 'needs_setup') {
    return currentSetupStep(view.setup_plan?.steps ?? [], view.setup_plan?.current_step_id ?? undefined)?.id ?? 'setup'
  }
  return 'connect'
}

function formatDuration(locale: string, seconds: number): string {
  const safeSeconds = Math.max(0, Math.floor(seconds))
  const hours = Math.floor(safeSeconds / 3600)
  const minutes = Math.floor((safeSeconds % 3600) / 60)
  const remainingSeconds = safeSeconds % 60

  if (hours === 0) {
    if (locale === 'fr') {
      return `${minutes} min ${remainingSeconds.toString().padStart(2, '0')} s`
    }
    return `${minutes}m ${remainingSeconds.toString().padStart(2, '0')}s`
  }

  if (locale === 'fr') return `${hours} h ${minutes.toString().padStart(2, '0')} min`
  return `${hours}h ${minutes.toString().padStart(2, '0')}m`
}

function useElapsedSeconds(sinceUnix?: number | null): number {
  const [nowMs, setNowMs] = useState(() => Date.now())

  useEffect(() => {
    if (!sinceUnix) return undefined
    const interval = window.setInterval(() => setNowMs(Date.now()), 1000)
    return () => window.clearInterval(interval)
  }, [sinceUnix])

  if (!sinceUnix) return 0
  return Math.max(0, Math.floor(nowMs / 1000) - sinceUnix)
}
