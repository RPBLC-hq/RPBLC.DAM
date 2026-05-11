import { useEffect, useState, type CSSProperties, type HTMLAttributes, type ReactNode } from 'react'
import { Button } from './Button'
import { RedactionLoader } from '../brand/RedactionLoader'

export type ConsentState =
  | 'pending'
  | 'granted'
  | 'denied'
  | 'revoked'
  | 'expired'
  | 'superseded'
  | 'sealed'

export type ConsentDataItem = {
  id: string
  label: ReactNode
  description?: ReactNode
  required?: boolean
  checked?: boolean
  disabled?: boolean
}

export type ConsentTone = 'person' | 'operator'

export type ConsentStateMarkProps = {
  state: ConsentState
  label?: ReactNode
} & Omit<HTMLAttributes<HTMLSpanElement>, 'children'>

export function ConsentStateMark({
  state,
  label,
  className,
  ...rest
}: ConsentStateMarkProps) {
  return (
    <span
      className={joinClasses('rpblc-consent-state', `rpblc-consent-state--${state}`, className)}
      data-state={state}
      {...rest}
    >
      <span className="rpblc-consent-state__bracket" aria-hidden="true">[</span>
      <span className="rpblc-consent-state__label">{label ?? state}</span>
      <span className="rpblc-consent-state__bracket" aria-hidden="true">]</span>
    </span>
  )
}

export type ConsentDataItemRowProps = {
  item: ConsentDataItem
  onCheckedChange?: (checked: boolean) => void
  sealed?: boolean
} & Omit<HTMLAttributes<HTMLLabelElement>, 'children' | 'onChange'>

export function ConsentDataItemRow({
  item,
  onCheckedChange,
  sealed,
  className,
  ...rest
}: ConsentDataItemRowProps) {
  const interactive = typeof onCheckedChange === 'function'
  return (
    <label
      className={joinClasses(
        'rpblc-consent-data-item',
        item.required && 'rpblc-consent-data-item--required',
        item.disabled && 'rpblc-consent-data-item--disabled',
        sealed && 'rpblc-consent-data-item--sealed',
        className,
      )}
      {...rest}
    >
      <span className="rpblc-consent-data-item__control" aria-hidden={!interactive}>
        {interactive ? (
          <input
            className="rpblc-consent-data-item__check-input"
            type="checkbox"
            checked={Boolean(item.checked)}
            disabled={item.disabled || item.required}
            onChange={(event) => onCheckedChange(event.currentTarget.checked)}
          />
        ) : (
          <span className="rpblc-consent-data-item__check-static" />
        )}
      </span>
      <span className="rpblc-consent-data-item__body">
        <span className="rpblc-consent-data-item__label">
          {sealed ? (
            <RedactionLoader redacted static bars={3} width="9em" size="0.62em" />
          ) : (
            item.label
          )}
        </span>
        {item.description && (
          <span className="rpblc-consent-data-item__description">{item.description}</span>
        )}
      </span>
      {item.required && <span className="rpblc-consent-data-item__meta">required</span>}
    </label>
  )
}

export type ConsentPurposeCardProps = {
  purpose: ReactNode
  actor: ReactNode
  duration: ReactNode
  tone?: ConsentTone
  description?: ReactNode
  state?: ConsentState
  children?: ReactNode
  actions?: ReactNode
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

export function ConsentPurposeCard({
  purpose,
  actor,
  duration,
  tone = 'person',
  description,
  state,
  children,
  actions,
  className,
  ...rest
}: ConsentPurposeCardProps) {
  return (
    <article
      className={joinClasses(
        'rpblc-consent-purpose',
        `rpblc-consent-purpose--${tone}`,
        className,
      )}
      {...rest}
    >
      <header className="rpblc-consent-purpose__header">
        <div>
          <div className="rpblc-consent-purpose__eyebrow">purpose</div>
          <h3 className="rpblc-consent-purpose__title">{purpose}</h3>
        </div>
        {state && <ConsentStateMark state={state} />}
      </header>
      {description && <p className="rpblc-consent-purpose__description">{description}</p>}
      <dl className="rpblc-consent-summary">
        <div>
          <dt>Actor</dt>
          <dd>{actor}</dd>
        </div>
        <div>
          <dt>Duration</dt>
          <dd>{duration}</dd>
        </div>
      </dl>
      {children && <div className="rpblc-consent-purpose__items">{children}</div>}
      {actions && <div className="rpblc-consent-purpose__actions">{actions}</div>}
    </article>
  )
}

export type ConsentRequestProps = {
  actor: ReactNode
  purpose: ReactNode
  data: ReactNode
  reason: ReactNode
  duration: ReactNode
  tone?: ConsentTone
  dataItems?: ConsentDataItem[]
  state?: ConsentState
  allowLabel?: ReactNode
  denyLabel?: ReactNode
  onAllow?: () => void
  onDeny?: () => void
  children?: ReactNode
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

export function ConsentRequest({
  actor,
  purpose,
  data,
  reason,
  duration,
  tone = 'person',
  dataItems,
  state = 'pending',
  allowLabel = 'Allow',
  denyLabel = 'Not now',
  onAllow,
  onDeny,
  children,
  className,
  ...rest
}: ConsentRequestProps) {
  return (
    <section
      className={joinClasses(
        'rpblc-consent-request',
        `rpblc-consent-request--${tone}`,
        className,
      )}
      {...rest}
    >
      <header className="rpblc-consent-request__header">
        <ConsentStateMark state={state} />
        <h2 className="rpblc-consent-request__title">
          {actor} wants to use {data} for {purpose}.
        </h2>
      </header>

      <div className="rpblc-consent-request__reason">
        <span className="rpblc-consent-request__label">Why now</span>
        <p>{reason}</p>
      </div>

      <dl className="rpblc-consent-summary rpblc-consent-summary--request">
        <div>
          <dt>Data</dt>
          <dd>{data}</dd>
        </div>
        <div>
          <dt>Actor</dt>
          <dd>{actor}</dd>
        </div>
        <div>
          <dt>Duration</dt>
          <dd>{duration}</dd>
        </div>
      </dl>

      {dataItems && dataItems.length > 0 && (
        <div className="rpblc-consent-request__items">
          {dataItems.map((item) => (
            <ConsentDataItemRow key={item.id} item={item} />
          ))}
        </div>
      )}

      {children}

      {state === 'pending' && (
        <div className="rpblc-consent-request__actions">
          <Button variant="primary" onClick={onAllow}>{allowLabel}</Button>
          <Button variant="secondary" onClick={onDeny}>{denyLabel}</Button>
        </div>
      )}
    </section>
  )
}

export type ConsentRequestCardProps = {
  /** Who is asking — bracketed in the rendered sentence. */
  actor: ReactNode
  /** Short label of the value being requested (e.g. "mobile phone"). */
  valueLabel: ReactNode
  /** Optional preview of the value (e.g. "+1 415 555 0142") shown muted. */
  valuePreview?: ReactNode
  /** Plain-language reason the actor needs the value. */
  purpose: ReactNode
  /** Seconds until the request auto-denies. When set, renders a countdown.
   *  Values ≤ 30 also flip the card to urgent. */
  expiresInSec?: number
  /** Force urgent styling regardless of countdown. */
  urgent?: boolean
  onAllowOnce?: () => void
  onAllowAlways?: () => void
  onDeny?: () => void
  /** Full sentence override. Use when localization needs different grammar. */
  sentence?: ReactNode
  /** Localizable chrome and aria label overrides. */
  incomingLabel?: ReactNode
  countdownLabel?: ReactNode
  countdownSuffix?: ReactNode
  purposePrefix?: ReactNode
  ariaLabel?: string
  decisionAriaLabel?: string
  /** Per-button label overrides. */
  allowOnceLabel?: ReactNode
  allowAlwaysLabel?: ReactNode
  denyLabel?: ReactNode
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

/**
 * ConsentRequestCard — the compact, notification-shaped consent request.
 *
 * Used in the DAM tray, the wallet sidebar, and any in-product surface
 * where an LLM/MCP client asks to read one stored value. Distinct from
 * `ConsentRequest`, which is the formal full-section CMP flow.
 *
 * Layout:
 *   - Left rail in accent (alarm when urgent).
 *   - Header: pulsing "incoming request" + countdown (when set).
 *   - Sentence: `[actor] wants to read your <b>label</b> (preview).`
 *   - Purpose: muted, in a left-bordered blockquote.
 *   - Actions: deny (danger) · allow once · allow + remember (primary).
 *     Deny sits leftmost so the safest answer is the easiest reach.
 */
export function ConsentRequestCard({
  actor,
  valueLabel,
  valuePreview,
  purpose,
  expiresInSec,
  urgent: urgentOverride,
  onAllowOnce,
  onAllowAlways,
  onDeny,
  sentence,
  incomingLabel = 'incoming request',
  countdownLabel,
  countdownSuffix = 'to decide',
  purposePrefix = 'for:',
  ariaLabel = 'Incoming consent request',
  decisionAriaLabel = 'Decision',
  allowOnceLabel = 'allow once',
  allowAlwaysLabel = 'allow + remember',
  denyLabel = 'deny',
  className,
  ...rest
}: ConsentRequestCardProps) {
  // The card owns its own 1Hz countdown so the urgent flip and the
  // visible timer happen as the user is looking at it. Re-seeding when
  // `expiresInSec` changes lets the consumer reset the timer on a
  // fresh request without remounting the card.
  const [remaining, setRemaining] = useState<number | null>(() =>
    typeof expiresInSec === 'number' ? Math.max(0, expiresInSec) : null,
  )
  useEffect(() => {
    if (typeof expiresInSec !== 'number') {
      setRemaining(null)
      return
    }
    setRemaining(Math.max(0, expiresInSec))
    const id = window.setInterval(() => {
      setRemaining((prev) => (prev === null || prev <= 0 ? prev : prev - 1))
    }, 1000)
    return () => window.clearInterval(id)
  }, [expiresInSec])

  const urgent =
    urgentOverride ?? (typeof remaining === 'number' && remaining <= 30)
  const countdown =
    countdownLabel ?? formatCountdown(remaining ?? undefined)
  return (
    <article
      className={joinClasses(
        'rpblc-consent-request-card',
        urgent ? 'rpblc-consent-request-card--urgent' : undefined,
        className,
      )}
      aria-label={ariaLabel}
      {...rest}
    >
      <header className="rpblc-consent-request-card__head">
        <span className="rpblc-consent-request-card__pulse">{incomingLabel}</span>
        {countdown && (
          <span className="rpblc-consent-request-card__count">
            {countdown} {countdownSuffix}
          </span>
        )}
      </header>
      <p className="rpblc-consent-request-card__sentence">
        {sentence ?? (
          <>
            <em>{actor}</em> wants to read your <b>{valueLabel}</b>
            {valuePreview && (
              <>
                {' '}
                <span className="rpblc-consent-request-card__preview">({valuePreview})</span>
              </>
            )}
            .
          </>
        )}
      </p>
      <p className="rpblc-consent-request-card__purpose">
        {purposePrefix} {purpose}
      </p>
      <div
        className="rpblc-consent-request-card__actions"
        role="group"
        aria-label={decisionAriaLabel}
      >
        <Button variant="danger" bracketed onClick={onDeny}>
          {denyLabel}
        </Button>
        <Button variant="secondary" bracketed onClick={onAllowOnce}>
          {allowOnceLabel}
        </Button>
        <Button variant="primary" bracketed onClick={onAllowAlways}>
          {allowAlwaysLabel}
        </Button>
      </div>
    </article>
  )
}

function formatCountdown(seconds?: number): string | null {
  if (typeof seconds !== 'number' || seconds < 0) return null
  if (seconds >= 3600) {
    const h = Math.floor(seconds / 3600)
    const m = Math.floor((seconds % 3600) / 60)
    return `${h}h ${m.toString().padStart(2, '0')}m`
  }
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${s.toString().padStart(2, '0')}`
}

export type ConsentEvidenceItem = {
  label: ReactNode
  value: ReactNode
}

export type ConsentEvidencePanelProps = {
  title?: ReactNode
  items: ConsentEvidenceItem[]
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

export function ConsentEvidencePanel({
  title = 'Evidence',
  items,
  className,
  ...rest
}: ConsentEvidencePanelProps) {
  return (
    <aside className={joinClasses('rpblc-consent-evidence', className)} {...rest}>
      <h3 className="rpblc-consent-evidence__title">{title}</h3>
      <dl className="rpblc-consent-evidence__list">
        {items.map((item, index) => (
          <div key={index} className="rpblc-consent-evidence__item">
            <dt>{item.label}</dt>
            <dd>{item.value}</dd>
          </div>
        ))}
      </dl>
    </aside>
  )
}

export type ConsentMatrixCell = {
  purpose: string
  dataItem: string
  state: ConsentState
}

export type ConsentMatrixProps = {
  purposes: string[]
  dataItems: string[]
  cells: ConsentMatrixCell[]
} & Omit<HTMLAttributes<HTMLDivElement>, 'children'>

export function ConsentMatrix({
  purposes,
  dataItems,
  cells,
  style,
  className,
  ...rest
}: ConsentMatrixProps) {
  const lookup = new Map(cells.map((cell) => [`${cell.purpose}:${cell.dataItem}`, cell.state]))
  const matrixStyle: CSSProperties = {
    ['--rpblc-consent-matrix-columns' as string]: dataItems.length,
    ...style,
  }
  return (
    <div
      className={joinClasses('rpblc-consent-matrix', className)}
      role="table"
      style={matrixStyle}
      {...rest}
    >
      <div className="rpblc-consent-matrix__row rpblc-consent-matrix__row--head" role="row">
        <div className="rpblc-consent-matrix__cell" role="columnheader">Purpose</div>
        {dataItems.map((item) => (
          <div key={item} className="rpblc-consent-matrix__cell" role="columnheader">
            {item}
          </div>
        ))}
      </div>
      {purposes.map((purpose) => (
        <div key={purpose} className="rpblc-consent-matrix__row" role="row">
          <div className="rpblc-consent-matrix__cell rpblc-consent-matrix__purpose" role="rowheader">
            {purpose}
          </div>
          {dataItems.map((item) => {
            const state = lookup.get(`${purpose}:${item}`) ?? 'sealed'
            return (
              <div key={item} className="rpblc-consent-matrix__cell" role="cell">
                <ConsentStateMark state={state} />
              </div>
            )
          })}
        </div>
      ))}
    </div>
  )
}

function joinClasses(...parts: Array<string | false | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
