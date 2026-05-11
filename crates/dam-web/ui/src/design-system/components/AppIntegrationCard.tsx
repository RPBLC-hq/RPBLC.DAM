import {
  type HTMLAttributes,
  type ReactNode,
  useId,
  useState,
} from 'react'

export type AppIntegrationStatus = 'enabled' | 'disabled' | 'pending' | 'attention'

export type AppIntegrationCardProps = {
  /** App name. Top-line, bright, mono. */
  name: ReactNode
  /** One-line purpose. The customer-facing reason this app exists in the list. */
  purpose: ReactNode
  /** Current status. Drives the state pill. */
  status: AppIntegrationStatus
  /** Optional override for the status pill text. Defaults to the status name. */
  statusLabel?: ReactNode
  /** Optional leading badge — short mono identifier (vault key / app code). */
  leading?: ReactNode
  /**
   * The primary action affordance — usually a Button. The card does not
   * synthesize one; consumers compose it so href / onClick / form posts
   * stay in the consumer's hands.
   */
  action?: ReactNode
  /**
   * Technical details, hidden behind a disclosure. For raw tokens, paths,
   * IDs, version strings — anything a normal user does not need to read.
   */
  details?: ReactNode
  /** Defaults to "Show details". Closed-state label. */
  detailsClosedLabel?: ReactNode
  /** Defaults to "Hide details". Open-state label. */
  detailsOpenLabel?: ReactNode
  /** Visually mark the card as the currently-selected integration. */
  selected?: boolean
  /**
   * Suppress the inline status pill. Use when the action itself carries
   * the state (e.g. a `Toggle` whose checked/unchecked is the same fact
   * as `enabled`/`disabled`). Avoids two visual sources of truth — see
   * AGENTS.md "single source of truth for state".
   */
  hideStatusPill?: boolean
  className?: string
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

/**
 * AppIntegrationCard — list-row pattern for app integrations in product
 * settings. The visual contract reads top-down on every viewport:
 *
 * 1. Name + state pill
 * 2. Purpose (one line)
 * 3. Action (right-aligned on desktop, full-width below on mobile)
 * 4. Details disclosure (closed by default; technical content lives here)
 *
 * The card does not own its action's behavior — consumers pass any node
 * (Button, anchor, form). Use this for app integrations, OAuth connections,
 * worker bindings, vault-side adapters; it is not for content/list rows.
 */
export function AppIntegrationCard({
  name,
  purpose,
  status,
  statusLabel,
  leading,
  action,
  details,
  detailsClosedLabel = 'Show details',
  detailsOpenLabel = 'Hide details',
  selected = false,
  hideStatusPill = false,
  className,
  ...rest
}: AppIntegrationCardProps) {
  const detailsId = useId()
  const [open, setOpen] = useState(false)
  const label = statusLabel ?? defaultStatusLabel(status)
  return (
    <article
      className={joinClasses(
        'rpblc-app-card',
        selected ? 'rpblc-app-card--selected' : undefined,
        className,
      )}
      {...rest}
    >
      <header className="rpblc-app-card__header">
        {leading && <span className="rpblc-app-card__leading">{leading}</span>}
        <h3 className="rpblc-app-card__name">{name}</h3>
        {!hideStatusPill && (
          <span
            className={joinClasses(
              'rpblc-app-card__state',
              `rpblc-app-card__state--${status}`,
            )}
          >
            {label}
          </span>
        )}
      </header>
      <p className="rpblc-app-card__purpose">{purpose}</p>
      {(action || details) && (
        <div className="rpblc-app-card__row">
          {details ? (
            <button
              type="button"
              className="rpblc-app-card__disclosure"
              aria-expanded={open}
              aria-controls={detailsId}
              onClick={() => setOpen((v) => !v)}
            >
              <span>{open ? detailsOpenLabel : detailsClosedLabel}</span>
              <span
                className={joinClasses(
                  'rpblc-app-card__chevron',
                  open ? 'rpblc-app-card__chevron--open' : undefined,
                )}
                aria-hidden="true"
              />
            </button>
          ) : (
            <span aria-hidden="true" />
          )}
          {action && <div className="rpblc-app-card__action">{action}</div>}
        </div>
      )}
      {details && (
        <div
          id={detailsId}
          className="rpblc-app-card__details"
          hidden={!open}
        >
          {details}
        </div>
      )}
    </article>
  )
}

function defaultStatusLabel(status: AppIntegrationStatus): string {
  switch (status) {
    case 'enabled':
      return 'On'
    case 'disabled':
      return 'Off'
    case 'pending':
      return 'Pending'
    case 'attention':
      return 'Attention'
  }
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
