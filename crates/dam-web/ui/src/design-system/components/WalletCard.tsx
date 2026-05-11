import {
  type AnchorHTMLAttributes,
  type ButtonHTMLAttributes,
  type ElementType,
  type HTMLAttributes,
  type ReactNode,
} from 'react'
import { ProtectionMark, type ProtectionState } from './ProtectionMark'

export type WalletCardState = ProtectionState | 'expired'

export type WalletCardProps = {
  /** Short kind tag — phone, email, address. Mono uppercase. */
  kind: ReactNode
  /** The hero — the stored value (or its redacted form). */
  value: ReactNode
  /**
   * Wrap the value in an anchor (for "view detail" navigation). When set,
   * the card renders as a scannable list row with a chevron and an
   * optional active indicator. `action` and `href` are mutually
   * exclusive — pick one.
   */
  href?: string
  /** Title attribute for the value link — useful when ellipsis truncates it. */
  valueTitle?: string
  /** Scannable secondary row: shared-with, last-seen, source app, etc. */
  meta?: ReactNode
  /**
   * The primary inline action. Mutually exclusive with `href` and
   * `onClick`. Use for surfaces where the action lives next to the value;
   * use `onClick`/`href` when the row opens a detail surface.
   */
  action?: ReactNode
  /**
   * Click handler. When set (and no `action` / `href` is provided), the
   * card renders as a button surface — chevron at the right edge, grip
   * rail on the left, hover/active styling.
   */
  onClick?: () => void
  /** Highlights the row as the currently selected/expanded one. */
  active?: boolean
  /** Drives the bracket pill in the header and the row's accent treatment. */
  state?: WalletCardState
  className?: string
} & Omit<HTMLAttributes<HTMLElement>, 'children' | 'title' | 'onClick'>

/**
 * WalletCard — a scannable row representing a stored value.
 *
 * The card has three modes, picked by which of `href`, `onClick`, and
 * `action` you pass:
 *
 *   1. `href` → list row that links to a detail surface. Renders a
 *      chevron at the right edge.
 *   2. `onClick` → list row that opens an in-page detail. The row itself
 *      becomes a `<button>`. Renders a chevron and supports `active`.
 *   3. `action` → static row with an inline affordance. The action lives
 *      where the chevron would otherwise sit.
 *
 * In all modes the layout is the same scannable shape: grip rail, kind
 * eyebrow over the value-as-hero, ProtectionMark on the right, then the
 * chevron or the inline action. On mobile the action stacks below.
 */
export function WalletCard({
  kind,
  value,
  href,
  valueTitle,
  meta,
  action,
  onClick,
  active,
  state = 'protected',
  className,
  ...rest
}: WalletCardProps) {
  const interactive = !action && (Boolean(href) || Boolean(onClick))
  const Tag: ElementType = href ? 'a' : onClick ? 'button' : 'article'
  const interactiveProps =
    href
      ? ({ href } satisfies AnchorHTMLAttributes<HTMLAnchorElement>)
      : onClick
        ? ({ type: 'button', onClick } satisfies ButtonHTMLAttributes<HTMLButtonElement>)
        : {}

  /* ProtectionMark accepts the three vault states. WalletCard's legacy
     "expired" maps to revoked-styling. */
  const markState: ProtectionState =
    state === 'expired' || state === 'revoked' ? 'revoked' : state

  return (
    <Tag
      className={joinClasses(
        'rpblc-wallet-card',
        interactive ? 'rpblc-wallet-card--interactive' : undefined,
        active ? 'rpblc-wallet-card--active' : undefined,
        state === 'allowed' ? 'rpblc-wallet-card--allowed' : undefined,
        state === 'expired' || state === 'revoked' ? 'rpblc-wallet-card--revoked' : undefined,
        className,
      )}
      {...interactiveProps}
      {...rest}
    >
      <span className="rpblc-wallet-card__grip" aria-hidden="true" />
      <div className="rpblc-wallet-card__main">
        <span className="rpblc-wallet-card__kind">{kind}</span>
        <span
          className="rpblc-wallet-card__value"
          title={typeof value === 'string' ? valueTitle ?? value : valueTitle}
        >
          <span className="rpblc-wallet-card__value-bracket" aria-hidden="true">[</span>
          <span className="rpblc-wallet-card__value-text">{value}</span>
          <span className="rpblc-wallet-card__value-bracket" aria-hidden="true">]</span>
        </span>
        {meta && <span className="rpblc-wallet-card__meta">{meta}</span>}
      </div>
      <ProtectionMark state={markState} className="rpblc-wallet-card__mark" />
      {action ? (
        <div className="rpblc-wallet-card__action">{action}</div>
      ) : interactive ? (
        <span className="rpblc-wallet-card__chev" aria-hidden="true">›</span>
      ) : null}
    </Tag>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
