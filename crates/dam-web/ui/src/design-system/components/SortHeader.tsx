import { type AnchorHTMLAttributes, type ReactNode } from 'react'

export type SortDirection = 'asc' | 'desc'

export type SortHeaderProps = {
  /** Column label. */
  label: ReactNode
  /**
   * Active direction, if this column is currently the sorted column.
   * `undefined` = column is sortable but not currently active.
   */
  active?: SortDirection
  /**
   * Hrefs for ascending and descending sort. Used when SortHeader is used
   * inside a server-rendered surface (RPBLC.DAM is the canonical example) —
   * the buttons render as `<a>` so they survive without JavaScript.
   */
  ascHref?: string
  descHref?: string
  /** Click handlers for client-rendered surfaces. Ignored when href is provided. */
  onAsc?: () => void
  onDesc?: () => void
  /** Accessible labels for the asc/desc buttons. */
  ascLabel?: string
  descLabel?: string
  className?: string
}

/**
 * SortHeader — column-header sort control.
 *
 * Renders a label plus paired ascending/descending chevron buttons. The
 * currently-active direction fills with --bright (ink) to read as a
 * committed mark, mirroring SegmentedControl. SortHeader is the column-
 * level companion to CycleButton — same visual language, different
 * interaction model.
 *
 * For surfaces without JavaScript (server-rendered), pass `ascHref`/`descHref`.
 * For client-rendered surfaces, pass `onAsc`/`onDesc`.
 */
export function SortHeader({
  label,
  active,
  ascHref,
  descHref,
  onAsc,
  onDesc,
  ascLabel,
  descLabel,
  className,
}: SortHeaderProps) {
  return (
    <span className={joinClasses('rpblc-sort-header', className)}>
      <span className="rpblc-sort-header__label">{label}</span>
      <span className="rpblc-sort-header__buttons" role="group" aria-label={`Sort ${typeof label === 'string' ? label : ''}`}>
        <SortButton
          direction="asc"
          active={active === 'asc'}
          href={ascHref}
          onClick={onAsc}
          ariaLabel={ascLabel ?? 'Sort ascending'}
        />
        <SortButton
          direction="desc"
          active={active === 'desc'}
          href={descHref}
          onClick={onDesc}
          ariaLabel={descLabel ?? 'Sort descending'}
        />
      </span>
    </span>
  )
}

function SortButton({
  direction,
  active,
  href,
  onClick,
  ariaLabel,
}: {
  direction: SortDirection
  active: boolean
  href?: string
  onClick?: () => void
  ariaLabel: string
}) {
  const className = joinClasses(
    'rpblc-sort-header__button',
    active ? 'rpblc-sort-header__button--active' : undefined,
  )
  const chevron = (
    <span
      className={`rpblc-sort-header__chevron rpblc-sort-header__chevron--${direction}`}
      aria-hidden="true"
    />
  )
  if (href) {
    const anchorProps: AnchorHTMLAttributes<HTMLAnchorElement> = {
      href,
      className,
      'aria-label': ariaLabel,
      'aria-current': active ? 'true' : undefined,
    }
    return <a {...anchorProps}>{chevron}</a>
  }
  return (
    <button
      type="button"
      className={className}
      aria-label={ariaLabel}
      aria-pressed={active}
      onClick={onClick}
    >
      {chevron}
    </button>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
