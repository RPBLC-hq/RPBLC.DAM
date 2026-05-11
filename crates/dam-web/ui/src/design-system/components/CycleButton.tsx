import {
  type AnchorHTMLAttributes,
  type ButtonHTMLAttributes,
  type ElementType,
  type ReactNode,
} from 'react'

export type CycleButtonSize = 'sm' | 'md'

type CommonProps = {
  label: ReactNode
  value: ReactNode
  nextLabel?: string
  size?: CycleButtonSize
  /** Underlying element. Defaults to "button". Pass "a" with href for link-styled cycling. */
  as?: ElementType
}

export type CycleButtonProps = CommonProps &
  Omit<ButtonHTMLAttributes<HTMLButtonElement> & AnchorHTMLAttributes<HTMLAnchorElement>, keyof CommonProps>

/**
 * CycleButton — one compact control for small mutually-exclusive ordered modes.
 *
 * Use when the user does not need to compare every option at once, for example:
 * Recent -> Oldest -> A-Z.
 */
export function CycleButton({
  label,
  value,
  nextLabel,
  size = 'sm',
  as,
  className,
  'aria-label': ariaLabelProp,
  ...rest
}: CycleButtonProps) {
  const Tag = (as ?? 'button') as ElementType
  const ariaLabel =
    ariaLabelProp ??
    (typeof label === 'string' && typeof value === 'string' && nextLabel
      ? `${label}. Current: ${value}. Click for ${nextLabel}.`
      : undefined)

  return (
    <Tag
      className={joinClasses('rpblc-cycle-button', `rpblc-cycle-button--${size}`, className)}
      aria-label={ariaLabel}
      {...rest}
    >
      <span className="rpblc-cycle-button__label">{label}</span>
      <strong className="rpblc-cycle-button__value">{value}</strong>
      <span className="rpblc-cycle-button__mark" aria-hidden="true" />
    </Tag>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
