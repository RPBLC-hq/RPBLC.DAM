import {
  type AnchorHTMLAttributes,
  type ButtonHTMLAttributes,
  type ElementType,
  type ReactNode,
} from 'react'

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'
export type ButtonSize = 'sm' | 'md' | 'lg'

type CommonProps = {
  children: ReactNode
  variant?: ButtonVariant
  size?: ButtonSize
  /** Underlying element. Defaults to "button". Pass "a" with href for link-styled buttons. */
  as?: ElementType
  /**
   * Wraps the label in `[ … ]` brackets — the brand grammar. The brackets
   * are colored by the variant (accent for secondary/ghost, cta-fg for
   * primary, alarm for danger) and stay vertically centered against
   * multi-line wrapped text. Defaults to false.
   */
  bracketed?: boolean
}

export type ButtonProps = CommonProps &
  Omit<ButtonHTMLAttributes<HTMLButtonElement> & AnchorHTMLAttributes<HTMLAnchorElement>, keyof CommonProps>

/**
 * Button — a token-driven action affordance.
 *
 * Four variants:
 *   - primary: gold accent background, dark text. The strong call-to-action.
 *   - secondary: hairline border, accent on hover. The default.
 *   - ghost: no border, muted text, accent on hover. Tertiary actions.
 *   - danger: alarm-toned hairline border, alarm fill on hover. Destructive
 *     or irreversible actions. Pair with a product-layer confirmation —
 *     never use as the default primary action.
 *
 * Size sm/md/lg adjusts padding and font-size.
 */
export function Button({
  children,
  variant = 'secondary',
  size = 'md',
  as,
  bracketed = false,
  className,
  ...rest
}: ButtonProps) {
  const Tag = (as ?? 'button') as ElementType
  return (
    <Tag
      className={joinClasses(
        'rpblc-button',
        `rpblc-button--${variant}`,
        `rpblc-button--${size}`,
        bracketed ? 'rpblc-button--bracketed' : undefined,
        className,
      )}
      {...rest}
    >
      {bracketed ? <span className="rpblc-button__text">{children}</span> : children}
    </Tag>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
