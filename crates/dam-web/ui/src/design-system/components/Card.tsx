import { type ElementType, type HTMLAttributes, type ReactNode } from 'react'

export type CardVariant = 'panel' | 'flash' | 'warm'

export type CardProps = {
  children: ReactNode
  variant?: CardVariant
  as?: ElementType
} & Omit<HTMLAttributes<HTMLDivElement>, 'children'>

/**
 * Card — a panel surface with hairline border.
 *
 * Three variants:
 *   - panel: dark/light surface (--panel) with --line border. The default.
 *   - flash: inverted band (--flash-bg). The cream-on-dark moment.
 *   - warm: warm cream variant (--flash-warm). Emphasis without inversion.
 */
export function Card({ children, variant = 'panel', as, className, ...rest }: CardProps) {
  const Tag = (as ?? 'div') as ElementType
  return (
    <Tag
      className={joinClasses('rpblc-card', `rpblc-card--${variant}`, className)}
      {...rest}
    >
      {children}
    </Tag>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
