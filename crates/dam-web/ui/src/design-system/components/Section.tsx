import { type ElementType, type HTMLAttributes, type ReactNode } from 'react'

export type SectionDensity = 'comfortable' | 'compact'

export type SectionProps = {
  children: ReactNode
  /** Eyebrow label above the title. Mono, accent, uppercase. */
  eyebrow?: ReactNode
  /** Section title. */
  title?: ReactNode
  /**
   * Spacing density.
   *
   * - `comfortable` (default): hero/marketing surfaces. Generous padding,
   *   sans-serif title.
   * - `compact`: product settings surfaces. Tighter padding, mono uppercase
   *   title that doubles as the section eyebrow. Mobile shrinks padding
   *   by one step.
   */
  density?: SectionDensity
  as?: ElementType
} & Omit<HTMLAttributes<HTMLElement>, 'children' | 'title'>

/**
 * Section — a titled content panel.
 *
 * Composes the bordered panel pattern with optional eyebrow + title header.
 * The eyebrow follows the brand convention: mono, --accent, uppercase, tracked.
 */
export function Section({
  children,
  eyebrow,
  title,
  density = 'comfortable',
  as,
  className,
  ...rest
}: SectionProps) {
  const Tag = (as ?? 'section') as ElementType
  return (
    <Tag
      className={joinClasses('rpblc-section', `rpblc-section--${density}`, className)}
      {...rest}
    >
      {(eyebrow || title) && (
        <header className="rpblc-section__header">
          {eyebrow && <span className="rpblc-section__eyebrow">{eyebrow}</span>}
          {title && <h2 className="rpblc-section__title">{title}</h2>}
        </header>
      )}
      <div className="rpblc-section__body">{children}</div>
    </Tag>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
