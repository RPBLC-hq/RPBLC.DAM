import { type HTMLAttributes, type ReactNode } from 'react'

export type StatProps = {
  /** The numeric or short string value (e.g. "98.7%", "$2.3M"). */
  value: ReactNode
  /** Description of what the value represents. */
  label: ReactNode
  /** Optional source citation rendered below in mono. */
  source?: ReactNode
} & Omit<HTMLAttributes<HTMLDListElement>, 'children'>

/**
 * Stat — a value/label/source triple.
 *
 * Used in evidence sections. Value in mono, large. Label in body. Source in
 * mono, --soft, small.
 */
export function Stat({ value, label, source, className, ...rest }: StatProps) {
  return (
    <dl className={joinClasses('rpblc-stat', className)} {...rest}>
      <dt className="rpblc-stat__value">{value}</dt>
      <dd className="rpblc-stat__label">{label}</dd>
      {source && <span className="rpblc-stat__source">{source}</span>}
    </dl>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
