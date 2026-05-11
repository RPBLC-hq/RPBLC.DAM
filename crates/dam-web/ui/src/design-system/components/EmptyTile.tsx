import { type HTMLAttributes, type ReactNode } from 'react'

export type EmptyTileProps = {
  /** The single short sentence the tile communicates. Mono uppercase, muted. */
  message: ReactNode
  /** Optional trailing affordance — usually a ghost-variant Button. */
  action?: ReactNode
} & Omit<HTMLAttributes<HTMLDivElement>, 'children'>

/**
 * EmptyTile — calm one-sentence tile for empty states.
 *
 * Dashed hairline border, mono uppercase copy in --muted, optional ghost
 * action right-aligned. Used across surfaces for "nothing's asking",
 * "no value matches", "nothing happened today", etc.
 *
 * Pair with `ErrorTile` for the same shape with an alarm rail.
 */
export function EmptyTile({ message, action, className, ...rest }: EmptyTileProps) {
  return (
    <div className={join('rpblc-state-tile', 'rpblc-state-tile--empty', className)} role="status" {...rest}>
      <span className="rpblc-state-tile__message">{message}</span>
      {action && <span className="rpblc-state-tile__action">{action}</span>}
    </div>
  )
}

function join(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
