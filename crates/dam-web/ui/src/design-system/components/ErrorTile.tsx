import { type HTMLAttributes, type ReactNode } from 'react'

export type ErrorTileProps = {
  /** The hand-written banker-voice sentence. Plain text, no "Error:". */
  message: ReactNode
  /** Optional trailing affordance — usually a ghost-variant retry Button. */
  action?: ReactNode
} & Omit<HTMLAttributes<HTMLDivElement>, 'children'>

/**
 * ErrorTile — calm one-sentence tile for error states.
 *
 * Solid hairline border with a 2px alarm rail on the left. Sans-serif
 * sentence in --text. Optional ghost action right-aligned. The message
 * MUST be a hand-written banker-voice sentence — never a raw error
 * code, stack trace, or backend string. The translation is the
 * consumer's responsibility (see `RPBLC.Architecture/dam/web/specs/error-policy.md`
 * for the DAM mapping convention).
 */
export function ErrorTile({ message, action, className, ...rest }: ErrorTileProps) {
  return (
    <div className={join('rpblc-state-tile', 'rpblc-state-tile--error', className)} role="alert" {...rest}>
      <span className="rpblc-state-tile__message">{message}</span>
      {action && <span className="rpblc-state-tile__action">{action}</span>}
    </div>
  )
}

function join(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
