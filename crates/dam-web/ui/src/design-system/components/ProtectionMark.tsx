import { type HTMLAttributes, type ReactNode } from 'react'

export type ProtectionState = 'protected' | 'allowed' | 'revoked'

export type ProtectionMarkProps = {
  state: ProtectionState
  /** Override the visible label. Defaults to the state name. */
  label?: ReactNode
} & Omit<HTMLAttributes<HTMLSpanElement>, 'children'>

/**
 * ProtectionMark — a small bordered pill with a colored dot, labeling
 * the protection state of a stored value.
 *
 *   protected  · gold dot, hairline border
 *   allowed    · cream/ink dot, soft border
 *   revoked    · alarm dot, alarm border + text
 *
 * Use on wallet rows, value-detail headers, and audit timelines. The
 * three-state vocabulary is the data-vault counterpart to the formal
 * grant lifecycle on `ConsentStateMark`. They are deliberately
 * distinct components.
 */
export function ProtectionMark({
  state,
  label,
  className,
  ...rest
}: ProtectionMarkProps) {
  return (
    <span
      className={joinClasses('rpblc-protection-mark', `rpblc-protection-mark--${state}`, className)}
      data-state={state}
      {...rest}
    >
      <span className="rpblc-protection-mark__dot" aria-hidden="true" />
      <span className="rpblc-protection-mark__label">{label ?? state}</span>
    </span>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
