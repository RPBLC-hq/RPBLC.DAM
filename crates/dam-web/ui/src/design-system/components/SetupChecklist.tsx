import { type HTMLAttributes, type ReactNode } from 'react'

export type SetupStepState = 'todo' | 'current' | 'done' | 'blocked' | 'failed'

export type SetupStep = {
  /** Stable backend id (e.g. `ne_install`). Surfaced as the React key. */
  id: string
  /** One short imperative phrase. */
  label: ReactNode
  /** State drives the visual treatment and the trailing glyph. */
  state: SetupStepState
  /**
   * Optional longer explanation revealed by hovering / focusing the
   * inline `(i)` info marker. Use when the short `label` can't carry
   * the full reason (e.g. "Add to login items" → hint explains why
   * launch-at-login is needed before the reboot step).
   */
  hint?: ReactNode
  /** When `failed` or `blocked`, a one-line banker-voice reason rendered under the label. */
  reason?: ReactNode
}

export type SetupChecklistProps = {
  steps: SetupStep[]
  /** Accessible label for `done` glyph. Translate at call site. */
  doneAriaLabel?: string
  /** Accessible label for `current` glyph. */
  currentAriaLabel?: string
  /** Accessible label for `failed` glyph. */
  failedAriaLabel?: string
  /** Accessible label for `blocked` glyph. */
  blockedAriaLabel?: string
  /** Accessible label for the hint info marker (e.g. "more info"). */
  hintAriaLabel?: string
} & Omit<HTMLAttributes<HTMLOListElement>, 'children'>

/**
 * SetupChecklist — resumable step list.
 *
 * Each step has a stable id, a label, a state (todo/current/done/blocked/failed),
 * and an optional reason. The component renders a numbered list with state-tinted
 * rows, a trailing state glyph, and (when failed/blocked) a one-line reason.
 *
 * The component is presentational; it owns no state. Consumers fetch the steps
 * from the backend (e.g. `dam-diagnostics::SetupPlan`) on every mount, so the
 * UI is resumable across hide/show without client-side checkpointing.
 *
 * The CTA below the checklist is the consumer's responsibility — typically a
 * bracketed `Button` whose label names the consequence of advancing the
 * `current` step.
 */
export function SetupChecklist({
  steps,
  doneAriaLabel = 'done',
  currentAriaLabel = 'current',
  failedAriaLabel = 'failed',
  blockedAriaLabel = 'blocked',
  hintAriaLabel = 'more info',
  className,
  ...rest
}: SetupChecklistProps) {
  return (
    <ol className={join('rpblc-setup-checklist', className)} {...rest}>
      {steps.map((step, i) => (
        <li
          // The id is a stable action handle but not necessarily unique
          // across rendered rows — the diagnostics plan can surface
          // multiple checks that resolve under the same action. Compose
          // with the index to guarantee a unique React key without
          // changing the action contract.
          key={`${step.id}-${i}`}
          className={join('rpblc-setup-checklist__step', `rpblc-setup-checklist__step--${step.state}`)}
          aria-current={step.state === 'current' ? 'step' : undefined}
        >
          <span className="rpblc-setup-checklist__num" aria-hidden="true">
            {String(i + 1).padStart(2, '0')}
          </span>
          <span className="rpblc-setup-checklist__body">
            <span className="rpblc-setup-checklist__label-row">
              <span className="rpblc-setup-checklist__label">{step.label}</span>
              {step.hint && (
                // The hint marker uses the brand's bracket grammar
                // (`[i]`), with a CSS-only tooltip on the parent. The
                // tooltip shows immediately on hover/focus (no native
                // title delay) and is styled to match the panel
                // (mono, hairline border, accent bracket). `aria-label`
                // carries the hint copy for screen readers; sighted
                // users see it as the popup. `aria-describedby` would
                // be cleaner but requires generated ids; the current
                // pattern is good enough for a first-run aid.
                <span className="rpblc-setup-checklist__hint-anchor">
                  <button
                    type="button"
                    className="rpblc-setup-checklist__hint"
                    aria-label={
                      typeof step.hint === 'string'
                        ? `${hintAriaLabel}: ${step.hint}`
                        : hintAriaLabel
                    }
                  >
                    [i]
                  </button>
                  <span className="rpblc-setup-checklist__hint-tip" role="tooltip">
                    {step.hint}
                  </span>
                </span>
              )}
            </span>
            {step.reason && (step.state === 'failed' || step.state === 'blocked') && (
              <span className="rpblc-setup-checklist__reason">{step.reason}</span>
            )}
          </span>
          <span
            className="rpblc-setup-checklist__state"
            aria-label={ariaLabelFor(step.state, {
              done: doneAriaLabel,
              current: currentAriaLabel,
              failed: failedAriaLabel,
              blocked: blockedAriaLabel,
            })}
          >
            {glyphFor(step.state)}
          </span>
        </li>
      ))}
    </ol>
  )
}

function glyphFor(state: SetupStepState): string {
  switch (state) {
    case 'done':
      return '✓'
    case 'failed':
      return '!'
    case 'blocked':
      return '⏸'
    case 'current':
      return '›'
    default:
      return ''
  }
}

function ariaLabelFor(
  state: SetupStepState,
  labels: { done: string; current: string; failed: string; blocked: string },
): string | undefined {
  switch (state) {
    case 'done':
      return labels.done
    case 'current':
      return labels.current
    case 'failed':
      return labels.failed
    case 'blocked':
      return labels.blocked
    default:
      return undefined
  }
}

function join(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
