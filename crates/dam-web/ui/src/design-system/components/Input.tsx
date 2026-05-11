import { forwardRef, useId, type InputHTMLAttributes, type ReactNode } from 'react'

export type InputProps = {
  /** Visible label. If omitted, pass aria-label for accessibility. */
  label?: ReactNode
  /** Error message. When set, switches the input into the error state and renders below. */
  error?: ReactNode
  /** Helper text shown below the input. Hidden when error is present. */
  helper?: ReactNode
} & InputHTMLAttributes<HTMLInputElement>

/**
 * Input — a token-driven text input.
 *
 * Default voice (placeholder, error) follows brand/voice.md — keep messages
 * short, concrete, and human.
 */
export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { label, error, helper, id, className, ...rest },
  ref,
) {
  const generatedId = useId()
  const inputId = id ?? generatedId
  const describedById = error || helper ? `${inputId}-desc` : undefined
  return (
    <div className={joinClasses('rpblc-input', error ? 'rpblc-input--error' : undefined, className)}>
      {label && (
        <label htmlFor={inputId} className="rpblc-input__label">
          {label}
        </label>
      )}
      <input
        ref={ref}
        id={inputId}
        className="rpblc-input__field"
        aria-describedby={describedById}
        aria-invalid={error ? true : undefined}
        {...rest}
      />
      {error && (
        <span id={describedById} className="rpblc-input__error">
          {error}
        </span>
      )}
      {!error && helper && (
        <span id={describedById} className="rpblc-input__helper">
          {helper}
        </span>
      )}
    </div>
  )
})

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
