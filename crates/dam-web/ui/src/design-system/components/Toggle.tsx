import { forwardRef, useId, type ButtonHTMLAttributes, type ReactNode } from 'react'

export type ToggleSize = 'sm' | 'md' | 'lg'

export type ToggleProps = {
  /** Whether the toggle is on. */
  checked: boolean
  /** Called when the toggle changes. */
  onCheckedChange: (next: boolean) => void
  /** Visible label. If omitted, pass aria-label for accessibility. */
  label?: ReactNode
  /** Helper text shown below. */
  helper?: ReactNode
  /** Size of the toggle. Defaults to "md". */
  size?: ToggleSize
  /** Disabled state. */
  disabled?: boolean
} & Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'onClick' | 'onChange' | 'children' | 'role'>

/**
 * Toggle — cyber-art-deco rectangular switch.
 *
 * No rounded ornament. Track is a hairline rectangle in --soft at rest,
 * --accent fill when on. Knob is a smaller rectangle that slides between edges.
 *
 * Accessible: role="switch" + aria-checked. Click and keyboard (Space/Enter)
 * both toggle.
 */
export const Toggle = forwardRef<HTMLButtonElement, ToggleProps>(function Toggle(
  {
    checked,
    onCheckedChange,
    label,
    helper,
    size = 'md',
    disabled,
    id,
    className,
    'aria-label': ariaLabel,
    ...rest
  },
  ref,
) {
  const generatedId = useId()
  const switchId = id ?? generatedId
  const helperId = helper ? `${switchId}-helper` : undefined
  return (
    <div className={joinClasses('rpblc-toggle', `rpblc-toggle--${size}`, disabled && 'rpblc-toggle--disabled', className)}>
      <div className="rpblc-toggle__row">
        <button
          ref={ref}
          id={switchId}
          type="button"
          role="switch"
          aria-checked={checked}
          aria-label={ariaLabel ?? (typeof label === 'string' ? label : undefined)}
          aria-describedby={helperId}
          disabled={disabled}
          className={joinClasses('rpblc-toggle__track', checked && 'rpblc-toggle__track--on')}
          onClick={() => !disabled && onCheckedChange(!checked)}
          {...rest}
        >
          <span className="rpblc-toggle__knob" aria-hidden="true" />
        </button>
        {label && (
          <label htmlFor={switchId} className="rpblc-toggle__label">
            {label}
          </label>
        )}
      </div>
      {helper && (
        <span id={helperId} className="rpblc-toggle__helper">
          {helper}
        </span>
      )}
    </div>
  )
})

function joinClasses(...parts: Array<string | false | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
