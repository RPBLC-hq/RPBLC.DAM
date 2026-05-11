import {
  type HTMLAttributes,
  type KeyboardEvent,
  type ReactNode,
  useCallback,
  useId,
  useRef,
} from 'react'

export type SegmentedControlSize = 'sm' | 'md'

export type SegmentedControlOption<T extends string = string> = {
  /** Stable value. */
  value: T
  /** User-facing label. */
  label: ReactNode
  /** Optional accessible label override (used when `label` is not a string). */
  ariaLabel?: string
  disabled?: boolean
}

export type SegmentedControlProps<T extends string = string> = {
  /** Controlled value. */
  value: T
  /** Required handler — controlled component. */
  onValueChange: (next: T) => void
  /** Mutually-exclusive options. Two to four work; five wraps. */
  options: ReadonlyArray<SegmentedControlOption<T>>
  /** Required group label for assistive tech. */
  'aria-label': string
  size?: SegmentedControlSize
  /** Stretch to fill the container width. Default: false (auto width). */
  fullWidth?: boolean
  className?: string
} & Omit<HTMLAttributes<HTMLDivElement>, 'onChange' | 'aria-label'>

/**
 * SegmentedControl — compact mutually-exclusive single-select.
 *
 * Use when every option must be visible at once and the set is small (≤4).
 * The control is a true ARIA radiogroup so screen readers announce the
 * exclusive selection. Roving-tabindex left/right arrow keys move focus and
 * activate the next option, mirroring native radio behavior.
 *
 * For ordered cyclic modes where only the current value needs to be visible,
 * use CycleButton. For larger known sets, use Dropdown.
 */
export function SegmentedControl<T extends string = string>({
  value,
  onValueChange,
  options,
  size = 'sm',
  fullWidth = false,
  className,
  'aria-label': ariaLabel,
  ...rest
}: SegmentedControlProps<T>) {
  const groupId = useId()
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([])

  const focusOption = useCallback((index: number) => {
    const list = itemRefs.current
    const el = list[index]
    if (el && !el.disabled) {
      el.focus()
    }
  }, [])

  const enabledIndexAfter = useCallback(
    (start: number, step: 1 | -1) => {
      const len = options.length
      let i = start
      for (let n = 0; n < len; n++) {
        i = (i + step + len) % len
        if (!options[i].disabled) return i
      }
      return start
    },
    [options],
  )

  const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      event.preventDefault()
      const next = enabledIndexAfter(index, 1)
      onValueChange(options[next].value)
      focusOption(next)
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      event.preventDefault()
      const next = enabledIndexAfter(index, -1)
      onValueChange(options[next].value)
      focusOption(next)
    } else if (event.key === 'Home') {
      event.preventDefault()
      const first = options.findIndex((o) => !o.disabled)
      if (first >= 0) {
        onValueChange(options[first].value)
        focusOption(first)
      }
    } else if (event.key === 'End') {
      event.preventDefault()
      for (let i = options.length - 1; i >= 0; i--) {
        if (!options[i].disabled) {
          onValueChange(options[i].value)
          focusOption(i)
          return
        }
      }
    }
  }

  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      className={joinClasses(
        'rpblc-segmented',
        `rpblc-segmented--${size}`,
        fullWidth ? 'rpblc-segmented--full' : undefined,
        className,
      )}
      style={
        fullWidth
          ? { gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))` }
          : undefined
      }
      {...rest}
    >
      {options.map((option, index) => {
        const selected = option.value === value
        const id = `${groupId}-${index}`
        return (
          <button
            key={option.value}
            id={id}
            ref={(el) => {
              itemRefs.current[index] = el
            }}
            type="button"
            role="radio"
            aria-checked={selected}
            aria-label={option.ariaLabel}
            disabled={option.disabled}
            tabIndex={selected ? 0 : -1}
            className={joinClasses(
              'rpblc-segmented__option',
              selected ? 'rpblc-segmented__option--selected' : undefined,
            )}
            onClick={() => {
              if (!option.disabled) onValueChange(option.value)
            }}
            onKeyDown={(event) => handleKeyDown(event, index)}
          >
            <span className="rpblc-segmented__label">{option.label}</span>
          </button>
        )
      })}
    </div>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
