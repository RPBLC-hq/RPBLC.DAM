import {
  forwardRef,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
  type KeyboardEvent,
  type ButtonHTMLAttributes,
} from 'react'

export type DropdownSize = 'sm' | 'md' | 'lg'

export type DropdownItem<V extends string = string> = {
  value: V
  label: ReactNode
  /** Optional secondary text rendered under the label in mono. */
  description?: ReactNode
  /** Mono leading tag — useful for vault keys or status codes. */
  leading?: ReactNode
  disabled?: boolean
}

export type DropdownProps<V extends string = string> = {
  /** Currently selected value. */
  value: V | null
  /** Called when the user picks a new value. */
  onValueChange: (next: V) => void
  /** Selectable items. */
  items: ReadonlyArray<DropdownItem<V>>
  /** Placeholder shown when no value is selected. */
  placeholder?: ReactNode
  /** Visible label rendered above the trigger. */
  label?: ReactNode
  /** Helper text below the trigger. Hidden when error is present. */
  helper?: ReactNode
  /** Error message. Switches into error state. */
  error?: ReactNode
  /** Size of the trigger. Defaults to "md". */
  size?: DropdownSize
  /** Disabled state. */
  disabled?: boolean
  /** className passed through to the wrapper. */
  className?: string
} & Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'value' | 'children' | 'onChange'>

/**
 * Dropdown — cyber-art-deco select.
 *
 * Rectangular trigger with chevron mark; opens a hairline-bordered listbox
 * panel below. Composes the same color/space tokens as Input.
 *
 * Keyboard:
 *   Enter / Space        open
 *   Escape               close
 *   ArrowDown / ArrowUp  move highlight (opens if closed)
 *   Enter (when open)    select highlighted
 *   Tab                  close (blur)
 *
 * Click outside the trigger or panel closes it.
 *
 * Single-select for v0.1. Multi-select and action-menu variants are on the
 * components/parking-lot.
 */
export const Dropdown = forwardRef<HTMLButtonElement, DropdownProps>(function Dropdown<V extends string = string>(
  {
    value,
    onValueChange,
    items,
    placeholder = 'Select…',
    label,
    helper,
    error,
    size = 'md',
    disabled,
    id,
    className,
    'aria-label': ariaLabel,
    ...rest
  }: DropdownProps<V>,
  ref: React.ForwardedRef<HTMLButtonElement>,
) {
  const generatedId = useId()
  const baseId = id ?? generatedId
  const triggerId = `${baseId}-trigger`
  const listId = `${baseId}-list`
  const labelId = label ? `${baseId}-label` : undefined
  const describedById = error ? `${baseId}-error` : helper ? `${baseId}-helper` : undefined

  const [open, setOpen] = useState(false)
  const [highlight, setHighlight] = useState<number>(() => {
    const idx = items.findIndex((it) => it.value === value)
    return idx >= 0 ? idx : 0
  })

  const wrapperRef = useRef<HTMLDivElement | null>(null)
  const triggerRef = useRef<HTMLButtonElement | null>(null)

  // Forward ref support — `as any` escape hatch to dodge variance between
  // React MutableRefObject vs RefObject typings across versions.
  const setTriggerRef = useCallback(
    (node: HTMLButtonElement | null) => {
      triggerRef.current = node
      if (typeof ref === 'function') ref(node)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      else if (ref) (ref as any).current = node
    },
    [ref],
  )

  // Click outside closes
  useEffect(() => {
    if (!open) return
    const onDocClick = (e: MouseEvent) => {
      if (!wrapperRef.current) return
      if (!wrapperRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDocClick)
    return () => document.removeEventListener('mousedown', onDocClick)
  }, [open])

  const closeAndFocus = useCallback(() => {
    setOpen(false)
    triggerRef.current?.focus()
  }, [])

  const moveHighlight = useCallback(
    (delta: number) => {
      if (items.length === 0) return
      let next = highlight
      for (let i = 0; i < items.length; i++) {
        next = (next + delta + items.length) % items.length
        if (!items[next].disabled) break
      }
      setHighlight(next)
    },
    [highlight, items],
  )

  const onTriggerKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (disabled) return
    switch (e.key) {
      case 'Enter':
      case ' ':
        e.preventDefault()
        setOpen((o) => !o)
        break
      case 'ArrowDown':
        e.preventDefault()
        if (!open) setOpen(true)
        else moveHighlight(1)
        break
      case 'ArrowUp':
        e.preventDefault()
        if (!open) setOpen(true)
        else moveHighlight(-1)
        break
      case 'Escape':
        if (open) {
          e.preventDefault()
          closeAndFocus()
        }
        break
    }
  }

  const onListKeyDown = (e: KeyboardEvent<HTMLUListElement>) => {
    switch (e.key) {
      case 'Enter':
        e.preventDefault()
        commit(highlight)
        break
      case 'Escape':
        e.preventDefault()
        closeAndFocus()
        break
      case 'ArrowDown':
        e.preventDefault()
        moveHighlight(1)
        break
      case 'ArrowUp':
        e.preventDefault()
        moveHighlight(-1)
        break
    }
  }

  const commit = (idx: number) => {
    const item = items[idx]
    if (!item || item.disabled) return
    onValueChange(item.value)
    closeAndFocus()
  }

  const selected = items.find((i) => i.value === value) ?? null

  return (
    <div
      ref={wrapperRef}
      className={joinClasses(
        'rpblc-dropdown',
        `rpblc-dropdown--${size}`,
        open && 'rpblc-dropdown--open',
        error ? 'rpblc-dropdown--error' : undefined,
        disabled && 'rpblc-dropdown--disabled',
        className,
      )}
    >
      {label && (
        <label id={labelId} htmlFor={triggerId} className="rpblc-dropdown__label">
          {label}
        </label>
      )}
      <button
        ref={setTriggerRef}
        id={triggerId}
        type="button"
        className="rpblc-dropdown__trigger"
        onClick={() => !disabled && setOpen((o) => !o)}
        onKeyDown={onTriggerKeyDown}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-labelledby={labelId}
        aria-label={ariaLabel ?? (typeof label === 'string' ? undefined : 'Select')}
        aria-describedby={describedById}
        aria-invalid={error ? true : undefined}
        disabled={disabled}
        {...rest}
      >
        <span className="rpblc-dropdown__value">
          {selected ? (
            <>
              {selected.leading !== undefined && (
                <span className="rpblc-dropdown__value-leading">{selected.leading}</span>
              )}
              <span className="rpblc-dropdown__value-label">{selected.label}</span>
            </>
          ) : (
            <span className="rpblc-dropdown__placeholder">{placeholder}</span>
          )}
        </span>
        <span className="rpblc-dropdown__chevron" aria-hidden="true" />
      </button>

      {open && (
        <ul
          id={listId}
          role="listbox"
          aria-labelledby={labelId}
          className="rpblc-dropdown__panel"
          tabIndex={-1}
          onKeyDown={onListKeyDown}
          ref={(el) => {
            if (el && open) el.focus()
          }}
        >
          {items.map((item, idx) => {
            const isSelected = item.value === value
            const isHighlighted = idx === highlight
            return (
              <li
                key={item.value}
                role="option"
                aria-selected={isSelected}
                aria-disabled={item.disabled || undefined}
                className={joinClasses(
                  'rpblc-dropdown__item',
                  isSelected && 'rpblc-dropdown__item--selected',
                  isHighlighted && 'rpblc-dropdown__item--highlight',
                  item.disabled && 'rpblc-dropdown__item--disabled',
                )}
                onMouseEnter={() => !item.disabled && setHighlight(idx)}
                onMouseDown={(e) => {
                  // Prevent the trigger from blurring before click registers
                  e.preventDefault()
                }}
                onClick={() => commit(idx)}
              >
                {item.leading !== undefined && (
                  <span className="rpblc-dropdown__item-leading">{item.leading}</span>
                )}
                <span className="rpblc-dropdown__item-body">
                  <span className="rpblc-dropdown__item-label">{item.label}</span>
                  {item.description !== undefined && (
                    <span className="rpblc-dropdown__item-desc">{item.description}</span>
                  )}
                </span>
                {isSelected && <span className="rpblc-dropdown__item-mark" aria-hidden="true">:</span>}
              </li>
            )
          })}
        </ul>
      )}

      {error ? (
        <span id={describedById} className="rpblc-dropdown__error">
          {error}
        </span>
      ) : helper ? (
        <span id={describedById} className="rpblc-dropdown__helper">
          {helper}
        </span>
      ) : null}
    </div>
  )
}) as <V extends string = string>(
  props: DropdownProps<V> & { ref?: React.ForwardedRef<HTMLButtonElement> },
) => JSX.Element

function joinClasses(...parts: Array<string | false | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
