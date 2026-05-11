import {
  forwardRef,
  type InputHTMLAttributes,
  type ReactNode,
} from 'react'

export type SearchBarProps = {
  /** Current value. Controlled. */
  value: string
  /** Called with the new value on every keystroke. */
  onValueChange: (next: string) => void
  /** Placeholder text. Defaults to "Search…". */
  placeholder?: string
  /**
   * Leading glyph. Defaults to `»` (the brand's forward-pointing chevron).
   * Pass `null` to hide. Pass a ReactNode for a custom mark.
   */
  icon?: ReactNode
  /**
   * Optional trailing slot — typically a result count rendered as
   * `5 / 12` or `5/12` mono uppercase. Free-form `ReactNode`.
   */
  count?: ReactNode
} & Omit<
  InputHTMLAttributes<HTMLInputElement>,
  'value' | 'onChange' | 'placeholder' | 'type'
>

/**
 * SearchBar — a focused search affordance.
 *
 * One row, one purpose: type to filter. The leading glyph plants the
 * brand's mono register; the input is transparent and flush; the
 * trailing count slot reports the filter outcome without taking a
 * second row.
 *
 * Distinct from `Input`:
 *   - No visible label (placeholder is the label) — pass `aria-label`
 *     for the accessible name.
 *   - No helper or error text.
 *   - Always `type="search"` and always mono.
 *   - Has a built-in count slot.
 *
 * Use `Input` when the field is part of a form. Use `SearchBar` when
 * it's an instant filter on a list, table, or wallet.
 */
export const SearchBar = forwardRef<HTMLInputElement, SearchBarProps>(
  function SearchBar(
    { value, onValueChange, placeholder = 'Search…', icon = '»', count, className, ...rest },
    ref,
  ) {
    return (
      <div className={joinClasses('rpblc-search-bar', className)}>
        {icon !== null && icon !== false && (
          <span className="rpblc-search-bar__icon" aria-hidden="true">
            {icon}
          </span>
        )}
        <input
          ref={ref}
          type="search"
          className="rpblc-search-bar__input"
          value={value}
          onChange={(e) => onValueChange(e.currentTarget.value)}
          placeholder={placeholder}
          {...rest}
        />
        {count !== undefined && count !== null && (
          <span className="rpblc-search-bar__count">{count}</span>
        )}
      </div>
    )
  },
)

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
