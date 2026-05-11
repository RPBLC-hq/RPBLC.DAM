import {
  type ButtonHTMLAttributes,
  type HTMLAttributes,
  type LiHTMLAttributes,
  type ReactNode,
} from 'react'

export type ListViewDensity = 'comfortable' | 'dense'

export type ListViewProps = {
  children: ReactNode
  /** Density. Comfortable (default) for browseable lists; dense for log-style or terminal-like lists. */
  density?: ListViewDensity
  /** Hairline border around the whole list. Defaults to true. */
  bordered?: boolean
} & Omit<HTMLAttributes<HTMLUListElement>, 'children'>

/**
 * ListView — vault-entry-style list container.
 *
 * Hairline border + dividers between items. Use for vault entries, log lists,
 * consent matrices (single-column), and any sequence where items share a
 * structural rhythm.
 *
 * Density:
 *  - "comfortable" (default): mono leading + sans body
 *  - "dense": mono everywhere, tighter padding — for log/terminal lists
 *
 * Pair with ListViewItem children. Each ListViewItem composes the structure;
 * ListView only handles the wrapper.
 */
export function ListView({
  children,
  density = 'comfortable',
  bordered = true,
  className,
  ...rest
}: ListViewProps) {
  return (
    <ul
      className={joinClasses(
        'rpblc-listview',
        `rpblc-listview--${density}`,
        bordered && 'rpblc-listview--bordered',
        className,
      )}
      {...rest}
    >
      {children}
    </ul>
  )
}

type ListViewItemBaseProps = {
  /** Mono leading tag — vault key, log id, type stamp. */
  leading?: ReactNode
  /** Primary text. The thing the row is about. */
  title?: ReactNode
  /** Secondary text under the title. */
  description?: ReactNode
  /** Right-aligned slot — meta, badges, action buttons. */
  trailing?: ReactNode
}

export type ListViewItemProps = ListViewItemBaseProps & {
  /** If provided, renders the item as a button row that fires onClick. */
  onClick?: () => void
} & Omit<LiHTMLAttributes<HTMLLIElement> & ButtonHTMLAttributes<HTMLButtonElement>, 'onClick' | keyof ListViewItemBaseProps>

/**
 * ListViewItem — a single row of a ListView.
 *
 * Layout:
 *   [ leading ]  title           trailing
 *                description
 *
 * If onClick is provided, the row is a focusable button-like surface;
 * otherwise it is a static <li>.
 */
export function ListViewItem({
  leading,
  title,
  description,
  trailing,
  onClick,
  className,
  children,
  ...rest
}: ListViewItemProps) {
  const Tag: 'li' = 'li'
  const isInteractive = typeof onClick === 'function'
  const inner = children ?? (
    <>
      {leading !== undefined && <span className="rpblc-listview-item__leading">{leading}</span>}
      <span className="rpblc-listview-item__body">
        {title !== undefined && <span className="rpblc-listview-item__title">{title}</span>}
        {description !== undefined && <span className="rpblc-listview-item__desc">{description}</span>}
      </span>
      {trailing !== undefined && <span className="rpblc-listview-item__trailing">{trailing}</span>}
    </>
  )
  if (isInteractive) {
    return (
      <Tag
        className={joinClasses('rpblc-listview-item', 'rpblc-listview-item--interactive', className)}
        {...(rest as LiHTMLAttributes<HTMLLIElement>)}
      >
        <button
          type="button"
          className="rpblc-listview-item__button"
          onClick={onClick}
        >
          {inner}
        </button>
      </Tag>
    )
  }
  return (
    <Tag
      className={joinClasses('rpblc-listview-item', className)}
      {...(rest as LiHTMLAttributes<HTMLLIElement>)}
    >
      {inner}
    </Tag>
  )
}

function joinClasses(...parts: Array<string | false | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
