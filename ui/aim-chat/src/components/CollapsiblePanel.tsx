import { ReactNode, useRef, useEffect, useState, useId } from 'react'

export interface CollapsiblePanelProps {
  title: string
  expanded: boolean
  onToggle: () => void
  grow?: boolean
  trailing?: ReactNode
  children: ReactNode
}

export function CollapsiblePanel({
  title,
  expanded,
  onToggle,
  grow,
  trailing,
  children,
}: CollapsiblePanelProps) {
  const contentRef = useRef<HTMLDivElement>(null)
  const bodyId = useId()
  const [contentHeight, setContentHeight] = useState<number | undefined>(undefined)
  // React 18 forwards the native inert attribute as a string, not a boolean.
  // Keep children mounted so drafts survive collapsing while excluding controls
  // from focus, pointer interaction and the accessibility tree immediately.
  const inertProps = expanded ? {} : { inert: '' }

  useEffect(() => {
    const el = contentRef.current
    if (!el) return

    setContentHeight(el.scrollHeight)

    const observer = new ResizeObserver(() => {
      setContentHeight(el.scrollHeight)
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [expanded])

  const panelClass = `panel collapsible-panel${grow && expanded ? ' grow' : ''}`

  return (
    <section className={panelClass}>
      <div
        className="collapsible-header"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        aria-controls={bodyId}
        onClick={onToggle}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle() } }}
      >
        <span className="collapsible-chevron" aria-hidden="true">{expanded ? '\u25BE' : '\u25B8'}</span>
        <h2>{title}</h2>
        {trailing && <span className="collapsible-trailing">{trailing}</span>}
      </div>
      <div
        {...inertProps}
        id={bodyId}
        aria-hidden={!expanded}
        className={`collapsible-body${expanded ? ' collapsible-body-open' : ''}`}
        style={{
          maxHeight: expanded ? (grow ? 'none' : (contentHeight ?? 800)) : 0,
        }}
      >
        <div ref={contentRef} className="collapsible-inner">
          {children}
        </div>
      </div>
    </section>
  )
}
