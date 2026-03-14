import { ReactNode, useRef, useEffect, useState } from 'react'

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
  const [contentHeight, setContentHeight] = useState<number | undefined>(undefined)

  useEffect(() => {
    if (contentRef.current) {
      setContentHeight(contentRef.current.scrollHeight)
    }
  }, [children, expanded])

  const panelClass = `panel collapsible-panel${grow && expanded ? ' grow' : ''}`

  return (
    <section className={panelClass}>
      <div
        className="collapsible-header"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={onToggle}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle() } }}
      >
        <span className="collapsible-chevron" aria-hidden="true">{expanded ? '\u25BE' : '\u25B8'}</span>
        <h2>{title}</h2>
        {trailing && <span className="collapsible-trailing">{trailing}</span>}
      </div>
      <div
        className={`collapsible-body${expanded ? ' collapsible-body-open' : ''}`}
        style={{
          maxHeight: expanded ? (grow ? undefined : (contentHeight ?? 800)) : 0,
        }}
      >
        <div ref={contentRef} className="collapsible-inner">
          {children}
        </div>
      </div>
    </section>
  )
}
