export interface TooltipProps {
  text: string
}

export function Tooltip({ text }: TooltipProps) {
  return (
    <span className="tooltip-trigger" tabIndex={0} aria-label={text}>
      <span className="tooltip-icon">?</span>
      <span className="tooltip-text" role="tooltip">{text}</span>
    </span>
  )
}
