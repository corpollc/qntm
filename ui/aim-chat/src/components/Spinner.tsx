export interface SpinnerProps {
  size?: 'sm' | 'md'
}

export function Spinner({ size = 'sm' }: SpinnerProps) {
  return <span className={`spinner spinner-${size}`} aria-label="Loading" />
}
