import { useCallback, useRef, useState } from 'react'

export type ToastType = 'success' | 'error' | 'info'

export interface Toast {
  id: string
  message: string
  type: ToastType
  duration: number
}

const DEFAULT_DURATIONS: Record<ToastType, number> = {
  success: 4000,
  info: 4000,
  error: 8000,
}

const MAX_VISIBLE = 3

let nextId = 0

export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([])
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  const removeToast = useCallback((id: string) => {
    const timer = timersRef.current.get(id)
    if (timer) {
      clearTimeout(timer)
      timersRef.current.delete(id)
    }
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const addToast = useCallback((message: string, type: ToastType, duration?: number) => {
    const id = `toast-${++nextId}`
    const dur = duration ?? DEFAULT_DURATIONS[type]
    const toast: Toast = { id, message, type, duration: dur }

    setToasts((prev) => {
      // If already at max, remove oldest to make room
      const next = prev.length >= MAX_VISIBLE ? prev.slice(1) : [...prev]
      if (prev.length >= MAX_VISIBLE) {
        const removed = prev[0]
        const timer = timersRef.current.get(removed.id)
        if (timer) {
          clearTimeout(timer)
          timersRef.current.delete(removed.id)
        }
        next.push(toast)
        return next
      }
      return [...prev, toast]
    })

    const timer = setTimeout(() => {
      timersRef.current.delete(id)
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, dur)
    timersRef.current.set(id, timer)

    return id
  }, [])

  return { toasts, addToast, removeToast }
}
