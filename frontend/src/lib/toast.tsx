import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react'
import { Icon } from '../components/Icon'
import type { Tone } from './format'

interface Toast {
  id: number
  tone: Tone
  message: ReactNode
}

type Notify = (message: ReactNode, tone?: Tone) => void

const ToastContext = createContext<Notify | null>(null)
const DURATION_MS = 4500

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(0)

  const dismiss = useCallback((id: number) => setToasts((list) => list.filter((t) => t.id !== id)), [])

  const notify = useCallback<Notify>(
    (message, tone = 'neutral') => {
      const id = ++nextId.current
      setToasts((list) => [...list.slice(-3), { id, tone, message }])
      window.setTimeout(() => dismiss(id), DURATION_MS)
    },
    [dismiss],
  )

  return (
    <ToastContext.Provider value={notify}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast tone-${toast.tone}`}>
            <Icon name={toast.tone === 'good' ? 'check' : toast.tone === 'neutral' ? 'info' : 'alert'} size={16} />
            <div>{toast.message}</div>
            <button onClick={() => dismiss(toast.id)} aria-label="Dismiss">
              <Icon name="close" size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): Notify {
  const notify = useContext(ToastContext)
  if (!notify) throw new Error('useToast must be used inside ToastProvider')
  return notify
}
