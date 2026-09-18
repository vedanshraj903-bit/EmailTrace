import { useCallback, useEffect, useState } from 'react'

interface ResourceState<T> {
  data: T | undefined
  error: Error | undefined
  loading: boolean
}

/**
 * Loads data for the given dependency key, cancelling stale requests when the key changes.
 * Pass `null` as the key to skip loading.
 */
export function useResource<T>(key: string | null, load: (signal: AbortSignal) => Promise<T>) {
  const [state, setState] = useState<ResourceState<T>>({ data: undefined, error: undefined, loading: key !== null })
  const [version, setVersion] = useState(0)

  useEffect(() => {
    if (key === null) return
    const controller = new AbortController()
    setState((previous) => ({ ...previous, loading: true, error: undefined }))
    load(controller.signal)
      .then((data) => setState({ data, error: undefined, loading: false }))
      .catch((error: Error) => {
        if (controller.signal.aborted) return
        setState((previous) => ({ ...previous, error, loading: false }))
      })
    return () => controller.abort()
    // `load` is intentionally excluded: callers pass inline closures keyed by `key`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, version])

  const reload = useCallback(() => setVersion((v) => v + 1), [])
  return { ...state, reload }
}
