import { useEffect, useState } from "react"

import type { ApiConnectionStatus } from "@/components/api-status"
import { getApiHealth } from "@/features/images/images-api"
import { isAbortError } from "@/lib/api-client"

export function useApiHealth(): ApiConnectionStatus {
  const [status, setStatus] =
    useState<ApiConnectionStatus>("checking")

  useEffect(() => {
    const controller = new AbortController()
    let active = true

    getApiHealth(controller.signal)
      .then((health) => {
        if (!active) return
        setStatus(
          health.status === "ok" && health.database === "ok"
            ? "connected"
            : "unavailable",
        )
      })
      .catch((error: unknown) => {
        if (active && !isAbortError(error)) {
          setStatus("unavailable")
        }
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [])

  return status
}
