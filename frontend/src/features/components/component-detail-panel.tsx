import {
  FileSearch,
  RotateCcw,
  TriangleAlert,
  X,
} from "lucide-react"
import {
  useEffect,
  useState,
} from "react"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { ComponentDetailContent } from "@/features/components/component-detail-content"
import { ComponentDetailSkeleton } from "@/features/components/component-detail-skeleton"
import { getComponentDetail } from "@/features/components/components-api"
import type { ComponentDetail } from "@/features/components/components-types"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"

type DetailStatus =
  | "unselected"
  | "invalid"
  | "loading"
  | "success"
  | "not-found"
  | "error"

function repositoryBasename(repository: string): string {
  return repository.split("/").at(-1) ?? repository
}

function CloseButton({ onClose }: { onClose: () => void }) {
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-sm"
      aria-label="Close component details"
      onClick={onClose}
    >
      <X aria-hidden="true" />
    </Button>
  )
}

function DetailError({
  status,
  onRetry,
  onClose,
}: {
  status: "invalid" | "not-found" | "error"
  onRetry: () => void
  onClose: () => void
}) {
  const title =
    status === "invalid"
      ? "Invalid component selection"
      : status === "not-found"
        ? "Component not found"
        : "Unable to load component details"
  const description =
    status === "invalid"
      ? "The component identifier in the URL is not valid."
      : status === "not-found"
        ? "The selected component is not available in the current dataset."
        : "The frontend could not retrieve the selected component."

  return (
    <div className="flex min-h-0 flex-1 items-center p-4">
      <Alert variant="destructive" className="p-4">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>{title}</AlertTitle>
        <AlertDescription>{description}</AlertDescription>
        <div className="col-start-2 mt-3 flex flex-wrap gap-2">
          {status === "error" ? (
            <Button
              type="button"
              variant="outline"
              onClick={onRetry}
            >
              <RotateCcw aria-hidden="true" />
              Retry
            </Button>
          ) : null}
          <Button
            type="button"
            variant="outline"
            onClick={onClose}
          >
            Close details
          </Button>
        </div>
      </Alert>
    </div>
  )
}

export function ComponentDetailPanel({
  componentId,
  invalidComponentId,
  onClose,
}: {
  componentId?: number
  invalidComponentId: boolean
  onClose: () => void
}) {
  const [detail, setDetail] = useState<ComponentDetail | null>(
    null,
  )
  const [status, setStatus] =
    useState<DetailStatus>("unselected")
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    if (invalidComponentId) {
      setDetail(null)
      setStatus("invalid")
      return
    }
    if (componentId === undefined) {
      setDetail(null)
      setStatus("unselected")
      return
    }

    const controller = new AbortController()
    let active = true

    setDetail(null)
    setStatus("loading")
    getComponentDetail(componentId, controller.signal)
      .then((response) => {
        if (!active) return
        setDetail(response)
        setStatus("success")
      })
      .catch((error: unknown) => {
        if (!active || isAbortError(error)) return
        setStatus(
          error instanceof ApiError && error.status === 404
            ? "not-found"
            : "error",
        )
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [componentId, invalidComponentId, reloadToken])

  return (
    <aside
      aria-label="Component details"
      className="sticky top-6 h-[calc(100vh-3rem)] w-[470px] shrink-0"
    >
      <Card className="h-full gap-0 overflow-hidden py-0">
        {status === "unselected" ? (
          <div className="flex h-full flex-col items-center justify-center px-8 text-center">
            <div className="flex size-11 items-center justify-center rounded-xl bg-muted text-muted-foreground">
              <FileSearch className="size-5" aria-hidden="true" />
            </div>
            <h2 className="mt-4 font-heading text-base font-semibold">
              Select a component
            </h2>
            <p className="mt-1 max-w-xs text-sm leading-6 text-muted-foreground">
              Choose a row to inspect its metadata and CPE evidence.
            </p>
          </div>
        ) : null}

        {status === "invalid" ||
        status === "not-found" ||
        status === "error" ? (
          <DetailError
            status={status}
            onRetry={() =>
              setReloadToken((current) => current + 1)
            }
            onClose={onClose}
          />
        ) : null}

        {status === "loading" ? (
          <div className="flex h-full min-h-0 flex-col">
            <div className="flex shrink-0 items-center justify-between border-b bg-card p-4">
              <div>
                <p className="font-heading text-sm font-semibold">
                  Loading component details
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Read-only evidence
                </p>
              </div>
              <CloseButton onClose={onClose} />
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto">
              <ComponentDetailSkeleton />
            </div>
          </div>
        ) : null}

        {status === "success" && detail ? (
          <div className="flex h-full min-h-0 flex-col">
            <div className="z-10 flex shrink-0 items-start justify-between gap-3 border-b bg-card p-4">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="font-heading text-base font-semibold">
                    {detail.name || "Not provided"}
                  </h2>
                  <Badge variant="outline">Read only</Badge>
                </div>
                <p className="mt-1 font-mono text-xs text-muted-foreground">
                  {detail.version || "Not provided"}
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <Badge variant="secondary">
                    {detail.component_type || "Not provided"}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {repositoryBasename(
                      detail.image.repository,
                    )}
                    :{detail.image.tag}
                  </span>
                </div>
              </div>
              <CloseButton onClose={onClose} />
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto">
              <ComponentDetailContent detail={detail} />
            </div>
          </div>
        ) : null}
      </Card>
    </aside>
  )
}
