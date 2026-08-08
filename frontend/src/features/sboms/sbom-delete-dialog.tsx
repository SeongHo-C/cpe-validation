import { LoaderCircle, Trash2, TriangleAlert } from "lucide-react"
import { useState } from "react"
import type { FormEvent } from "react"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { deleteSbom } from "@/features/sboms/sboms-query"
import type { SbomDocumentSummary } from "@/features/sboms/sboms-types"
import { ApiError } from "@/lib/api-client"

function deleteError(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) {
    return "This SBOM no longer exists."
  }
  if (error instanceof ApiError && error.status === 409) {
    return (
      error.detail ??
      "This SBOM cannot be deleted because protected data depends on it."
    )
  }
  return "Unable to delete SBOM."
}

function displayValue(value: string): string {
  return value || "—"
}

export function SbomDeleteDialog({
  sbom,
  onOpenChange,
  onDeleted,
}: {
  sbom: SbomDocumentSummary | null
  onOpenChange: (open: boolean) => void
  onDeleted: (sbomId: number) => void
}) {
  const [isDeleting, setIsDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const changeOpen = (open: boolean) => {
    if (isDeleting) return
    if (!open) setError(null)
    onOpenChange(open)
  }

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!sbom || isDeleting) return

    setIsDeleting(true)
    setError(null)
    try {
      await deleteSbom(sbom.id)
      onOpenChange(false)
      onDeleted(sbom.id)
    } catch (reason: unknown) {
      setError(deleteError(reason))
    } finally {
      setIsDeleting(false)
    }
  }

  return (
    <Dialog open={sbom !== null} onOpenChange={changeOpen}>
      <DialogContent
        showCloseButton={!isDeleting}
        aria-busy={isDeleting}
        onEscapeKeyDown={(event) => {
          if (isDeleting) event.preventDefault()
        }}
        onPointerDownOutside={(event) => {
          if (isDeleting) event.preventDefault()
        }}
      >
        <DialogHeader>
          <DialogTitle>Delete SBOM?</DialogTitle>
          <DialogDescription>
            Confirm the uploaded document you want to remove.
          </DialogDescription>
        </DialogHeader>

        {sbom ? (
          <form className="space-y-4" onSubmit={(event) => void submit(event)}>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 rounded-lg border bg-muted/30 p-4 text-sm">
              <dt className="text-muted-foreground">Manufacturer</dt>
              <dd className="min-w-0 break-words font-medium">
                {displayValue(sbom.manufacturer)}
              </dd>
              <dt className="text-muted-foreground">Product name</dt>
              <dd className="min-w-0 break-words font-medium">
                {displayValue(sbom.product_name)}
              </dd>
              <dt className="text-muted-foreground">Product version</dt>
              <dd className="min-w-0 break-words font-medium">
                {displayValue(sbom.product_version)}
              </dd>
              <dt className="text-muted-foreground">Original filename</dt>
              <dd className="min-w-0 break-words font-medium">
                {displayValue(sbom.original_filename)}
              </dd>
            </dl>

            <p className="text-sm text-muted-foreground">
              Deleting this SBOM will remove its imported components. If
              protected review data exists, deletion will be blocked. This
              action cannot be undone.
            </p>

            {error ? (
              <Alert variant="destructive">
                <TriangleAlert aria-hidden="true" />
                <AlertTitle>Delete failed</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={isDeleting}
                onClick={() => changeOpen(false)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="destructive"
                disabled={isDeleting}
              >
                {isDeleting ? (
                  <LoaderCircle className="animate-spin" aria-hidden="true" />
                ) : (
                  <Trash2 aria-hidden="true" />
                )}
                {isDeleting ? "Deleting…" : "Delete SBOM"}
              </Button>
            </DialogFooter>
          </form>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
