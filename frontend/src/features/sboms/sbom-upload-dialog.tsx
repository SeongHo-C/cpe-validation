import { LoaderCircle, TriangleAlert, Upload } from "lucide-react"
import { useRef, useState } from "react"
import type { FormEvent } from "react"

import { formLabelTextClassName } from "@/components/form-control-styles"
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { uploadSbom } from "@/features/sboms/sboms-query"
import type { SbomDocumentDetail } from "@/features/sboms/sboms-types"
import { ApiError } from "@/lib/api-client"

interface UploadError {
  title: string
  detail: string
}

function uploadError(error: unknown): UploadError {
  if (error instanceof ApiError && error.status === 409) {
    return {
      title: "Duplicate SBOM",
      detail: "This SBOM has already been uploaded.",
    }
  }
  if (error instanceof ApiError && error.status === 400) {
    return {
      title: "Invalid SBOM",
      detail:
        error.detail ??
        "Select a valid CycloneDX JSON SBOM and try again.",
    }
  }
  return {
    title: "Upload failed",
    detail:
      error instanceof ApiError && error.detail
        ? error.detail
        : "The SBOM could not be uploaded. Try again.",
  }
}

export function SbomUploadDialog({
  open,
  onOpenChange,
  onUploaded,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onUploaded: (document: SbomDocumentDetail) => void
}) {
  const formRef = useRef<HTMLFormElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [manufacturer, setManufacturer] = useState("")
  const [productName, setProductName] = useState("")
  const [productVersion, setProductVersion] = useState("")
  const [isUploading, setIsUploading] = useState(false)
  const [error, setError] = useState<UploadError | null>(null)

  const resetForm = () => {
    formRef.current?.reset()
    setFile(null)
    setManufacturer("")
    setProductName("")
    setProductVersion("")
    setError(null)
  }

  const changeOpen = (nextOpen: boolean) => {
    if (isUploading) return
    if (!nextOpen) resetForm()
    onOpenChange(nextOpen)
  }

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (isUploading) return
    if (!file) {
      setError({
        title: "SBOM file required",
        detail: "Select a CycloneDX JSON SBOM file.",
      })
      return
    }

    setIsUploading(true)
    setError(null)
    try {
      const document = await uploadSbom({
        file,
        manufacturer,
        productName,
        productVersion,
      })
      resetForm()
      onOpenChange(false)
      onUploaded(document)
    } catch (reason: unknown) {
      setError(uploadError(reason))
    } finally {
      setIsUploading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogContent
        showCloseButton={!isUploading}
        aria-busy={isUploading}
        aria-describedby={undefined}
        onEscapeKeyDown={(event) => {
          if (isUploading) event.preventDefault()
        }}
        onPointerDownOutside={(event) => {
          if (isUploading) event.preventDefault()
        }}
      >
        <DialogHeader>
          <DialogTitle>Upload SBOM</DialogTitle>
        </DialogHeader>

        <form
          ref={formRef}
          className="space-y-4"
          noValidate
          onSubmit={(event) => void submit(event)}
        >
          <div>
            <label htmlFor="sbom-upload-file" className={formLabelTextClassName}>
              SBOM file <span aria-hidden="true">*</span>
              <span className="sr-only"> required</span>
            </label>
            <div className="sr-only">
              <Input
                ref={fileInputRef}
                id="sbom-upload-file"
                name="file"
                type="file"
                accept="application/json,.json"
                tabIndex={-1}
                aria-describedby="sbom-upload-file-status"
                aria-invalid={error?.title === "SBOM file required"}
                required
                disabled={isUploading}
                onChange={(event) => {
                  setFile(event.target.files?.[0] ?? null)
                  setError(null)
                }}
              />
            </div>
            <div className="mt-1 flex min-w-0 flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="outline"
                disabled={isUploading}
                aria-invalid={error?.title === "SBOM file required"}
                onClick={() => fileInputRef.current?.click()}
              >
                Select file
              </Button>
              <p
                id="sbom-upload-file-status"
                className="min-w-0 flex-1 truncate text-sm text-muted-foreground"
                title={file?.name}
                aria-live="polite"
              >
                {file?.name ?? "No file selected"}
              </p>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <label
                htmlFor="sbom-upload-manufacturer"
                className={formLabelTextClassName}
              >
                Manufacturer
              </label>
              <Input
                id="sbom-upload-manufacturer"
                name="manufacturer"
                value={manufacturer}
                maxLength={255}
                className="mt-1"
                disabled={isUploading}
                onChange={(event) => setManufacturer(event.target.value)}
              />
            </div>
            <div>
              <label
                htmlFor="sbom-upload-product-name"
                className={formLabelTextClassName}
              >
                Product name
              </label>
              <Input
                id="sbom-upload-product-name"
                name="product_name"
                value={productName}
                maxLength={255}
                className="mt-1"
                disabled={isUploading}
                onChange={(event) => setProductName(event.target.value)}
              />
            </div>
            <div>
              <label
                htmlFor="sbom-upload-product-version"
                className={formLabelTextClassName}
              >
                Product version
              </label>
              <Input
                id="sbom-upload-product-version"
                name="product_version"
                value={productVersion}
                maxLength={255}
                className="mt-1"
                disabled={isUploading}
                onChange={(event) => setProductVersion(event.target.value)}
              />
            </div>
          </div>

          {error ? (
            <Alert variant="destructive">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>{error.title}</AlertTitle>
              <AlertDescription>{error.detail}</AlertDescription>
            </Alert>
          ) : null}

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={isUploading}
              onClick={() => changeOpen(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isUploading}>
              {isUploading ? (
                <LoaderCircle className="animate-spin" aria-hidden="true" />
              ) : (
                <Upload aria-hidden="true" />
              )}
              {isUploading ? "Uploading…" : "Upload SBOM"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
