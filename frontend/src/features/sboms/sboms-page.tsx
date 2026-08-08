import {
  FileText,
  LoaderCircle,
  TriangleAlert,
  Upload as UploadIcon,
} from "lucide-react"
import { useEffect, useState } from "react"
import {
  useNavigate,
  useOutletContext,
} from "react-router-dom"

import type { AppShellOutletContext } from "@/components/app-shell"
import { DataPanelHeader } from "@/components/data-panel-header"
import { selectControlClassName } from "@/components/form-control-styles"
import { PagePagination } from "@/components/page-pagination"
import { PageContent } from "@/components/page-content"
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import {
  DEFAULT_SBOM_PAGE,
  DEFAULT_SBOM_PAGE_SIZE,
  getSboms,
} from "@/features/sboms/sboms-query"
import { SbomDeleteDialog } from "@/features/sboms/sbom-delete-dialog"
import { SbomUploadDialog } from "@/features/sboms/sbom-upload-dialog"
import {
  SbomsTable,
  SbomsTableSkeleton,
} from "@/features/sboms/sboms-table"
import {
  sbomPageSizes,
  type SbomDocumentSummary,
  type SbomPage,
  type SbomPageSize,
} from "@/features/sboms/sboms-types"
import { isAbortError } from "@/lib/api-client"
import { formatInteger } from "@/lib/format"

function EmptyState() {
  return (
    <CardContent className="flex min-h-64 flex-col items-center justify-center px-6 text-center">
      <div className="flex size-11 items-center justify-center rounded-xl bg-muted text-muted-foreground">
        <FileText className="size-5" aria-hidden="true" />
      </div>
      <h2 className="mt-4 font-heading text-base font-semibold">
        No SBOMs available
      </h2>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">
        Uploaded SBOM documents will appear here.
      </p>
    </CardContent>
  )
}

export function SbomsPage() {
  const navigate = useNavigate()
  const { setSbomCount } =
    useOutletContext<AppShellOutletContext>()
  const [page, setPage] = useState(DEFAULT_SBOM_PAGE)
  const [pageSize, setPageSize] = useState<SbomPageSize>(
    DEFAULT_SBOM_PAGE_SIZE,
  )
  const [response, setResponse] = useState<SbomPage | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [hasError, setHasError] = useState(false)
  const [reloadToken, setReloadToken] = useState(0)
  const [isUploadDialogOpen, setIsUploadDialogOpen] = useState(false)
  const [sbomToDelete, setSbomToDelete] =
    useState<SbomDocumentSummary | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    let active = true

    setIsLoading(true)
    setHasError(false)
    getSboms(
      { page, page_size: pageSize },
      controller.signal,
    )
      .then((nextResponse) => {
        if (!active) return
        setResponse(nextResponse)
        setSbomCount(nextResponse.count)
        setIsLoading(false)
      })
      .catch((error: unknown) => {
        if (!active || isAbortError(error)) return
        setHasError(true)
        setSbomCount(undefined)
        setIsLoading(false)
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [page, pageSize, reloadToken, setSbomCount])

  const isInitialLoading = isLoading && response === null

  return (
    <PageContent id="sboms" aria-busy={isLoading}>
      <Card className="gap-0 py-0">
        <DataPanelHeader title="SBOM Inventory">
          <Button
            type="button"
            onClick={() => setIsUploadDialogOpen(true)}
          >
            <UploadIcon aria-hidden="true" />
            Upload SBOM
          </Button>
        </DataPanelHeader>

        {isInitialLoading ? <SbomsTableSkeleton /> : null}

        {!isInitialLoading && hasError ? (
          <div className="p-4">
            <Alert variant="destructive" className="p-4">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>Unable to load SBOMs</AlertTitle>
              <AlertDescription>
                The frontend could not retrieve the SBOM inventory.
              </AlertDescription>
              <div className="col-start-2 mt-3">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() =>
                    setReloadToken((current) => current + 1)
                  }
                >
                  Retry
                </Button>
              </div>
            </Alert>
          </div>
        ) : null}

        {!isInitialLoading && !hasError && response?.count === 0 ? (
          <EmptyState />
        ) : null}

        {!hasError && response && response.count > 0 ? (
          <>
            <div className="flex flex-col gap-2 border-b px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <label
                  htmlFor="sbom-page-size"
                  className="text-xs font-medium whitespace-nowrap text-foreground"
                >
                  Per page
                </label>
                <select
                  id="sbom-page-size"
                  aria-label="SBOMs per page"
                  value={pageSize}
                  onChange={(event) => {
                    setPageSize(
                      Number(event.target.value) as SbomPageSize,
                    )
                    setPage(DEFAULT_SBOM_PAGE)
                  }}
                  className={selectControlClassName}
                >
                  {sbomPageSizes.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </div>
              <p
                className="flex min-h-8 items-center gap-2 text-sm text-muted-foreground"
                aria-live="polite"
              >
                {isLoading ? (
                  <LoaderCircle
                    className="size-4 animate-spin"
                    aria-hidden="true"
                  />
                ) : null}
                {formatInteger(response.count)}{" "}
                {response.count === 1 ? "SBOM" : "SBOMs"}
              </p>
            </div>
            <SbomsTable
              sboms={response.results}
              isRefreshing={isLoading}
              onSelectSbom={(sbomId) =>
                navigate(`/components?sbom_id=${sbomId}`)
              }
              onDeleteSbom={setSbomToDelete}
            />
            <PagePagination
              page={response.page}
              totalPages={response.total_pages}
              disabled={isLoading}
              onPageChange={setPage}
            />
          </>
        ) : null}
      </Card>
      <SbomUploadDialog
        open={isUploadDialogOpen}
        onOpenChange={setIsUploadDialogOpen}
        onUploaded={() => {
          setPage(DEFAULT_SBOM_PAGE)
          setReloadToken((current) => current + 1)
        }}
      />
      <SbomDeleteDialog
        sbom={sbomToDelete}
        onOpenChange={(open) => {
          if (!open) setSbomToDelete(null)
        }}
        onDeleted={() => {
          setPage(DEFAULT_SBOM_PAGE)
          setReloadToken((current) => current + 1)
        }}
      />
    </PageContent>
  )
}
