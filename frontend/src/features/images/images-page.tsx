import {
  Box,
  Search,
  TriangleAlert,
} from "lucide-react"
import {
  useEffect,
  useMemo,
  useState,
} from "react"
import { useNavigate } from "react-router-dom"

import { DataPanelHeader } from "@/components/data-panel-header"
import { PageContent } from "@/components/page-content"
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import {
  getDockerImages,
} from "@/features/images/images-api"
import {
  ImagesSummary,
  ImagesSummarySkeleton,
} from "@/features/images/images-summary"
import {
  ImagesTable,
  ImagesTableSkeleton,
} from "@/features/images/images-table"
import type { DockerImageSummary } from "@/features/images/images-types"
import { isAbortError } from "@/lib/api-client"

function repositoryBasename(repository: string): string {
  return repository.split("/").at(-1) ?? repository
}

function EmptyState({
  title,
  description,
  onClear,
}: {
  title: string
  description: string
  onClear?: () => void
}) {
  return (
    <Card>
      <CardContent className="flex min-h-64 flex-col items-center justify-center px-6 text-center">
        <div className="flex size-11 items-center justify-center rounded-xl bg-muted text-muted-foreground">
          <Box className="size-5" aria-hidden="true" />
        </div>
        <h2 className="mt-4 font-heading text-base font-semibold">
          {title}
        </h2>
        <p className="mt-1 max-w-md text-sm text-muted-foreground">
          {description}
        </p>
        {onClear ? (
          <Button
            type="button"
            variant="outline"
            className="mt-4"
            onClick={onClear}
          >
            Clear search
          </Button>
        ) : null}
      </CardContent>
    </Card>
  )
}

function LoadingContent() {
  return (
    <div className="space-y-5">
      <ImagesSummarySkeleton />
      <Card className="gap-0 py-0">
        <DataPanelHeader
          title="Image Inventory"
          description="Docker Official Images with imported SBOM and Primary CPE coverage."
        />
        <div className="flex items-center justify-between gap-4 border-b p-4">
          <div className="relative w-full max-w-sm">
            <Skeleton className="h-9 w-full" />
          </div>
          <Skeleton className="h-4 w-24" />
        </div>
        <ImagesTableSkeleton />
      </Card>
    </div>
  )
}

export function ImagesPage() {
  const navigate = useNavigate()
  const [images, setImages] = useState<DockerImageSummary[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [hasError, setHasError] = useState(false)
  const [reloadToken, setReloadToken] = useState(0)
  const [search, setSearch] = useState("")

  useEffect(() => {
    const controller = new AbortController()
    let active = true

    setIsLoading(true)
    setHasError(false)
    getDockerImages(controller.signal)
      .then((responseImages) => {
        if (!active) return
        setImages(responseImages)
        setIsLoading(false)
      })
      .catch((error: unknown) => {
        if (!active || isAbortError(error)) return
        setHasError(true)
        setIsLoading(false)
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [reloadToken])

  const normalizedSearch = search.trim().toLowerCase()
  const filteredImages = useMemo(() => {
    if (!normalizedSearch) return images
    return images.filter((image) =>
      [
        image.repository,
        repositoryBasename(image.repository),
        image.tag,
        image.platform,
      ].some((value) =>
        value.toLowerCase().includes(normalizedSearch),
      ),
    )
  }, [images, normalizedSearch])

  return (
    <PageContent id="images">
      {isLoading ? <LoadingContent /> : null}

      {!isLoading && hasError ? (
        <Alert variant="destructive" className="p-4">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>Unable to load Docker images</AlertTitle>
          <AlertDescription>
            The frontend could not reach the SBOM API.
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
      ) : null}

      {!isLoading && !hasError && images.length === 0 ? (
        <EmptyState
          title="No Docker images available"
          description="Import SBOM data before using the validation workbench."
        />
      ) : null}

      {!isLoading && !hasError && images.length > 0 ? (
        <div className="space-y-5">
          <ImagesSummary images={images} />

          <Card className="gap-0 py-0">
            <DataPanelHeader
              title="Image Inventory"
              description="Docker Official Images with imported SBOM and Primary CPE coverage."
            />
            <div className="flex flex-col gap-3 border-b p-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="relative w-full max-w-md">
                <label
                  htmlFor="image-search"
                  className="sr-only"
                >
                  Search Docker images
                </label>
                <Search
                  className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
                  aria-hidden="true"
                />
                <Input
                  id="image-search"
                  value={search}
                  onChange={(event) =>
                    setSearch(event.target.value)
                  }
                  placeholder="Search repository, tag, or platform..."
                  className="pl-9"
                />
              </div>
              <p
                className="shrink-0 text-sm text-muted-foreground"
                aria-live="polite"
              >
                {filteredImages.length} of {images.length} images
              </p>
            </div>

            {filteredImages.length > 0 ? (
              <ImagesTable
                images={filteredImages}
                onSelectImage={(imageId) =>
                  navigate(`/components?image_id=${imageId}`)
                }
              />
            ) : (
              <div className="p-4">
                <EmptyState
                  title="No matching images"
                  description="Try another repository, tag, or platform."
                  onClear={() => setSearch("")}
                />
              </div>
            )}
          </Card>
        </div>
      ) : null}
    </PageContent>
  )
}
