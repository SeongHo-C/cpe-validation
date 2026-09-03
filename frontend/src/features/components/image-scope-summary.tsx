import {
  FilterX,
  Layers3,
  TriangleAlert,
} from "lucide-react"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type {
  DictionaryStatus,
  DockerImageDetail,
} from "@/features/components/components-types"
import { formatInteger, formatPercent } from "@/lib/format"

export type ImageDetailError = "not-found" | "unavailable" | null

interface ImageScopeSummaryProps {
  imageId?: number
  image?: DockerImageDetail | null
  isLoading: boolean
  error: ImageDetailError
  componentCount?: number
  dictionaryStatus?: DictionaryStatus
  onClearImageFilter: () => void
}

function repositoryBasename(repository: string): string {
  return repository.split("/").at(-1) ?? repository
}

function ScopeStats({
  stats,
}: {
  stats: Array<{ label: string; value: string }>
}) {
  return (
    <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {stats.map((stat) => (
        <div
          key={stat.label}
          className="rounded-lg border bg-muted/30 px-3 py-2.5"
        >
          <dt className="text-xs text-muted-foreground">
            {stat.label}
          </dt>
          <dd className="mt-1 font-heading text-base font-semibold">
            {stat.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function ImageScopeSummary({
  imageId,
  image,
  isLoading,
  error,
  componentCount,
  dictionaryStatus,
  onClearImageFilter,
}: ImageScopeSummaryProps) {
  if (imageId === undefined) {
    const showsMissingCpes = dictionaryStatus === "NOT_PRESENT"
    const hasDictionaryFilter =
      dictionaryStatus !== undefined
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Layers3
              className="size-4 text-cyan-700"
              aria-hidden="true"
            />
            All Docker Images
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            {showsMissingCpes
              ? "Showing components without a Primary CPE across all images."
              : hasDictionaryFilter
                ? "Showing Primary CPE Components with the selected Dictionary status across all images."
                : "Showing components with a primary CPE across all images."}
          </p>
        </CardHeader>
        <CardContent>
          <ScopeStats
            stats={[
              {
                label: showsMissingCpes
                  ? "Components without Primary CPE"
                  : hasDictionaryFilter
                    ? "Matching Components"
                    : "Primary CPE Components",
                value:
                  componentCount === undefined
                    ? "Loading"
                    : formatInteger(componentCount),
              },
              { label: "Image Scope", value: "All images" },
              {
                label: "Structural scope",
                value: "component.cpe only",
              },
            ]}
          />
        </CardContent>
      </Card>
    )
  }

  if (isLoading && !image) {
    return (
      <Card aria-label="Loading selected image scope">
        <CardHeader>
          <Skeleton className="h-5 w-44" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {Array.from({ length: 4 }, (_, index) => (
              <Skeleton key={index} className="h-16 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="space-y-4">
          <Alert variant={error === "not-found" ? "destructive" : "default"}>
            <TriangleAlert aria-hidden="true" />
            <AlertTitle>
              {error === "not-found"
                ? "Docker image not found"
                : "Unable to load image details"}
            </AlertTitle>
            <AlertDescription>
              {error === "not-found"
                ? "The selected image is not available in the current dataset."
                : "The component list remains available, but the selected image summary could not be retrieved."}
            </AlertDescription>
          </Alert>
          <Button
            type="button"
            variant="outline"
            onClick={onClearImageFilter}
          >
            <FilterX aria-hidden="true" />
            Clear image filter
          </Button>
        </CardContent>
      </Card>
    )
  }

  if (!image) return null

  return (
    <Card>
      <CardHeader className="sm:grid-cols-[1fr_auto]">
        <div>
          <CardTitle>
            {repositoryBasename(image.repository)}:{image.tag}
          </CardTitle>
          <p className="mt-1 text-sm text-muted-foreground">
            {image.repository}
          </p>
          <p className="mt-0.5 font-mono text-xs text-muted-foreground">
            {image.platform}
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="mt-3 sm:mt-0"
          onClick={onClearImageFilter}
        >
          <FilterX aria-hidden="true" />
          Clear image filter
        </Button>
      </CardHeader>
      <CardContent>
        <ScopeStats
          stats={[
            {
              label: "Total Components",
              value: formatInteger(image.total_components),
            },
            {
              label: "Primary CPE",
              value: formatInteger(
                image.components_with_primary_cpe,
              ),
            },
            {
              label: "Unique CPE",
              value: formatInteger(image.unique_primary_cpes),
            },
            {
              label: "CPE Coverage",
              value: formatPercent(image.primary_cpe_ratio),
            },
          ]}
        />
      </CardContent>
    </Card>
  )
}
