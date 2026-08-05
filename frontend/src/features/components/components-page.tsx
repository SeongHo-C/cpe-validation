import {
  Box,
  TriangleAlert,
} from "lucide-react"
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react"
import { useSearchParams } from "react-router-dom"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { DataPanelHeader } from "@/components/data-panel-header"
import { PageContent } from "@/components/page-content"
import { ComponentDetailPanel } from "@/features/components/component-detail-panel"
import {
  getComponents,
  getDockerImageDetail,
} from "@/features/components/components-api"
import { ComponentsPagination } from "@/features/components/components-pagination"
import {
  canonicalizeComponentsSearch,
  DEFAULT_COMPONENT_ORDERING,
  DEFAULT_COMPONENT_PAGE,
  DEFAULT_COMPONENT_PAGE_SIZE,
  parseComponentsUrlState,
  type ComponentOrdering,
  type ComponentPageSize,
} from "@/features/components/components-query"
import {
  ComponentsTable,
  ComponentsTableSkeleton,
} from "@/features/components/components-table"
import { ComponentsToolbar } from "@/features/components/components-toolbar"
import type {
  ComponentSummary,
  DictionaryStatus,
  DockerImageDetail,
  PaginatedResponse,
} from "@/features/components/components-types"
import {
  ImageScopeSummary,
  type ImageDetailError,
} from "@/features/components/image-scope-summary"
import { SbomScopeSummary } from "@/features/components/sbom-scope-summary"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"

interface QueryUpdates {
  imageId?: number | null
  sbomId?: number | null
  componentId?: number | null
  search?: string
  ordering?: ComponentOrdering
  page?: number
  pageSize?: ComponentPageSize
  dictionaryStatus?: DictionaryStatus | null
}

function EmptyComponents({
  hasSearch,
  hasImageFilter,
  hasSbomFilter,
  hasDictionaryFilter,
  onClearSearch,
}: {
  hasSearch: boolean
  hasImageFilter: boolean
  hasSbomFilter: boolean
  hasDictionaryFilter: boolean
  onClearSearch: () => void
}) {
  let description =
    "No components with a primary CPE were found in this scope."
  if (hasSearch) {
    description =
      "Try another component name, version, publisher, PURL, or CPE."
  } else if (hasDictionaryFilter) {
    description =
      "No components match the selected Dictionary status."
  } else if (hasImageFilter) {
    description =
      "This image does not contain components with a primary CPE."
  } else if (hasSbomFilter) {
    description =
      "This SBOM does not contain components with a primary CPE."
  }

  return (
    <CardContent className="flex min-h-64 flex-col items-center justify-center px-6 text-center">
      <div className="flex size-11 items-center justify-center rounded-xl bg-muted text-muted-foreground">
        <Box className="size-5" aria-hidden="true" />
      </div>
      <h2 className="mt-4 font-heading text-base font-semibold">
        {hasSearch
          ? "No matching components"
          : hasDictionaryFilter
            ? "No components with this Dictionary status"
            : "No primary CPE components available"}
      </h2>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">
        {description}
      </p>
      {hasSearch ? (
        <Button
          type="button"
          variant="outline"
          className="mt-4"
          onClick={onClearSearch}
        >
          Clear search
        </Button>
      ) : null}
    </CardContent>
  )
}

export function ComponentsPage() {
  const [searchParameters, setSearchParameters] =
    useSearchParams()
  const searchSignature = searchParameters.toString()
  const urlState = useMemo(
    () =>
      parseComponentsUrlState(
        new URLSearchParams(searchSignature),
      ),
    [searchSignature],
  )
  const {
    imageId,
    invalidImageId,
    sbomId,
    invalidSbomId,
    conflictingScopeFilters,
    componentId,
    invalidComponentId,
    search,
    ordering,
    page,
    pageSize,
    dictionaryStatus,
  } = urlState

  const [searchInput, setSearchInput] = useState(search)
  const [components, setComponents] =
    useState<PaginatedResponse<ComponentSummary> | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [componentsError, setComponentsError] = useState(false)
  const [componentsReloadToken, setComponentsReloadToken] =
    useState(0)
  const [image, setImage] = useState<DockerImageDetail | null>(
    null,
  )
  const [isImageLoading, setIsImageLoading] = useState(false)
  const [imageError, setImageError] =
    useState<ImageDetailError>(null)

  const updateQuery = useCallback(
    (updates: QueryUpdates) => {
      const next = new URLSearchParams(searchSignature)

      if ("imageId" in updates) {
        if (updates.imageId === null) {
          next.delete("image_id")
        } else if (updates.imageId !== undefined) {
          next.set("image_id", String(updates.imageId))
        }
      }
      if ("sbomId" in updates) {
        if (updates.sbomId === null) {
          next.delete("sbom_id")
        } else if (updates.sbomId !== undefined) {
          next.set("sbom_id", String(updates.sbomId))
        }
      }
      if ("componentId" in updates) {
        if (updates.componentId === null) {
          next.delete("component_id")
        } else if (updates.componentId !== undefined) {
          next.set(
            "component_id",
            String(updates.componentId),
          )
        }
      }
      if (updates.search !== undefined) {
        const normalizedSearch = updates.search.trim()
        if (normalizedSearch) {
          next.set("search", normalizedSearch)
        } else {
          next.delete("search")
        }
      }
      if (updates.ordering !== undefined) {
        if (updates.ordering === DEFAULT_COMPONENT_ORDERING) {
          next.delete("ordering")
        } else {
          next.set("ordering", updates.ordering)
        }
      }
      if (updates.page !== undefined) {
        if (updates.page === DEFAULT_COMPONENT_PAGE) {
          next.delete("page")
        } else {
          next.set("page", String(updates.page))
        }
      }
      if (updates.pageSize !== undefined) {
        if (
          updates.pageSize === DEFAULT_COMPONENT_PAGE_SIZE
        ) {
          next.delete("page_size")
        } else {
          next.set("page_size", String(updates.pageSize))
        }
      }
      if ("dictionaryStatus" in updates) {
        if (updates.dictionaryStatus == null) {
          next.delete("dictionary_status")
        } else {
          next.set(
            "dictionary_status",
            updates.dictionaryStatus,
          )
        }
      }

      setSearchParameters(next)
    },
    [searchSignature, setSearchParameters],
  )

  const updateListQuery = useCallback(
    (updates: QueryUpdates) =>
      updateQuery({
        ...updates,
        componentId: null,
      }),
    [updateQuery],
  )

  useEffect(() => {
    const current = new URLSearchParams(searchSignature)
    const canonical = canonicalizeComponentsSearch(current)
    if (canonical.toString() !== current.toString()) {
      setSearchParameters(canonical, { replace: true })
    }
  }, [searchSignature, setSearchParameters])

  useEffect(() => {
    setSearchInput(search)
  }, [search])

  useEffect(() => {
    const normalizedSearch = searchInput.trim()
    if (normalizedSearch === search) return

    const timeout = window.setTimeout(() => {
      updateListQuery({
        search: normalizedSearch,
        page: DEFAULT_COMPONENT_PAGE,
      })
    }, 300)

    return () => window.clearTimeout(timeout)
  }, [search, searchInput, updateListQuery])

  useEffect(() => {
    if (
      invalidImageId ||
      invalidSbomId ||
      conflictingScopeFilters
    ) {
      setComponents(null)
      setComponentsError(false)
      setIsLoading(false)
      return
    }

    const controller = new AbortController()
    let active = true

    setIsLoading(true)
    setComponentsError(false)
    getComponents(
      {
        image_id: imageId,
        sbom_id: sbomId,
        search,
        ordering,
        page,
        page_size: pageSize,
        dictionary_status: dictionaryStatus,
      },
      controller.signal,
    )
      .then((response) => {
        if (!active) return
        setComponents(response)
        setIsLoading(false)
      })
      .catch((error: unknown) => {
        if (!active || isAbortError(error)) return
        setComponentsError(true)
        setIsLoading(false)
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [
    componentsReloadToken,
    imageId,
    invalidImageId,
    sbomId,
    invalidSbomId,
    conflictingScopeFilters,
    ordering,
    page,
    pageSize,
    search,
    dictionaryStatus,
  ])

  useEffect(() => {
    if (
      invalidImageId ||
      invalidSbomId ||
      conflictingScopeFilters ||
      imageId === undefined
    ) {
      setImage(null)
      setImageError(null)
      setIsImageLoading(false)
      return
    }

    const controller = new AbortController()
    let active = true

    setImage(null)
    setImageError(null)
    setIsImageLoading(true)
    getDockerImageDetail(imageId, controller.signal)
      .then((response) => {
        if (!active) return
        setImage(response)
        setIsImageLoading(false)
      })
      .catch((error: unknown) => {
        if (!active || isAbortError(error)) return
        setImageError(
          error instanceof ApiError && error.status === 404
            ? "not-found"
            : "unavailable",
        )
        setIsImageLoading(false)
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [
    imageId,
    invalidImageId,
    invalidSbomId,
    conflictingScopeFilters,
  ])

  const clearSearch = () => {
    setSearchInput("")
    updateListQuery({
      search: "",
      page: DEFAULT_COMPONENT_PAGE,
    })
  }

  const clearImageFilter = () => {
    updateListQuery({
      imageId: null,
      page: DEFAULT_COMPONENT_PAGE,
    })
  }

  const clearSbomFilter = () => {
    updateListQuery({
      sbomId: null,
      page: DEFAULT_COMPONENT_PAGE,
    })
  }

  const clearScopeFilters = () => {
    updateListQuery({
      imageId: null,
      sbomId: null,
      page: DEFAULT_COMPONENT_PAGE,
    })
  }

  if (
    invalidImageId ||
    invalidSbomId ||
    conflictingScopeFilters
  ) {
    const title = conflictingScopeFilters
      ? "Conflicting component filters"
      : invalidSbomId
        ? "Invalid SBOM filter"
        : "Invalid image filter"
    const description = conflictingScopeFilters
      ? "Select either an SBOM or Docker image scope, not both."
      : invalidSbomId
        ? "The SBOM identifier in the URL is not valid."
        : "The image identifier in the URL is not valid."
    return (
      <PageContent>
        <Alert variant="destructive" className="p-4">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>{title}</AlertTitle>
          <AlertDescription>{description}</AlertDescription>
          <div className="col-start-2 mt-3">
            <Button
              type="button"
              variant="outline"
              onClick={clearScopeFilters}
            >
              View all components
            </Button>
          </div>
        </Alert>
      </PageContent>
    )
  }

  const isInitialLoading = isLoading && components === null
  const resultCount = components?.count
  const selectedSbom =
    sbomId === undefined
      ? null
      : (components?.results.find(
          (component) => component.sbom.id === sbomId,
        )?.sbom ?? null)

  return (
    <PageContent aria-busy={isLoading}>
      <div className="flex items-start gap-5">
        <section
          aria-label="Primary CPE Component list"
          className="min-w-0 flex-1 space-y-5"
        >
          {sbomId !== undefined ? (
            <SbomScopeSummary
              sbomId={sbomId}
              sbom={selectedSbom}
              componentCount={resultCount}
              onClearSbomFilter={clearSbomFilter}
            />
          ) : (
            <ImageScopeSummary
              imageId={imageId}
              image={image}
              isLoading={isImageLoading}
              error={imageError}
              componentCount={resultCount}
              dictionaryStatus={dictionaryStatus}
              onClearImageFilter={clearImageFilter}
            />
          )}

          <Card
            id="components-table"
            className="gap-0 py-0"
          >
            <DataPanelHeader
              title="Validation Queue"
              description="Search and filter components selected for Primary CPE validation."
            />
            <ComponentsToolbar
              searchInput={searchInput}
              ordering={ordering}
              pageSize={pageSize}
              dictionaryStatus={dictionaryStatus}
              resultCount={resultCount}
              isBusy={isLoading}
              onSearchInputChange={setSearchInput}
              onOrderingChange={(nextOrdering) =>
                updateListQuery({
                  ordering: nextOrdering,
                  page: DEFAULT_COMPONENT_PAGE,
                })
              }
              onPageSizeChange={(nextPageSize) =>
                updateListQuery({
                  pageSize: nextPageSize,
                  page: DEFAULT_COMPONENT_PAGE,
                })
              }
              onDictionaryStatusChange={(nextStatus) =>
                updateListQuery({
                  dictionaryStatus: nextStatus ?? null,
                  page: DEFAULT_COMPONENT_PAGE,
                })
              }
            />

            {isInitialLoading ? (
              <ComponentsTableSkeleton />
            ) : null}

            {!isInitialLoading && componentsError ? (
              <div className="p-4">
                <Alert variant="destructive" className="p-4">
                  <TriangleAlert aria-hidden="true" />
                  <AlertTitle>
                    Unable to load components
                  </AlertTitle>
                  <AlertDescription>
                    The frontend could not retrieve the CPE
                    validation queue.
                  </AlertDescription>
                  <div className="col-start-2 mt-3">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() =>
                        setComponentsReloadToken(
                          (current) => current + 1,
                        )
                      }
                    >
                      Retry
                    </Button>
                  </div>
                </Alert>
              </div>
            ) : null}

            {!isInitialLoading &&
            !componentsError &&
            components?.count === 0 ? (
              <EmptyComponents
                hasSearch={Boolean(search)}
                hasImageFilter={imageId !== undefined}
                hasSbomFilter={sbomId !== undefined}
                hasDictionaryFilter={
                  dictionaryStatus !== undefined
                }
                onClearSearch={clearSearch}
              />
            ) : null}

            {!componentsError &&
            components &&
            components.count > 0 ? (
              <>
                <ComponentsTable
                  components={components.results}
                  ordering={ordering}
                  page={components.page}
                  pageSize={components.page_size}
                  totalPages={components.total_pages}
                  isRefreshing={isLoading}
                  selectedComponentId={componentId}
                  onOrderingChange={(nextOrdering) =>
                    updateListQuery({
                      ordering: nextOrdering,
                      page: DEFAULT_COMPONENT_PAGE,
                    })
                  }
                  onSelectComponent={(nextComponentId) =>
                    updateQuery({
                      componentId: nextComponentId,
                    })
                  }
                />
                <ComponentsPagination
                  page={components.page}
                  totalPages={components.total_pages}
                  disabled={isLoading}
                  onPageChange={(nextPage) =>
                    updateListQuery({ page: nextPage })
                  }
                />
              </>
            ) : null}
          </Card>
        </section>

        <ComponentDetailPanel
          componentId={componentId}
          invalidComponentId={invalidComponentId}
          onClose={() => updateQuery({ componentId: null })}
        />
      </div>
    </PageContent>
  )
}
