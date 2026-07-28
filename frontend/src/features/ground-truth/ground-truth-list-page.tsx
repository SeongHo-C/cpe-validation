import {
  ClipboardList,
  LoaderCircle,
  RotateCcw,
  Search,
  TriangleAlert,
} from "lucide-react"
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react"
import { Link, useSearchParams } from "react-router-dom"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { ComponentsPagination } from "@/features/components/components-pagination"
import type { DictionaryStatus } from "@/features/components/components-types"
import {
  dictionaryStatusClassName,
  dictionaryStatusLabels,
} from "@/features/components/dictionary-status"
import { getGroundTruthComponents } from "@/features/ground-truth/ground-truth-api"
import {
  DEFAULT_GROUND_TRUTH_QUERY,
  groundTruthDetailPath,
  parseGroundTruthListQuery,
  writeGroundTruthListQuery,
} from "@/features/ground-truth/ground-truth-query"
import type {
  GroundTruthComponentSummary,
  GroundTruthListQuery,
  GroundTruthOrdering,
  GroundTruthStatus,
} from "@/features/ground-truth/ground-truth-types"
import { getDockerImages } from "@/features/images/images-api"
import type { DockerImageSummary } from "@/features/images/images-types"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"
import { cn } from "@/lib/utils"

const selectClassName =
  "h-9 rounded-lg border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"

function groundTruthValue(
  component: GroundTruthComponentSummary,
): string {
  const groundTruth = component.ground_truth
  if (!groundTruth) return "미작성"
  if (groundTruth.source === "DICTIONARY") {
    return groundTruth.dictionary_cpe?.cpe_name ?? "CPE 없음"
  }
  if (groundTruth.source === "MANUAL") {
    return groundTruth.manual_cpe ?? "CPE 없음"
  }
  return "CPE 없음"
}

function requestError(error: unknown): string {
  if (error instanceof ApiError) {
    return error.detail ?? error.message
  }
  return "Ground Truth 검토 목록을 불러오지 못했습니다."
}

export function GroundTruthListPage() {
  const [searchParameters, setSearchParameters] =
    useSearchParams()
  const searchSignature = searchParameters.toString()
  const query = useMemo(
    () =>
      parseGroundTruthListQuery(
        new URLSearchParams(searchSignature),
      ),
    [searchSignature],
  )
  const [searchInput, setSearchInput] = useState(
    query.search ?? "",
  )
  const [components, setComponents] = useState<{
    count: number
    page: number
    page_size: number
    total_pages: number
    results: GroundTruthComponentSummary[]
  } | null>(null)
  const [images, setImages] = useState<DockerImageSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const setQuery = useCallback(
    (updates: Partial<GroundTruthListQuery>) => {
      const next = { ...query, ...updates }
      setLoading(true)
      setSearchParameters(writeGroundTruthListQuery(next))
    },
    [query, setSearchParameters],
  )

  useEffect(() => {
    setSearchInput(query.search ?? "")
  }, [query.search])

  useEffect(() => {
    const controller = new AbortController()
    getDockerImages(controller.signal)
      .then(setImages)
      .catch(() => setImages([]))
    return () => controller.abort()
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    getGroundTruthComponents(query, controller.signal)
      .then((response) => {
        setComponents(response)
        setLoading(false)
      })
      .catch((reason: unknown) => {
        if (isAbortError(reason)) return
        setError(requestError(reason))
        setLoading(false)
      })
    return () => controller.abort()
  }, [query])

  const submitSearch = (event: FormEvent) => {
    event.preventDefault()
    setQuery({
      search: searchInput.trim() || undefined,
      page: 1,
    })
  }

  const hasAppliedSearchState =
    query.image_id !== undefined ||
    query.ground_truth_status !== undefined ||
    query.dictionary_status !== undefined ||
    query.search !== undefined ||
    query.ordering !== DEFAULT_GROUND_TRUTH_QUERY.ordering ||
    query.page !== DEFAULT_GROUND_TRUTH_QUERY.page ||
    query.page_size !== DEFAULT_GROUND_TRUTH_QUERY.page_size
  const resetDisabled =
    loading || (!hasAppliedSearchState && searchInput === "")

  const resetSearch = () => {
    setSearchInput("")
    if (!hasAppliedSearchState) return
    setLoading(true)
    setSearchParameters(
      writeGroundTruthListQuery(DEFAULT_GROUND_TRUTH_QUERY),
    )
  }

  return (
    <div className="mx-auto min-w-0 max-w-[2200px] space-y-5">
      <header>
        <div className="flex items-center gap-2">
          <ClipboardList
            className="size-5 text-cyan-700"
            aria-hidden="true"
          />
          <h2 className="font-heading text-xl font-semibold tracking-tight">
            Ground Truth 검토 목록
          </h2>
        </div>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
          Primary CPE가 있는 Component를 대상으로 검색 알고리즘과
          독립적인 예상 정답을 구축합니다.
        </p>
      </header>

      <Card className="gap-0 py-0" aria-busy={loading}>
        <CardHeader className="border-b">
          <CardTitle>Review Components</CardTitle>
          <form
            className="mt-4 space-y-4"
            onSubmit={submitSearch}
          >
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
              <label className="min-w-0 flex-1 space-y-1 text-xs font-medium">
                <span className="block">Component Keyword</span>
                <Input
                  aria-label="Component Keyword"
                  value={searchInput}
                  placeholder="Search by name, version, publisher, PURL, or CPE"
                  onChange={(event) =>
                    setSearchInput(event.target.value)
                  }
                />
              </label>
              <Button
                type="submit"
                className="w-full sm:w-auto"
                disabled={loading}
              >
                <Search aria-hidden="true" />
                Search
              </Button>
            </div>

            <div className="flex flex-col gap-3 xl:flex-row xl:items-end xl:justify-between">
              <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:flex lg:flex-wrap">
                <label className="space-y-1 text-xs font-medium sm:w-full lg:w-[220px]">
                  <span className="block">Image</span>
                  <select
                    aria-label="Image"
                    className={`${selectClassName} w-full`}
                    value={query.image_id ?? ""}
                    onChange={(event) =>
                      setQuery({
                        image_id: event.target.value
                          ? Number(event.target.value)
                          : undefined,
                        page: 1,
                      })
                    }
                  >
                    <option value="">All Images</option>
                    {images.map((image) => (
                      <option key={image.id} value={image.id}>
                        {image.repository}:{image.tag}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="space-y-1 text-xs font-medium sm:w-full lg:w-[200px]">
                  <span className="block">Ground Truth Status</span>
                  <select
                    aria-label="Ground Truth Status"
                    className={`${selectClassName} w-full`}
                    value={query.ground_truth_status ?? ""}
                    onChange={(event) =>
                      setQuery({
                        ground_truth_status:
                          (event.target.value ||
                            undefined) as
                            | GroundTruthStatus
                            | undefined,
                        page: 1,
                      })
                    }
                  >
                    <option value="">All Statuses</option>
                    <option value="UNREVIEWED">Unreviewed</option>
                    <option value="COMPLETED">Completed</option>
                  </select>
                </label>
                <label className="space-y-1 text-xs font-medium sm:w-full lg:w-[210px]">
                  <span className="block">Exact Match</span>
                  <select
                    aria-label="Exact Match"
                    className={`${selectClassName} w-full`}
                    value={query.dictionary_status ?? ""}
                    onChange={(event) =>
                      setQuery({
                        dictionary_status:
                          (event.target.value ||
                            undefined) as
                            | DictionaryStatus
                            | undefined,
                        page: 1,
                      })
                    }
                  >
                    <option value="">
                      All Exact Match Results
                    </option>
                    <option value="OFFICIAL_ACTIVE">
                      Official active
                    </option>
                    <option value="OFFICIAL_DEPRECATED">
                      Official deprecated
                    </option>
                    <option value="NOT_IN_DICTIONARY">
                      Not in Dictionary
                    </option>
                  </select>
                </label>
              </div>

              <div className="flex flex-col gap-3 sm:flex-row sm:items-end xl:ml-auto xl:shrink-0">
                <label className="space-y-1 text-xs font-medium sm:w-[220px]">
                  <span className="block">Sort</span>
                  <select
                    aria-label="Sort"
                    className={`${selectClassName} w-full`}
                    value={query.ordering}
                    onChange={(event) =>
                      setQuery({
                        ordering: event.target
                          .value as GroundTruthOrdering,
                        page: 1,
                      })
                    }
                  >
                    <option value="id">
                      Component ID Ascending
                    </option>
                    <option value="-id">
                      Component ID Descending
                    </option>
                  </select>
                </label>
                <Button
                  type="button"
                  variant="outline"
                  className="w-full sm:w-auto"
                  disabled={resetDisabled}
                  onClick={resetSearch}
                >
                  <RotateCcw aria-hidden="true" />
                  Reset
                </Button>
              </div>
            </div>
          </form>
        </CardHeader>

        {error ? (
          <div className="p-4">
            <Alert variant="destructive">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>목록 조회 실패</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          </div>
        ) : null}

        {!components && loading ? (
          <CardContent className="flex min-h-64 items-center justify-center gap-2 text-sm text-muted-foreground">
            <LoaderCircle
              className="size-4 animate-spin"
              aria-hidden="true"
            />
            검토 목록을 불러오는 중…
          </CardContent>
        ) : null}

        {components ? (
          <div className="relative overflow-x-auto">
            {loading ? (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-background/60">
                <LoaderCircle
                  className="size-5 animate-spin"
                  aria-label="검토 목록 불러오는 중"
                />
              </div>
            ) : null}
            <Table className="min-w-[1180px]">
              <TableHeader>
                <TableRow>
                  <TableHead>Component</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Image</TableHead>
                  <TableHead>Original CPE</TableHead>
                  <TableHead>Exact Match</TableHead>
                  <TableHead>Ground Truth Status</TableHead>
                  <TableHead>Ground Truth</TableHead>
                  <TableHead>Decision Type</TableHead>
                  <TableHead>Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {components.results.map((component) => {
                  const value = groundTruthValue(component)
                  return (
                    <TableRow key={component.id}>
                      <TableCell className="font-medium">
                        {component.name}
                      </TableCell>
                      <TableCell>{component.version || "—"}</TableCell>
                      <TableCell>
                        {component.image.repository}:
                        {component.image.tag}
                      </TableCell>
                      <TableCell>
                        <p
                          className="max-w-64 truncate font-mono text-xs"
                          title={component.cpe}
                        >
                          {component.cpe}
                        </p>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={cn(
                            dictionaryStatusClassName(
                              component.dictionary_status,
                            ),
                          )}
                        >
                          {
                            dictionaryStatusLabels[
                              component.dictionary_status
                            ]
                          }
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            component.ground_truth_status ===
                            "COMPLETED"
                              ? "secondary"
                              : "outline"
                          }
                        >
                          {component.ground_truth_status ===
                          "COMPLETED"
                            ? "작성 완료"
                            : "미작성"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <p
                          className="max-w-72 truncate font-mono text-xs"
                          title={value}
                        >
                          {value}
                        </p>
                      </TableCell>
                      <TableCell>
                        {component.decision_type ?? "—"}
                      </TableCell>
                      <TableCell>
                        <Button asChild size="sm" variant="outline">
                          <Link
                            to={groundTruthDetailPath(
                              component.id,
                              new URLSearchParams(searchSignature),
                            )}
                          >
                            Ground Truth 작성
                          </Link>
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
            {components.results.length === 0 ? (
              <CardContent className="py-16 text-center text-sm text-muted-foreground">
                현재 필터와 일치하는 Component가 없습니다.
              </CardContent>
            ) : null}
          </div>
        ) : null}

        {components ? (
          <CardFooter className="flex-wrap justify-between gap-4">
            <label className="flex items-center gap-2 whitespace-nowrap text-sm">
              <span className="text-muted-foreground">
                Rows per page
              </span>
              <select
                aria-label="Rows per page"
                className={selectClassName}
                value={query.page_size}
                onChange={(event) =>
                  setQuery({
                    page_size: Number(event.target.value),
                    page: 1,
                  })
                }
              >
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="200">200</option>
              </select>
            </label>
            <ComponentsPagination
              page={components.page}
              totalPages={components.total_pages}
              disabled={loading}
              onPageChange={(page) => setQuery({ page })}
            />
          </CardFooter>
        ) : null}
      </Card>
    </div>
  )
}
