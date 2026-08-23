import {
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
  formLabelClassName,
  selectControlClassName,
} from "@/components/form-control-styles"
import { PageContent } from "@/components/page-content"
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { ComponentsPagination } from "@/features/components/components-pagination"
import type { DictionaryStatus } from "@/features/components/components-types"
import {
  dictionaryStatuses,
  dictionaryStatusLabels,
} from "@/features/components/dictionary-status"
import {
  getGroundTruthComponents,
  getGroundTruthDiscrepancyTypes,
} from "@/features/ground-truth/ground-truth-api"
import {
  groundTruthDecisionCodes,
  groundTruthDecisionNames,
} from "@/features/ground-truth/ground-truth-decision"
import {
  DEFAULT_GROUND_TRUTH_QUERY,
  groundTruthDetailPath,
  parseGroundTruthListQuery,
  writeGroundTruthListQuery,
} from "@/features/ground-truth/ground-truth-query"
import type {
  GroundTruthComponentSummary,
  GroundTruthDecisionCode,
  GroundTruthDiscrepancyType,
  GroundTruthListQuery,
  GroundTruthOrdering,
  GroundTruthStatus,
} from "@/features/ground-truth/ground-truth-types"
import { getSboms } from "@/features/sboms/sboms-query"
import type { SbomDocumentSummary } from "@/features/sboms/sboms-types"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"

function groundTruthValue(
  component: GroundTruthComponentSummary,
): string {
  const groundTruth = component.ground_truth
  if (!groundTruth) return "Not Assigned"
  if (groundTruth.source === "DICTIONARY") {
    return (
      groundTruth.dictionary_cpe?.cpe_name ??
      "No direct official CPE"
    )
  }
  if (groundTruth.source === "MANUAL") {
    return groundTruth.manual_cpe ?? "No direct official CPE"
  }
  return "No direct official CPE"
}

function requestError(error: unknown): string {
  if (error instanceof ApiError) {
    return error.detail ?? error.message
  }
  return "Unable to load Ground Truth review components."
}

function sbomOptionLabel(sbom: SbomDocumentSummary): string {
  const productIdentity = [
    sbom.manufacturer,
    sbom.product_name,
    sbom.product_version,
  ]
    .filter(Boolean)
    .join(" ")
  return (
    productIdentity ||
    sbom.original_filename ||
    "Untitled SBOM"
  )
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
  const [sboms, setSboms] = useState<SbomDocumentSummary[]>([])
  const [discrepancyTypes, setDiscrepancyTypes] = useState<
    GroundTruthDiscrepancyType[]
  >([])
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
    getSboms(
      { page: 1, page_size: 200 },
      controller.signal,
    )
      .then((response) => setSboms(response.results))
      .catch(() => setSboms([]))
    return () => controller.abort()
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    getGroundTruthDiscrepancyTypes({}, controller.signal)
      .then(setDiscrepancyTypes)
      .catch(() => setDiscrepancyTypes([]))
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
    query.sbom_id !== undefined ||
    query.ground_truth_status !== undefined ||
    query.dictionary_status !== undefined ||
    query.decision !== undefined ||
    query.discrepancy_type !== undefined ||
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
    <PageContent>
      <Card className="gap-0 py-0" aria-busy={loading}>
        <CardHeader className="border-b p-4">
          <form
            className="space-y-4"
            onSubmit={submitSearch}
          >
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
              <label
                className={`${formLabelClassName} min-w-0 flex-1`}
              >
                <span className="block">Component Keyword</span>
                <Input
                  aria-label="Component Keyword"
                  value={searchInput}
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

            <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
              <label className={formLabelClassName}>
                <span className="block">SBOM</span>
                <select
                  aria-label="SBOM"
                  className={`${selectControlClassName} w-full`}
                  value={query.sbom_id ?? ""}
                  onChange={(event) =>
                    setQuery({
                      image_id: undefined,
                      sbom_id: event.target.value
                        ? Number(event.target.value)
                        : undefined,
                      page: 1,
                    })
                  }
                >
                  <option value="">All SBOMs</option>
                  {sboms.map((sbom) => (
                    <option key={sbom.id} value={sbom.id}>
                      {sbomOptionLabel(sbom)}
                    </option>
                  ))}
                </select>
              </label>
              <label className={formLabelClassName}>
                <span className="block">Ground Truth Status</span>
                <select
                  aria-label="Ground Truth Status"
                  className={`${selectControlClassName} w-full`}
                  value={query.ground_truth_status ?? ""}
                  onChange={(event) =>
                    setQuery({
                      ground_truth_status:
                        (event.target.value || undefined) as
                          | GroundTruthStatus
                          | undefined,
                      page: 1,
                    })
                  }
                >
                  <option value="">All Statuses</option>
                  <option value="UNREVIEWED">Not Reviewed</option>
                  <option value="COMPLETED">Completed</option>
                </select>
              </label>
              <label className={formLabelClassName}>
                <span className="block">Dictionary Status</span>
                <select
                  aria-label="Dictionary Status"
                  className={`${selectControlClassName} w-full`}
                  value={query.dictionary_status ?? ""}
                  onChange={(event) =>
                    setQuery({
                      dictionary_status:
                        (event.target.value || undefined) as
                          | DictionaryStatus
                          | undefined,
                      page: 1,
                    })
                  }
                >
                  <option value="">All Dictionary Statuses</option>
                  {dictionaryStatuses.map((status) => (
                    <option key={status} value={status}>
                      {dictionaryStatusLabels[status]}
                    </option>
                  ))}
                </select>
              </label>
              <label className={formLabelClassName}>
                <span className="block">CPE Validation Result</span>
                <select
                  aria-label="CPE Validation Result"
                  className={`${selectControlClassName} w-full`}
                  value={query.decision ?? ""}
                  onChange={(event) =>
                    setQuery({
                      decision:
                        (event.target.value || undefined) as
                          | GroundTruthDecisionCode
                          | undefined,
                      page: 1,
                    })
                  }
                >
                  <option value="">All Decisions</option>
                  {groundTruthDecisionCodes.map((code) => (
                    <option key={code} value={code}>
                      {groundTruthDecisionNames[code]}
                    </option>
                  ))}
                </select>
              </label>
              <label className={formLabelClassName}>
                <span className="block">Incorrect CPE Field</span>
                <select
                  aria-label="Incorrect CPE Field"
                  className={`${selectControlClassName} w-full`}
                  value={query.discrepancy_type ?? ""}
                  onChange={(event) =>
                    setQuery({
                      discrepancy_type:
                        event.target.value || undefined,
                      page: 1,
                    })
                  }
                >
                  <option value="">All Incorrect CPE Fields</option>
                  {discrepancyTypes.map((discrepancyType) => (
                    <option
                      key={discrepancyType.id}
                      value={discrepancyType.code}
                    >
                      {discrepancyType.name}
                      {!discrepancyType.is_active
                        ? " (Inactive)"
                        : ""}
                    </option>
                  ))}
                </select>
              </label>
              <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-end">
                <label
                  className={`${formLabelClassName} min-w-0 flex-1`}
                >
                  <span className="block">Sort</span>
                  <select
                    aria-label="Sort"
                    className={`${selectControlClassName} w-full`}
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
              <AlertTitle>
                Unable to load review components
              </AlertTitle>
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
            Loading review components…
          </CardContent>
        ) : null}

        {components ? (
          <div className="relative overflow-x-auto">
            {loading ? (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-background/60">
                <LoaderCircle
                  className="size-5 animate-spin"
                  aria-label="Loading review components"
                />
              </div>
            ) : null}
            <Table className="min-w-[1320px] table-fixed">
              <TableCaption className="sr-only">
                Ground Truth review components
              </TableCaption>
              <colgroup>
                <col className="w-[11%]" />
                <col className="w-[7%]" />
                <col className="w-[24%]" />
                <col className="w-[24%]" />
                <col className="w-[14%]" />
                <col className="w-[14%]" />
                <col className="w-[6%]" />
              </colgroup>
              <TableHeader className="bg-muted/45">
                <TableRow>
                  <TableHead className="text-left">Component</TableHead>
                  <TableHead className="text-center">Version</TableHead>
                  <TableHead className="text-left">Original CPE</TableHead>
                  <TableHead className="text-left">Ground Truth</TableHead>
                  <TableHead className="text-center">
                    CPE Validation Result
                  </TableHead>
                  <TableHead className="text-center">
                    Incorrect CPE Fields
                  </TableHead>
                  <TableHead className="text-center">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {components.results.map((component) => {
                  const value = groundTruthValue(component)
                  return (
                    <TableRow key={component.id}>
                      <TableCell className="min-w-0 text-left font-medium">
                        <p
                          className="truncate"
                          title={component.name}
                        >
                          {component.name}
                        </p>
                      </TableCell>
                      <TableCell className="min-w-0 text-center">
                        <p
                          className="truncate"
                          title={component.version || "—"}
                        >
                          {component.version || "—"}
                        </p>
                      </TableCell>
                      <TableCell className="min-w-0 text-left">
                        <p
                          className="w-full truncate font-mono text-xs"
                          title={component.cpe}
                        >
                          {component.cpe}
                        </p>
                      </TableCell>
                      <TableCell className="min-w-0 text-left">
                        <p
                          className="w-full truncate font-mono text-xs"
                          title={value}
                        >
                          {value}
                        </p>
                      </TableCell>
                      <TableCell className="min-w-0 text-center">
                        {component.decision ? (
                          <Badge
                            className="max-w-full truncate"
                            title={
                              groundTruthDecisionNames[
                                component.decision.code
                              ]
                            }
                            variant="secondary"
                          >
                            {
                              groundTruthDecisionNames[
                                component.decision.code
                              ]
                            }
                          </Badge>
                        ) : (
                          "—"
                        )}
                      </TableCell>
                      <TableCell className="min-w-0 text-center">
                        {component.discrepancy_types.length ? (
                          <div className="flex min-w-0 flex-wrap justify-center gap-1">
                            {component.discrepancy_types.map(
                              (discrepancyType) => (
                                <Badge
                                  className="max-w-full"
                                  key={discrepancyType.id}
                                  title={discrepancyType.name}
                                  variant="outline"
                                >
                                  {discrepancyType.name}
                                  {!discrepancyType.is_active
                                    ? " · Inactive"
                                    : ""}
                                </Badge>
                              ),
                            )}
                          </div>
                        ) : (
                          "None"
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-center">
                        <Button asChild size="sm" variant="outline">
                          <Link
                            to={groundTruthDetailPath(
                              component.id,
                              new URLSearchParams(searchSignature),
                            )}
                          >
                            {component.ground_truth_status ===
                            "COMPLETED"
                              ? "Edit"
                              : "Review"}
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
                No components match the current filters.
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
                className={`${selectControlClassName} w-auto`}
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
    </PageContent>
  )
}
