import {
  BookOpenText,
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
import { useSearchParams } from "react-router-dom"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import {
  getCpeDictionaryResults,
  getCpeDictionarySnapshot,
} from "@/features/cpe-dictionary/cpe-dictionary-api"
import { CpeDictionaryComponentContext } from "@/features/cpe-dictionary/cpe-dictionary-context"
import { CpeDictionaryDetailDialog } from "@/features/cpe-dictionary/cpe-dictionary-detail"
import {
  DEFAULT_CPE_DICTIONARY_QUERY,
  hasCpeDictionarySearchTerm,
  parseCpeDictionaryUrlQuery,
  writeCpeDictionaryUrlQuery,
} from "@/features/cpe-dictionary/cpe-dictionary-query"
import { CpeDictionaryResultsTable } from "@/features/cpe-dictionary/cpe-dictionary-table"
import { CpeGroundTruthEditor } from "@/features/cpe-dictionary/cpe-ground-truth-editor"
import type {
  CpeDictionaryDetail,
  CpeDictionaryPageSize,
  CpeDictionaryQuery,
  CpeDictionaryResult,
  CpeDictionarySearchResponse,
  CpeDictionarySnapshot,
  CpeGroundTruthCandidate,
} from "@/features/cpe-dictionary/cpe-dictionary-types"
import { getComponentDetail } from "@/features/components/components-api"
import { ComponentsPagination } from "@/features/components/components-pagination"
import type { ComponentDetail } from "@/features/components/components-types"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"
import { formatInteger } from "@/lib/format"

const selectClassName =
  "h-8 w-full rounded-lg border border-input bg-background px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    return error.detail
      ? `${error.detail}${error.code ? ` (${error.code})` : ""}`
      : error.message
  }
  return fallback
}

function Field({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <label className="space-y-1.5 text-xs font-medium">
      <span>{label}</span>
      {children}
    </label>
  )
}

function candidateFromResult(
  result: CpeDictionaryResult,
): CpeGroundTruthCandidate {
  return {
    id: result.id,
    cpe_name: result.cpe_name,
    cpe_uuid: result.cpe_name_id,
    deprecated: result.deprecated,
    part: result.part,
    vendor: result.vendor,
    product: result.product,
    version: result.version,
  }
}

function candidateFromDetail(
  detail: CpeDictionaryDetail,
): CpeGroundTruthCandidate {
  return {
    id: detail.id,
    cpe_name: detail.cpe_name,
    cpe_uuid: detail.cpe_name_id,
    deprecated: detail.deprecated,
    part: detail.part,
    vendor: detail.vendor,
    product: detail.product,
    version: detail.version,
  }
}

export function CpeDictionaryPage() {
  const [searchParameters, setSearchParameters] =
    useSearchParams()
  const searchSignature = searchParameters.toString()
  const submittedQuery = useMemo(
    () =>
      parseCpeDictionaryUrlQuery(
        new URLSearchParams(searchSignature),
      ),
    [searchSignature],
  )
  const rawComponentId = searchParameters.get("component_id") ?? ""
  const componentId =
    /^\d+$/.test(rawComponentId) && Number(rawComponentId) > 0
      ? Number(rawComponentId)
      : undefined
  const invalidComponentId =
    Boolean(rawComponentId) && componentId === undefined

  const [draft, setDraft] =
    useState<CpeDictionaryQuery>(submittedQuery)
  const [response, setResponse] =
    useState<CpeDictionarySearchResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [searchError, setSearchError] = useState<string | null>(
    null,
  )
  const [selectedCpeNameId, setSelectedCpeNameId] = useState<
    string | null
  >(null)
  const [groundTruthCandidate, setGroundTruthCandidate] =
    useState<CpeGroundTruthCandidate | null>(null)
  const [snapshot, setSnapshot] =
    useState<CpeDictionarySnapshot | null>(null)
  const [snapshotError, setSnapshotError] = useState<string | null>(
    null,
  )
  const [component, setComponent] =
    useState<ComponentDetail | null>(null)
  const [componentLoading, setComponentLoading] = useState(false)
  const [componentError, setComponentError] = useState<
    string | null
  >(invalidComponentId ? "The component_id is invalid." : null)

  useEffect(() => {
    setDraft(submittedQuery)
  }, [submittedQuery])

  useEffect(() => {
    setGroundTruthCandidate(null)
  }, [componentId])

  useEffect(() => {
    const controller = new AbortController()
    getCpeDictionarySnapshot(controller.signal)
      .then((result) => {
        setSnapshot(result)
        setSnapshotError(null)
      })
      .catch((error: unknown) => {
        if (isAbortError(error)) return
        setSnapshotError(
          errorMessage(
            error,
            "The selected Dictionary snapshot is unavailable.",
          ),
        )
      })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!hasCpeDictionarySearchTerm(submittedQuery)) {
      setResponse(null)
      setSearchError(null)
      setLoading(false)
      return
    }
    const controller = new AbortController()
    setLoading(true)
    setSearchError(null)
    getCpeDictionaryResults(submittedQuery, controller.signal)
      .then((result) => {
        setResponse(result)
        setLoading(false)
      })
      .catch((error: unknown) => {
        if (isAbortError(error)) return
        setResponse(null)
        setSearchError(
          errorMessage(
            error,
            "The Dictionary search could not be completed.",
          ),
        )
        setLoading(false)
      })
    return () => controller.abort()
  }, [submittedQuery])

  useEffect(() => {
    if (invalidComponentId) {
      setComponent(null)
      setComponentLoading(false)
      setComponentError("The component_id is invalid.")
      return
    }
    if (!componentId) {
      setComponent(null)
      setComponentLoading(false)
      setComponentError(null)
      return
    }
    const controller = new AbortController()
    setComponent(null)
    setComponentLoading(true)
    setComponentError(null)
    getComponentDetail(componentId, controller.signal)
      .then((result) => {
        setComponent(result)
        setComponentLoading(false)
      })
      .catch((error: unknown) => {
        if (isAbortError(error)) return
        setComponentError(
          errorMessage(
            error,
            "The Component context could not be loaded.",
          ),
        )
        setComponentLoading(false)
      })
    return () => controller.abort()
  }, [componentId, invalidComponentId])

  const setQueryInUrl = useCallback(
    (nextQuery: CpeDictionaryQuery) => {
      setSearchParameters(
        writeCpeDictionaryUrlQuery(
          nextQuery,
          componentId ? String(componentId) : undefined,
        ),
      )
    },
    [componentId, setSearchParameters],
  )

  const submitSearch = (event: FormEvent) => {
    event.preventDefault()
    setQueryInUrl({
      ...draft,
      q: draft.q.trim(),
      vendor: draft.vendor.trim(),
      product: draft.product.trim(),
      version: draft.version.trim(),
      page: 1,
    })
  }

  const reset = () => {
    setDraft(DEFAULT_CPE_DICTIONARY_QUERY)
    setSelectedCpeNameId(null)
    const next = new URLSearchParams()
    if (componentId) {
      next.set("component_id", String(componentId))
    }
    setSearchParameters(next)
  }

  const fillDraft = (field: "q" | "product", value: string) => {
    setDraft((current) => ({ ...current, [field]: value }))
  }
  const totalPages = response
    ? Math.ceil(response.count / response.page_size)
    : 0
  const viewDetails = useCallback((cpeNameId: string) => {
    setSelectedCpeNameId(cpeNameId)
  }, [])

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-8">
        <div>
          <div className="flex items-center gap-2">
            <BookOpenText
              className="size-5 text-cyan-700"
              aria-hidden="true"
            />
            <h1 className="font-heading text-2xl font-semibold tracking-tight">
              CPE Dictionary
            </h1>
          </div>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
            Search the selected official NVD CPE Dictionary
            snapshot and compare records with SBOM metadata. Results
            are not Ground Truth and are never applied automatically.
          </p>
        </div>
        <div className="max-w-sm rounded-lg border bg-card px-4 py-3 text-right">
          <p className="text-xs font-medium text-muted-foreground">
            CPE Dictionary Snapshot
          </p>
          <p className="mt-1 font-mono text-sm font-semibold">
            {response?.snapshot.snapshot_id ??
              snapshot?.snapshot_id ??
              component?.dictionary_match.snapshot_id ??
              "Unavailable"}
          </p>
          {response || snapshot ? (
            <p
              className="mt-1 max-w-72 truncate font-mono text-[10px] text-muted-foreground"
              title={
                response?.snapshot.manifest_sha256 ??
                snapshot?.manifest_sha256
              }
            >
              Manifest SHA-256:{" "}
              {response?.snapshot.manifest_sha256 ??
                snapshot?.manifest_sha256}
            </p>
          ) : null}
          {snapshotError ? (
            <p className="mt-1 text-xs text-red-700">
              {snapshotError}
            </p>
          ) : null}
        </div>
      </header>

      {rawComponentId ? (
        <CpeDictionaryComponentContext
          detail={component}
          loading={componentLoading}
          error={componentError}
          onFill={fillDraft}
        />
      ) : null}

      {componentId && !invalidComponentId ? (
        <CpeGroundTruthEditor
          key={componentId}
          componentId={componentId}
          selectedCpe={groundTruthCandidate}
          onSelectedCpeChange={setGroundTruthCandidate}
        />
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Search official CPE names</CardTitle>
          <CardDescription>
            Enter a keyword or a structured CPE field. Structured
            fields use case-insensitive exact equality.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="grid grid-cols-6 gap-3"
            onSubmit={submitSearch}
          >
            <Field label="Keyword">
              <Input
                name="q"
                value={draft.q}
                placeholder="curl, openssl, or a title"
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    q: event.target.value,
                  }))
                }
              />
            </Field>
            <Field label="Part">
              <select
                name="part"
                className={selectClassName}
                value={draft.part}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    part: event.target
                      .value as CpeDictionaryQuery["part"],
                  }))
                }
              >
                <option value="">Any part</option>
                <option value="a">Application (a)</option>
                <option value="o">Operating system (o)</option>
                <option value="h">Hardware (h)</option>
              </select>
            </Field>
            <Field label="Vendor">
              <Input
                name="vendor"
                value={draft.vendor}
                placeholder="haxx"
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    vendor: event.target.value,
                  }))
                }
              />
            </Field>
            <Field label="Product">
              <Input
                name="product"
                value={draft.product}
                placeholder="curl"
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    product: event.target.value,
                  }))
                }
              />
            </Field>
            <Field label="Version">
              <Input
                name="version"
                value={draft.version}
                placeholder="8.14.1"
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    version: event.target.value,
                  }))
                }
              />
            </Field>
            <Field label="Status">
              <select
                name="deprecated"
                className={selectClassName}
                value={draft.deprecated}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    deprecated: event.target
                      .value as CpeDictionaryQuery["deprecated"],
                  }))
                }
              >
                <option value="active">Active</option>
                <option value="deprecated">Deprecated</option>
                <option value="all">All records</option>
              </select>
            </Field>
            <div className="col-span-6 flex gap-2 pt-1">
              <Button type="submit" disabled={loading}>
                {loading ? (
                  <LoaderCircle
                    className="animate-spin"
                    aria-hidden="true"
                  />
                ) : (
                  <Search aria-hidden="true" />
                )}
                Search
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={reset}
              >
                <RotateCcw aria-hidden="true" />
                Reset
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {searchError ? (
        <Alert variant="destructive">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>Dictionary search failed</AlertTitle>
          <AlertDescription>{searchError}</AlertDescription>
        </Alert>
      ) : null}

      {!hasCpeDictionarySearchTerm(submittedQuery) ? (
        <Card>
          <CardContent className="flex min-h-48 flex-col items-center justify-center text-center">
            <Search
              className="size-7 text-muted-foreground"
              aria-hidden="true"
            />
            <h2 className="mt-3 font-heading font-semibold">
              Search the selected Dictionary snapshot
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Enter a keyword or structured CPE field, then submit the
              form.
            </p>
          </CardContent>
        </Card>
      ) : null}

      {loading && !response ? (
        <Card aria-busy="true">
          <CardContent className="flex min-h-48 items-center justify-center gap-2 text-sm text-muted-foreground">
            <LoaderCircle
              className="size-4 animate-spin"
              aria-hidden="true"
            />
            Searching the selected Dictionary snapshot…
          </CardContent>
        </Card>
      ) : null}

      {response ? (
        <Card aria-busy={loading}>
          <CardHeader>
            <CardTitle>
              {formatInteger(response.count)} result
              {response.count === 1 ? "" : "s"}
            </CardTitle>
            <CardDescription>
              Active records are listed first, followed by vendor,
              product, version, and raw CPE.
            </CardDescription>
          </CardHeader>
          {response.results.length > 0 ? (
            <CpeDictionaryResultsTable
              results={response.results}
              onViewDetails={viewDetails}
              onSelectGroundTruth={
                componentId
                  ? (result) =>
                      setGroundTruthCandidate(
                        candidateFromResult(result),
                      )
                  : undefined
              }
            />
          ) : (
            <CardContent className="flex min-h-40 items-center justify-center text-sm text-muted-foreground">
              No CPE Dictionary records match these exact search
              conditions.
            </CardContent>
          )}
          <CardFooter className="justify-between gap-4">
            <label className="flex shrink-0 items-center gap-2 whitespace-nowrap text-sm">
              <span className="shrink-0 text-muted-foreground">
                Rows per page
              </span>
              <select
                aria-label="Rows per page"
                className={`${selectClassName} w-24`}
                value={submittedQuery.page_size}
                onChange={(event) =>
                  setQueryInUrl({
                    ...submittedQuery,
                    page: 1,
                    page_size: Number(
                      event.target.value,
                    ) as CpeDictionaryPageSize,
                  })
                }
              >
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
            </label>
            <ComponentsPagination
              page={response.page}
              totalPages={totalPages}
              disabled={loading}
              onPageChange={(page) =>
                setQueryInUrl({ ...submittedQuery, page })
              }
            />
          </CardFooter>
        </Card>
      ) : null}

      <CpeDictionaryDetailDialog
        cpeNameId={selectedCpeNameId}
        onClose={() => setSelectedCpeNameId(null)}
        onSelectGroundTruth={
          componentId
            ? (detail) =>
                setGroundTruthCandidate(
                  candidateFromDetail(detail),
                )
            : undefined
        }
      />
    </div>
  )
}
