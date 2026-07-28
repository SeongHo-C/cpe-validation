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
import { CpeDictionaryDetailDialog } from "@/features/cpe-dictionary/cpe-dictionary-detail"
import {
  DEFAULT_CPE_DICTIONARY_QUERY,
  hasCpeDictionarySearchTerm,
  parseCpeDictionaryUrlQuery,
  writeCpeDictionaryUrlQuery,
} from "@/features/cpe-dictionary/cpe-dictionary-query"
import { CpeDictionaryResultsTable } from "@/features/cpe-dictionary/cpe-dictionary-table"
import type {
  CpeDictionaryDetail,
  CpeDictionaryCandidate,
  CpeDictionaryPageSize,
  CpeDictionaryQuery,
  CpeDictionaryResult,
  CpeDictionarySearchResponse,
  CpeDictionarySnapshot,
} from "@/features/cpe-dictionary/cpe-dictionary-types"
import { ComponentsPagination } from "@/features/components/components-pagination"
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
): CpeDictionaryCandidate {
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
): CpeDictionaryCandidate {
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

const emptyPreservedQueryKeys: readonly string[] = []

export function CpeDictionarySearch({
  onSelectCandidate,
  onCopyToManual,
  preserveQueryKeys = emptyPreservedQueryKeys,
}: {
  onSelectCandidate?: (
    candidate: CpeDictionaryCandidate,
  ) => void
  onCopyToManual?: (rawCpe: string) => void
  preserveQueryKeys?: readonly string[]
}) {
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
  const [reloadToken, setReloadToken] = useState(0)
  const [snapshot, setSnapshot] =
    useState<CpeDictionarySnapshot | null>(null)
  const [snapshotError, setSnapshotError] = useState<string | null>(
    null,
  )

  useEffect(() => {
    setDraft(submittedQuery)
  }, [submittedQuery])

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
        setSearchError(
          errorMessage(
            error,
            "The Dictionary search could not be completed.",
          ),
        )
        setLoading(false)
      })
    return () => controller.abort()
  }, [reloadToken, submittedQuery])

  const setQueryInUrl = useCallback(
    (nextQuery: CpeDictionaryQuery) => {
      const next = writeCpeDictionaryUrlQuery(nextQuery)
      for (const key of preserveQueryKeys) {
        const value = searchParameters.get(key)
        if (value !== null) next.set(key, value)
      }
      if (hasCpeDictionarySearchTerm(nextQuery)) {
        setLoading(true)
      }
      setSearchParameters(next)
    },
    [
      preserveQueryKeys,
      searchParameters,
      setSearchParameters,
    ],
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
    for (const key of preserveQueryKeys) {
      const value = searchParameters.get(key)
      if (value !== null) next.set(key, value)
    }
    setSearchParameters(next)
  }

  const totalPages = response
    ? Math.ceil(response.count / response.page_size)
    : 0
  const viewDetails = useCallback((cpeNameId: string) => {
    setSelectedCpeNameId(cpeNameId)
  }, [])

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <div className="max-w-sm rounded-lg border bg-card px-4 py-3 text-right">
          <p className="text-xs font-medium text-muted-foreground">
            CPE Dictionary Snapshot
          </p>
          <p className="mt-1 font-mono text-sm font-semibold">
            {response?.snapshot.snapshot_id ??
              snapshot?.snapshot_id ??
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
      </div>

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
          <div className="col-start-2 mt-3">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setLoading(true)
                setReloadToken((current) => current + 1)
              }}
            >
              Retry
            </Button>
          </div>
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
        <Card className="relative" aria-busy={loading}>
          {loading ? (
            <div className="absolute inset-0 z-10 flex items-center justify-center bg-background/65 backdrop-blur-[1px]">
              <div className="flex items-center gap-2 rounded-lg border bg-card px-4 py-3 text-sm shadow-sm">
                <LoaderCircle
                  className="size-4 animate-spin"
                  aria-hidden="true"
                />
                불러오는 중...
              </div>
            </div>
          ) : null}
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
              onSelectCandidate={
                onSelectCandidate
                  ? (result) =>
                      onSelectCandidate(
                        candidateFromResult(result),
                      )
                  : undefined
              }
              onCopyToManual={onCopyToManual}
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
        onSelectCandidate={
          onSelectCandidate
            ? (detail) =>
                onSelectCandidate(candidateFromDetail(detail))
            : undefined
        }
        onCopyToManual={onCopyToManual}
      />
    </div>
  )
}
