import { LoaderCircle, Search } from "lucide-react"

import { Input } from "@/components/ui/input"
import {
  componentOrderings,
  componentPageSizes,
  type ComponentOrdering,
  type ComponentPageSize,
} from "@/features/components/components-query"
import {
  dictionaryStatuses,
  dictionaryStatusLabels,
} from "@/features/components/dictionary-status"
import type { DictionaryStatus } from "@/features/components/components-types"
import { formatInteger } from "@/lib/format"

const orderingLabels: Record<ComponentOrdering, string> = {
  name: "Name A–Z",
  "-name": "Name Z–A",
  version: "Version A–Z",
  "-version": "Version Z–A",
  component_type: "Type A–Z",
  "-component_type": "Type Z–A",
  publisher: "Publisher A–Z",
  "-publisher": "Publisher Z–A",
  repository: "Repository A–Z",
  "-repository": "Repository Z–A",
  tag: "Tag A–Z",
  "-tag": "Tag Z–A",
}

const selectClassName =
  "h-9 rounded-md border border-input bg-transparent px-3 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50"

interface ComponentsToolbarProps {
  searchInput: string
  ordering: ComponentOrdering
  pageSize: ComponentPageSize
  dictionaryStatus?: DictionaryStatus
  resultCount?: number
  isBusy: boolean
  onSearchInputChange: (value: string) => void
  onOrderingChange: (value: ComponentOrdering) => void
  onPageSizeChange: (value: ComponentPageSize) => void
  onDictionaryStatusChange: (
    value: DictionaryStatus | undefined,
  ) => void
}

export function ComponentsToolbar({
  searchInput,
  ordering,
  pageSize,
  dictionaryStatus,
  resultCount,
  isBusy,
  onSearchInputChange,
  onOrderingChange,
  onPageSizeChange,
  onDictionaryStatusChange,
}: ComponentsToolbarProps) {
  return (
    <div className="space-y-3 border-b p-4">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-end">
        <div className="min-w-0 flex-1">
          <label
            htmlFor="component-search"
            className="mb-1.5 block text-xs font-medium text-foreground"
          >
            Search components
          </label>
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              id="component-search"
              value={searchInput}
              onChange={(event) =>
                onSearchInputChange(event.target.value)
              }
              placeholder="Search name, version, publisher, PURL, CPE, or bom-ref..."
              className="pl-9"
            />
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3 sm:flex">
          <div>
            <label
              htmlFor="component-dictionary-status"
              className="mb-1.5 block text-xs font-medium text-foreground"
            >
              Dictionary status
            </label>
            <select
              id="component-dictionary-status"
              aria-label="Dictionary status filter"
              value={dictionaryStatus ?? ""}
              onChange={(event) =>
                onDictionaryStatusChange(
                  event.target.value
                    ? (event.target.value as DictionaryStatus)
                    : undefined,
                )
              }
              className={selectClassName}
            >
              <option value="">All Dictionary Statuses</option>
              {dictionaryStatuses.map((value) => (
                <option key={value} value={value}>
                  {dictionaryStatusLabels[value]}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label
              htmlFor="component-ordering"
              className="mb-1.5 block text-xs font-medium text-foreground"
            >
              Sort by
            </label>
            <select
              id="component-ordering"
              aria-label="Sort components"
              value={ordering}
              onChange={(event) =>
                onOrderingChange(
                  event.target.value as ComponentOrdering,
                )
              }
              className={selectClassName}
            >
              {componentOrderings.map((value) => (
                <option key={value} value={value}>
                  {orderingLabels[value]}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label
              htmlFor="component-page-size"
              className="mb-1.5 block text-xs font-medium text-foreground"
            >
              Per page
            </label>
            <select
              id="component-page-size"
              aria-label="Components per page"
              value={pageSize}
              onChange={(event) =>
                onPageSizeChange(
                  Number(event.target.value) as ComponentPageSize,
                )
              }
              className={selectClassName}
            >
              {componentPageSizes.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
        </div>

        <p
          className="flex min-h-9 shrink-0 items-center gap-2 text-sm text-muted-foreground xl:pb-0"
          aria-live="polite"
        >
          {isBusy ? (
            <LoaderCircle
              className="size-4 animate-spin"
              aria-hidden="true"
            />
          ) : null}
          {resultCount === undefined
            ? "Loading components"
            : searchInput.trim() || dictionaryStatus
              ? `${formatInteger(resultCount)} matching components`
              : `${formatInteger(resultCount)} primary CPE components`}
        </p>
      </div>
      <p className="text-xs leading-5 text-muted-foreground">
        Dictionary status indicates raw-string presence in the
        selected NVD snapshot, not semantic correctness.
      </p>
    </div>
  )
}
