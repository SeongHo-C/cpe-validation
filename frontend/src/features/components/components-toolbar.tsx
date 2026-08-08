import { LoaderCircle, Search } from "lucide-react"

import {
  formLabelTextClassName,
  selectControlClassName,
} from "@/components/form-control-styles"
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
            className={formLabelTextClassName}
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
              className="pl-9"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 xl:flex">
          <div>
            <label
              htmlFor="component-dictionary-status"
              className={formLabelTextClassName}
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
              className={`${selectControlClassName} w-full`}
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
              className={formLabelTextClassName}
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
              className={`${selectControlClassName} w-full`}
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
              className={formLabelTextClassName}
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
              className={`${selectControlClassName} w-full`}
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
            : `${formatInteger(resultCount)} ${
                resultCount === 1 ? "result" : "results"
              }`}
        </p>
      </div>
      <p className="text-xs leading-5 text-muted-foreground">
        Dictionary status reflects exact NVD CPE presence, not
        semantic correctness.
      </p>
    </div>
  )
}
