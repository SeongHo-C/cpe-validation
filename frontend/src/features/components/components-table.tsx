import {
  flexRender,
  functionalUpdate,
  getCoreRowModel,
  useReactTable,
  type SortingState,
  type Updater,
} from "@tanstack/react-table"
import type { KeyboardEvent } from "react"

import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  type ComponentOrdering,
} from "@/features/components/components-query"
import { componentsTableColumns } from "@/features/components/components-table-columns"
import type { ComponentSummary } from "@/features/components/components-types"
import { cn } from "@/lib/utils"

interface ComponentsTableProps {
  components: ComponentSummary[]
  ordering: ComponentOrdering
  page: number
  pageSize: number
  totalPages: number
  isRefreshing: boolean
  selectedComponentId?: number
  onOrderingChange: (ordering: ComponentOrdering) => void
  onSelectComponent: (componentId: number) => void
}

const sortableColumnIds = new Set([
  "name",
  "version",
  "repository",
  "component_type",
  "publisher",
])

function orderingToSorting(
  ordering: ComponentOrdering,
): SortingState {
  const desc = ordering.startsWith("-")
  return [
    {
      id: desc ? ordering.slice(1) : ordering,
      desc,
    },
  ]
}

function sortingToOrdering(
  sorting: SortingState,
): ComponentOrdering | null {
  const sort = sorting[0]
  if (!sort || !sortableColumnIds.has(sort.id)) return null
  return `${sort.desc ? "-" : ""}${sort.id}` as ComponentOrdering
}

export function ComponentsTable({
  components,
  ordering,
  page,
  pageSize,
  totalPages,
  isRefreshing,
  selectedComponentId,
  onOrderingChange,
  onSelectComponent,
}: ComponentsTableProps) {
  const sorting = orderingToSorting(ordering)
  const table = useReactTable({
    data: components,
    columns: componentsTableColumns,
    state: {
      sorting,
      pagination: {
        pageIndex: Math.max(page - 1, 0),
        pageSize,
      },
    },
    manualPagination: true,
    manualSorting: true,
    pageCount: totalPages,
    enableSortingRemoval: false,
    getCoreRowModel: getCoreRowModel(),
    onSortingChange: (
      updater: Updater<SortingState>,
    ) => {
      const nextSorting = functionalUpdate(updater, sorting)
      const nextOrdering = sortingToOrdering(nextSorting)
      if (nextOrdering) {
        onOrderingChange(nextOrdering)
      }
    },
  })

  return (
    <div
      aria-busy={isRefreshing}
      className={cn(
        "transition-opacity",
        isRefreshing && "opacity-60",
      )}
    >
      <Table className="min-w-[1080px] table-auto">
        <TableCaption className="sr-only">
          Primary CPE Components for Dictionary review
        </TableCaption>
        <TableHeader className="bg-muted/45">
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={headerGroup.id}>
              {headerGroup.headers.map((header) => {
                const sorted = header.column.getIsSorted()
                return (
                  <TableHead
                    key={header.id}
                    aria-sort={
                      sorted === "asc"
                        ? "ascending"
                        : sorted === "desc"
                          ? "descending"
                          : undefined
                    }
                  >
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )}
                  </TableHead>
                )
              })}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.map((row) => {
            const isSelected =
              row.original.id === selectedComponentId
            return (
              <TableRow
                key={row.original.id}
                role="button"
                tabIndex={0}
                aria-label={`Inspect component ${row.original.name} ${row.original.version || "without a version"}`}
                aria-pressed={isSelected}
                data-state={isSelected ? "selected" : undefined}
                className="cursor-pointer outline-none focus-visible:bg-cyan-50 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-600"
                onClick={() =>
                  onSelectComponent(row.original.id)
                }
                onKeyDown={(
                  event: KeyboardEvent<HTMLTableRowElement>,
                ) => {
                  if (
                    event.key === "Enter" ||
                    event.key === " "
                  ) {
                    event.preventDefault()
                    onSelectComponent(row.original.id)
                  }
                }}
              >
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id}>
                    {flexRender(
                      cell.column.columnDef.cell,
                      cell.getContext(),
                    )}
                  </TableCell>
                ))}
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}

export function ComponentsTableSkeleton() {
  return (
    <div aria-label="Loading Primary CPE Component table">
      <Table className="min-w-[1080px] table-auto">
        <TableCaption className="sr-only">
          Loading Primary CPE Components
        </TableCaption>
        <TableHeader className="bg-muted/45">
          <TableRow>
            <TableHead>Component</TableHead>
            <TableHead className="text-center">Version</TableHead>
            <TableHead>Primary CPE</TableHead>
            <TableHead className="text-center">
              Dictionary Status
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: 9 }, (_, rowIndex) => (
            <TableRow key={rowIndex}>
              <TableCell>
                <Skeleton className="h-8 w-52" />
              </TableCell>
              <TableCell>
                <Skeleton className="mx-auto h-5 w-20" />
              </TableCell>
              <TableCell>
                <Skeleton className="h-8 w-72" />
              </TableCell>
              <TableCell>
                <Skeleton className="mx-auto h-5 w-24" />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
