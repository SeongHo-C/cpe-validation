import {
  flexRender,
  functionalUpdate,
  getCoreRowModel,
  useReactTable,
  type SortingState,
  type Updater,
} from "@tanstack/react-table"

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
  onOrderingChange: (ordering: ComponentOrdering) => void
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
  onOrderingChange,
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
      <Table className="min-w-[1280px]">
        <TableCaption className="sr-only">
          Primary CPE Components selected for structural validation
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
          {table.getRowModel().rows.map((row) => (
            <TableRow key={row.original.id}>
              {row.getVisibleCells().map((cell) => (
                <TableCell key={cell.id}>
                  {flexRender(
                    cell.column.columnDef.cell,
                    cell.getContext(),
                  )}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

export function ComponentsTableSkeleton() {
  return (
    <div aria-label="Loading Primary CPE Component table">
      <Table className="min-w-[1280px]">
        <TableCaption className="sr-only">
          Loading Primary CPE Components
        </TableCaption>
        <TableHeader className="bg-muted/45">
          <TableRow>
            {[
              "Component",
              "Version",
              "Image",
              "Type",
              "Publisher",
              "Primary CPE",
              "Part",
              "Structural Status",
            ].map((label) => (
              <TableHead key={label}>{label}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: 9 }, (_, rowIndex) => (
            <TableRow key={rowIndex}>
              {Array.from({ length: 8 }, (_, cellIndex) => (
                <TableCell key={cellIndex}>
                  <Skeleton
                    className={
                      cellIndex === 0 || cellIndex === 5
                        ? "h-8 w-52"
                        : "h-5 w-20"
                    }
                  />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
