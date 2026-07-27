import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from "@tanstack/react-table"
import {
  useState,
  type KeyboardEvent,
} from "react"

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
import { imagesTableColumns } from "@/features/images/images-table-columns"
import type { DockerImageSummary } from "@/features/images/images-types"

interface ImagesTableProps {
  images: DockerImageSummary[]
  onSelectImage: (imageId: number) => void
}

const defaultSorting: SortingState = [
  { id: "repository", desc: false },
  { id: "tag", desc: false },
]

export function ImagesTable({
  images,
  onSelectImage,
}: ImagesTableProps) {
  const [sorting, setSorting] =
    useState<SortingState>(defaultSorting)
  const table = useReactTable({
    data: images,
    columns: imagesTableColumns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    sortDescFirst: false,
    enableSortingRemoval: true,
  })

  return (
    <Table>
      <TableCaption className="sr-only">
        Docker Official Images and Primary CPE coverage
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
                        : "none"
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
          <TableRow
            key={row.original.id}
            role="link"
            tabIndex={0}
            aria-label={`View Primary CPE Components for ${row.original.repository}:${row.original.tag}`}
            className="cursor-pointer outline-none focus-visible:bg-cyan-50 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-600"
            onClick={() => onSelectImage(row.original.id)}
            onKeyDown={(
              event: KeyboardEvent<HTMLTableRowElement>,
            ) => {
              if (
                event.key === "Enter" ||
                event.key === " "
              ) {
                event.preventDefault()
                onSelectImage(row.original.id)
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
        ))}
      </TableBody>
    </Table>
  )
}

export function ImagesTableSkeleton() {
  return (
    <div aria-label="Loading Docker image table">
      <Table>
        <TableCaption className="sr-only">
          Loading Docker image inventory
        </TableCaption>
        <TableHeader className="bg-muted/45">
          <TableRow>
            {[
              "Repository",
              "Tag",
              "Platform",
              "SBOMs",
              "Components",
              "Primary CPE",
              "Without CPE",
              "Coverage",
            ].map((label) => (
              <TableHead key={label}>{label}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: 8 }, (_, rowIndex) => (
            <TableRow key={rowIndex}>
              {Array.from({ length: 8 }, (_, cellIndex) => (
                <TableCell key={cellIndex}>
                  <Skeleton
                    className={
                      cellIndex === 0
                        ? "h-8 w-44"
                        : "h-5 w-16"
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
