import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table"
import {
  BadgeCheck,
  Clipboard,
  FileSearch,
} from "lucide-react"
import { useMemo } from "react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import type { CpeDictionaryResult } from "@/features/cpe-dictionary/cpe-dictionary-types"

export function CpeDictionaryResultsTable({
  results,
  onViewDetails,
  onSelectCandidate,
  onCopyToManual,
}: {
  results: CpeDictionaryResult[]
  onViewDetails: (cpeNameId: string) => void
  onSelectCandidate?: (record: CpeDictionaryResult) => void
  onCopyToManual?: (rawCpe: string) => void
}) {
  const columns = useMemo<ColumnDef<CpeDictionaryResult>[]>(
    () => [
      {
        id: "status",
        header: "Status",
        cell: ({ row }) => (
          <Badge
            variant="outline"
            className={
              row.original.deprecated
                ? "border-amber-200 bg-amber-50 text-amber-700"
                : "border-emerald-200 bg-emerald-50 text-emerald-700"
            }
          >
            {row.original.deprecated ? "Deprecated" : "Active"}
          </Badge>
        ),
      },
      {
        accessorKey: "title",
        header: "Title",
        cell: ({ row }) => (
          <div
            className="max-w-60 truncate font-medium"
            title={row.original.title}
          >
            {row.original.title || "No title"}
          </div>
        ),
      },
      { accessorKey: "vendor", header: "Vendor" },
      { accessorKey: "product", header: "Product" },
      {
        accessorKey: "version",
        header: "Version",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.version}
          </span>
        ),
      },
      { accessorKey: "update", header: "Update" },
      { accessorKey: "target_sw", header: "Target SW" },
      {
        accessorKey: "cpe_name",
        header: "CPE name",
        cell: ({ row }) => (
          <div
            className="max-w-80 truncate font-mono text-xs"
            title={row.original.cpe_name}
          >
            {row.original.cpe_name}
          </div>
        ),
      },
      {
        id: "actions",
        header: "Actions",
        cell: ({ row }) => (
          <div className="flex gap-1">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() =>
                onViewDetails(row.original.cpe_name_id)
              }
            >
              <FileSearch aria-hidden="true" />
              View details
            </Button>
            {onSelectCandidate ? (
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() =>
                  onSelectCandidate(row.original)
                }
              >
                <BadgeCheck aria-hidden="true" />
                Ground Truth로 선택
              </Button>
            ) : null}
            {onCopyToManual ? (
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() =>
                  onCopyToManual(row.original.cpe_name)
                }
              >
                <Clipboard aria-hidden="true" />
                수동 CPE로 복사
              </Button>
            ) : null}
            <Button
              type="button"
              size="icon-sm"
              variant="ghost"
              aria-label={`Copy CPE ${row.original.cpe_name}`}
              onClick={() =>
                void navigator.clipboard.writeText(
                  row.original.cpe_name,
                )
              }
            >
              <Clipboard aria-hidden="true" />
            </Button>
          </div>
        ),
      },
    ],
    [onCopyToManual, onSelectCandidate, onViewDetails],
  )
  const table = useReactTable({
    data: results,
    columns,
    getCoreRowModel: getCoreRowModel(),
  })

  return (
    <Table className="min-w-[1180px]">
      <TableCaption className="sr-only">
        CPE Dictionary search results
      </TableCaption>
      <TableHeader className="bg-muted/45">
        {table.getHeaderGroups().map((group) => (
          <TableRow key={group.id}>
            {group.headers.map((header) => (
              <TableHead key={header.id}>
                {header.isPlaceholder
                  ? null
                  : flexRender(
                      header.column.columnDef.header,
                      header.getContext(),
                    )}
              </TableHead>
            ))}
          </TableRow>
        ))}
      </TableHeader>
      <TableBody>
        {table.getRowModel().rows.map((row) => (
          <TableRow key={row.original.cpe_name_id}>
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
