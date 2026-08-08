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

const cpePartLabels: Record<string, string | undefined> = {
  a: "Application",
  o: "Operating System",
  h: "Hardware",
}

function cpePartLabel(part: string): string {
  const rawPart = part.trim()
  return cpePartLabels[rawPart] ?? (rawPart || "Not provided")
}

function columnLayoutClassName(
  columnId: string,
  hasReviewActions: boolean,
): string {
  switch (columnId) {
    case "status":
      return "w-24 text-center"
    case "part":
      return "w-32 text-center"
    case "vendor":
      return "w-20 text-left"
    case "product":
      return "w-24 text-left"
    case "version":
      return "w-20 text-center"
    case "cpe_name":
      return "text-left"
    case "actions":
      return hasReviewActions
        ? "w-64 text-center"
        : "w-36 text-center"
    default:
      return "text-left"
  }
}

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
  const hasReviewActions = Boolean(
    onSelectCandidate || onCopyToManual,
  )
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
        accessorKey: "part",
        header: "Part",
        cell: ({ row }) => cpePartLabel(row.original.part),
      },
      {
        accessorKey: "vendor",
        header: "Vendor",
        cell: ({ row }) => (
          <div
            className="w-full truncate"
            title={row.original.vendor}
          >
            {row.original.vendor}
          </div>
        ),
      },
      {
        accessorKey: "product",
        header: "Product",
        cell: ({ row }) => (
          <div
            className="w-full truncate"
            title={row.original.product}
          >
            {row.original.product}
          </div>
        ),
      },
      {
        accessorKey: "version",
        header: "Version",
        cell: ({ row }) => (
          <span
            className="block w-full truncate font-mono text-xs"
            title={row.original.version}
          >
            {row.original.version}
          </span>
        ),
      },
      {
        accessorKey: "cpe_name",
        header: "CPE name",
        cell: ({ row }) => (
          <div
            className="w-full truncate font-mono text-xs"
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
          <div className="flex items-center justify-center gap-1 whitespace-nowrap">
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
                aria-label="Select as Ground Truth"
                onClick={() =>
                  onSelectCandidate(row.original)
                }
              >
                <BadgeCheck aria-hidden="true" />
                Select
              </Button>
            ) : null}
            {onCopyToManual ? (
              <Button
                type="button"
                size="icon-sm"
                variant="outline"
                aria-label="Copy to Manual CPE"
                title="Copy to Manual CPE"
                onClick={() =>
                  onCopyToManual(row.original.cpe_name)
                }
              >
                <Clipboard aria-hidden="true" />
              </Button>
            ) : null}
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
    <Table className="min-w-[1080px] table-fixed">
      <TableCaption className="sr-only">
        CPE Dictionary search results
      </TableCaption>
      <TableHeader className="bg-muted/45">
        {table.getHeaderGroups().map((group) => (
          <TableRow key={group.id}>
            {group.headers.map((header) => (
              <TableHead
                key={header.id}
                className={columnLayoutClassName(
                  header.column.id,
                  hasReviewActions,
                )}
              >
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
              <TableCell
                key={cell.id}
                className={columnLayoutClassName(
                  cell.column.id,
                  hasReviewActions,
                )}
              >
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
