import type { ColumnDef } from "@tanstack/react-table"

import { Badge } from "@/components/ui/badge"
import { ComponentsTableSortHeader } from "@/features/components/components-table-sort-header"
import {
  dictionaryStatusClassName,
  dictionaryStatusLabels,
} from "@/features/components/dictionary-status"
import type { ComponentSummary } from "@/features/components/components-types"
import { cn } from "@/lib/utils"

export const componentsTableColumns: ColumnDef<ComponentSummary>[] =
  [
    {
      accessorKey: "name",
      header: ({ column }) => (
        <ComponentsTableSortHeader
          column={column}
          label="Component"
        />
      ),
      cell: ({ row }) => (
        <div className="w-[240px] min-w-0 max-w-[280px]">
          <p
            title={row.original.name || undefined}
            className="truncate font-medium text-foreground"
          >
            {row.original.name || "Not provided"}
          </p>
          {row.original.purl ? (
            <p
              title={row.original.purl}
              className="mt-0.5 truncate font-mono text-xs text-muted-foreground"
            >
              {row.original.purl}
            </p>
          ) : (
            <p className="mt-0.5 text-xs text-muted-foreground">
              No PURL
            </p>
          )}
        </div>
      ),
    },
    {
      accessorKey: "version",
      header: ({ column }) => (
        <div className="flex justify-center">
          <ComponentsTableSortHeader
            column={column}
            label="Version"
            align="center"
          />
        </div>
      ),
      cell: ({ row }) => (
        <span
          title={row.original.version || undefined}
          className="mx-auto block w-[120px] max-w-[150px] truncate text-center font-mono text-xs"
        >
          {row.original.version || "—"}
        </span>
      ),
    },
    {
      accessorKey: "cpe",
      enableSorting: false,
      header: "Primary CPE",
      cell: ({ row }) => (
        <span
          title={row.original.cpe || undefined}
          className={cn(
            "block w-[520px] min-w-[360px] max-w-[600px] truncate font-mono text-xs",
            !row.original.cpe && "text-muted-foreground",
          )}
        >
          {row.original.cpe || "—"}
        </span>
      ),
    },
    {
      accessorKey: "dictionary_status",
      enableSorting: false,
      header: () => (
        <div className="text-center">Dictionary Status</div>
      ),
      cell: ({ row }) => (
        <div className="mx-auto flex min-w-[180px] max-w-[200px] justify-center">
          <Badge
            variant="outline"
            className={cn(
              "whitespace-nowrap",
              dictionaryStatusClassName(
                row.original.dictionary_status,
              ),
            )}
          >
            {
              dictionaryStatusLabels[
                row.original.dictionary_status
              ]
            }
          </Badge>
        </div>
      ),
    },
  ]
