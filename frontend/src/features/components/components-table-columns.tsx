import type { ColumnDef } from "@tanstack/react-table"

import { Badge } from "@/components/ui/badge"
import { ComponentsTableSortHeader } from "@/features/components/components-table-sort-header"
import {
  dictionaryStatusClassName,
  dictionaryStatusLabels,
} from "@/features/components/dictionary-status"
import type { ComponentSummary } from "@/features/components/components-types"
import { cn } from "@/lib/utils"

function repositoryBasename(repository: string): string {
  return repository.split("/").at(-1) ?? repository
}

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
        <ComponentsTableSortHeader
          column={column}
          label="Version"
        />
      ),
      cell: ({ row }) => (
        <span
          title={row.original.version || undefined}
          className="block w-[120px] max-w-[150px] truncate font-mono text-xs"
        >
          {row.original.version || "—"}
        </span>
      ),
    },
    {
      id: "repository",
      accessorFn: (component) => component.image.repository,
      header: ({ column }) => (
        <ComponentsTableSortHeader
          column={column}
          label="Image"
        />
      ),
      cell: ({ row }) => {
        const { repository, tag } = row.original.image
        const imageReference = `${repository}:${tag}`
        return (
          <div
            title={imageReference}
            className="w-[210px] min-w-0 max-w-[230px]"
          >
            <div className="flex min-w-0 items-center gap-2">
              <span
                title={imageReference}
                className="min-w-0 flex-1 truncate font-medium"
              >
                {repositoryBasename(repository)}
              </span>
              <Badge
                variant="secondary"
                title={tag}
                className="max-w-24 shrink-0 truncate font-mono"
              >
                {tag}
              </Badge>
            </div>
            <p
              title={repository}
              className="mt-0.5 truncate text-xs text-muted-foreground"
            >
              {repository}
            </p>
          </div>
        )
      },
    },
    {
      accessorKey: "cpe",
      enableSorting: false,
      header: "Primary CPE",
      cell: ({ row }) => (
        <span
          title={row.original.cpe || undefined}
          className={cn(
            "block w-[360px] min-w-[260px] max-w-[400px] truncate font-mono text-xs",
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
      header: "Dictionary Status",
      cell: ({ row }) => (
        <div className="min-w-[180px] max-w-[200px]">
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
