import type { ColumnDef } from "@tanstack/react-table"
import { ChevronRight } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { ImagesTableSortHeader } from "@/features/images/images-table-sort-header"
import type { DockerImageSummary } from "@/features/images/images-types"
import { formatInteger, formatPercent } from "@/lib/format"

function repositoryBasename(repository: string): string {
  return repository.split("/").at(-1) ?? repository
}

export const imagesTableColumns: ColumnDef<DockerImageSummary>[] = [
  {
    accessorKey: "repository",
    header: ({ column }) => (
      <ImagesTableSortHeader
        column={column}
        label="Repository"
      />
    ),
    cell: ({ row }) => (
      <div className="flex min-w-52 items-center gap-3">
        <div className="min-w-0 flex-1">
          <p className="font-medium text-foreground">
            {repositoryBasename(row.original.repository)}
          </p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {row.original.repository}
          </p>
        </div>
        <ChevronRight
          className="size-4 shrink-0 text-muted-foreground"
          aria-hidden="true"
        />
      </div>
    ),
  },
  {
    accessorKey: "tag",
    header: ({ column }) => (
      <ImagesTableSortHeader column={column} label="Tag" />
    ),
    cell: ({ row }) => (
      <Badge variant="secondary" className="font-mono">
        {row.original.tag}
      </Badge>
    ),
  },
  {
    accessorKey: "platform",
    header: ({ column }) => (
      <ImagesTableSortHeader column={column} label="Platform" />
    ),
    cell: ({ row }) => (
      <span className="font-mono text-xs text-muted-foreground">
        {row.original.platform}
      </span>
    ),
  },
  {
    accessorKey: "sbom_count",
    header: ({ column }) => (
      <ImagesTableSortHeader column={column} label="SBOMs" />
    ),
    cell: ({ row }) => formatInteger(row.original.sbom_count),
  },
  {
    accessorKey: "total_components",
    header: ({ column }) => (
      <ImagesTableSortHeader
        column={column}
        label="Components"
      />
    ),
    cell: ({ row }) =>
      formatInteger(row.original.total_components),
  },
  {
    accessorKey: "components_with_primary_cpe",
    header: ({ column }) => (
      <ImagesTableSortHeader
        column={column}
        label="Primary CPE"
      />
    ),
    cell: ({ row }) =>
      formatInteger(row.original.components_with_primary_cpe),
  },
  {
    accessorKey: "components_without_primary_cpe",
    header: ({ column }) => (
      <ImagesTableSortHeader
        column={column}
        label="Without CPE"
      />
    ),
    cell: ({ row }) =>
      formatInteger(row.original.components_without_primary_cpe),
  },
  {
    accessorKey: "primary_cpe_ratio",
    header: ({ column }) => (
      <ImagesTableSortHeader column={column} label="Coverage" />
    ),
    cell: ({ row }) => {
      const ratio = row.original.primary_cpe_ratio
      const percentage = Math.min(Math.max(ratio * 100, 0), 100)
      const label = formatPercent(ratio)
      return (
        <div className="flex min-w-28 items-center gap-2">
          <Progress
            value={percentage}
            aria-label={`Primary CPE Coverage ${label}`}
            className="w-16 [&_[data-slot=progress-indicator]]:bg-cyan-600"
          />
          <span className="w-11 text-right text-xs font-medium">
            {label}
          </span>
        </div>
      )
    },
  },
]
