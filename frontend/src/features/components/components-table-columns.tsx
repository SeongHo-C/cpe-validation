import type { ColumnDef } from "@tanstack/react-table"

import { Badge } from "@/components/ui/badge"
import { ComponentsTableSortHeader } from "@/features/components/components-table-sort-header"
import type { ComponentSummary } from "@/features/components/components-types"
import { cn } from "@/lib/utils"

function repositoryBasename(repository: string): string {
  return repository.split("/").at(-1) ?? repository
}

const partDescriptions: Record<string, string> = {
  a: "Application",
  o: "Operating System",
  h: "Hardware",
}

function structuralStatusClassName(status: string): string {
  if (status === "STRUCTURALLY_VALID") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700"
  }
  if (status === "NOT_PRESENT") {
    return "border-border bg-muted text-muted-foreground"
  }
  return "border-red-200 bg-red-50 text-red-700"
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
        <div className="min-w-64 max-w-80">
          <p className="font-medium text-foreground">
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
        <span className="font-mono text-xs">
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
      cell: ({ row }) => (
        <div className="min-w-48">
          <div className="flex items-center gap-2">
            <span className="font-medium">
              {repositoryBasename(row.original.image.repository)}
            </span>
            <Badge variant="secondary" className="font-mono">
              {row.original.image.tag}
            </Badge>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {row.original.image.repository}
          </p>
        </div>
      ),
    },
    {
      accessorKey: "component_type",
      header: ({ column }) => (
        <ComponentsTableSortHeader
          column={column}
          label="Type"
        />
      ),
      cell: ({ row }) => (
        <Badge variant="outline">
          {row.original.component_type}
        </Badge>
      ),
    },
    {
      accessorKey: "publisher",
      header: ({ column }) => (
        <ComponentsTableSortHeader
          column={column}
          label="Publisher"
        />
      ),
      cell: ({ row }) => (
        <span
          className="block max-w-56 truncate"
          title={row.original.publisher || undefined}
        >
          {row.original.publisher || "—"}
        </span>
      ),
    },
    {
      accessorKey: "cpe",
      enableSorting: false,
      header: "Primary CPE",
      cell: ({ row }) => {
        const fields = row.original.cpe_fields
        const readable = fields
          ? `${fields.vendor}:${fields.product}`
          : "Primary CPE"
        return (
          <div className="min-w-72 max-w-96">
            <p className="font-medium">{readable}</p>
            <p
              title={row.original.cpe}
              className="mt-0.5 truncate font-mono text-xs text-muted-foreground"
            >
              {row.original.cpe}
            </p>
          </div>
        )
      },
    },
    {
      id: "part",
      accessorFn: (component) => component.cpe_fields?.part ?? "",
      enableSorting: false,
      header: "Part",
      cell: ({ row }) => {
        const part = row.original.cpe_fields?.part
        return part ? (
          <Badge
            variant="outline"
            title={partDescriptions[part] ?? "CPE part"}
            className="font-mono"
          >
            {part}
          </Badge>
        ) : (
          <span className="text-muted-foreground">—</span>
        )
      },
    },
    {
      accessorKey: "structural_status",
      enableSorting: false,
      header: "Structural Status",
      cell: ({ row }) => (
        <Badge
          variant="outline"
          className={cn(
            "whitespace-nowrap",
            structuralStatusClassName(
              row.original.structural_status,
            ),
          )}
        >
          {row.original.structural_status}
        </Badge>
      ),
    },
  ]
