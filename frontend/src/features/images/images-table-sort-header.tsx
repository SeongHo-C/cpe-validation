import type { Column } from "@tanstack/react-table"
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
} from "lucide-react"

import { Button } from "@/components/ui/button"
import type { DockerImageSummary } from "@/features/images/images-types"

interface ImagesTableSortHeaderProps {
  column: Column<DockerImageSummary>
  label: string
}

export function ImagesTableSortHeader({
  column,
  label,
}: ImagesTableSortHeaderProps) {
  const direction = column.getIsSorted()
  const SortIcon =
    direction === "asc"
      ? ArrowUp
      : direction === "desc"
        ? ArrowDown
        : ArrowUpDown

  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      className="-ml-2 h-8"
      onClick={column.getToggleSortingHandler()}
      aria-label={`Sort by ${label}`}
    >
      {label}
      <SortIcon className="size-3.5" aria-hidden="true" />
    </Button>
  )
}
