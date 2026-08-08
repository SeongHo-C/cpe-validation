import type { Column } from "@tanstack/react-table"
import {
  ArrowDown,
  ArrowUp,
  ChevronsUpDown,
} from "lucide-react"

import { Button } from "@/components/ui/button"
import type { ComponentSummary } from "@/features/components/components-types"

interface ComponentsTableSortHeaderProps {
  column: Column<ComponentSummary, unknown>
  label: string
  align?: "left" | "center"
}

export function ComponentsTableSortHeader({
  column,
  label,
  align = "left",
}: ComponentsTableSortHeaderProps) {
  const sorted = column.getIsSorted()

  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      className={
        align === "left" ? "-ml-2 h-8 px-2" : "h-8 px-2"
      }
      aria-label={`Sort by ${label}`}
      onClick={() => column.toggleSorting(sorted === "asc")}
    >
      {label}
      {sorted === "asc" ? (
        <ArrowUp aria-hidden="true" />
      ) : sorted === "desc" ? (
        <ArrowDown aria-hidden="true" />
      ) : (
        <ChevronsUpDown aria-hidden="true" />
      )}
    </Button>
  )
}
