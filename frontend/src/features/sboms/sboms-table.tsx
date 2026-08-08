import { Trash2 } from "lucide-react"
import type { KeyboardEvent } from "react"

import { Button } from "@/components/ui/button"
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
import type { SbomDocumentSummary } from "@/features/sboms/sboms-types"
import { formatDateTime, formatInteger } from "@/lib/format"

function productLabel(sbom: SbomDocumentSummary): string {
  return (
    sbom.product_name ||
    sbom.original_filename ||
    "Untitled SBOM"
  )
}

function formatLabel(sbom: SbomDocumentSummary): string {
  const rawFormat = sbom.format.trim()
  const format =
    rawFormat === "CYCLONEDX_JSON"
      ? "CycloneDX"
      : rawFormat.replaceAll("_", " ") || "Unknown format"
  return [format, sbom.spec_version].filter(Boolean).join(" ") || "—"
}

const columnHeaders = [
  { label: "Manufacturer", className: "text-left" },
  { label: "Product", className: "text-left" },
  { label: "Version", className: "text-center" },
  { label: "Format", className: "text-center" },
  { label: "Components", className: "text-center" },
  {
    label: "Uploaded",
    className: "min-w-36 text-center",
  },
  {
    label: "Actions",
    className: "w-20 min-w-20 text-center",
  },
] as const

const skeletonClassNames = [
  "h-5 w-24",
  "h-5 w-44",
  "h-5 w-24",
  "h-5 w-24",
  "mx-auto h-5 w-12",
  "mx-auto h-5 w-24",
  "mx-auto h-5 w-7",
] as const

interface SbomsTableProps {
  sboms: SbomDocumentSummary[]
  isRefreshing: boolean
  onSelectSbom: (sbomId: number) => void
  onDeleteSbom: (sbom: SbomDocumentSummary) => void
}

export function SbomsTable({
  sboms,
  isRefreshing,
  onSelectSbom,
  onDeleteSbom,
}: SbomsTableProps) {
  return (
    <div
      aria-busy={isRefreshing}
      className={isRefreshing ? "opacity-60" : undefined}
    >
      <Table>
        <TableCaption className="sr-only">
          SBOM inventory
        </TableCaption>
        <TableHeader className="bg-muted/45">
          <TableRow>
            {columnHeaders.map(({ label, className }) => (
              <TableHead key={label} className={className}>
                {label}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {sboms.map((sbom) => {
            const label = productLabel(sbom)
            return (
              <TableRow
                key={sbom.id}
                role="link"
                tabIndex={0}
                aria-label={`View Components for ${label}`}
                className="cursor-pointer outline-none focus-visible:bg-cyan-50 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-600"
                onClick={(event) => {
                  if (
                    event.target instanceof Element &&
                    event.target.closest("button")
                  ) {
                    return
                  }
                  onSelectSbom(sbom.id)
                }}
                onKeyDown={(
                  event: KeyboardEvent<HTMLTableRowElement>,
                ) => {
                  if (
                    event.target === event.currentTarget &&
                    (event.key === "Enter" || event.key === " ")
                  ) {
                    event.preventDefault()
                    onSelectSbom(sbom.id)
                  }
                }}
              >
                <TableCell>{sbom.manufacturer || "—"}</TableCell>
                <TableCell className="min-w-52 font-medium">
                  {label}
                </TableCell>
                <TableCell className="text-center">
                  {sbom.product_version || "—"}
                </TableCell>
                <TableCell className="text-center">
                  {formatLabel(sbom)}
                </TableCell>
                <TableCell className="text-center tabular-nums">
                  {formatInteger(sbom.component_count)}
                </TableCell>
                <TableCell className="text-center tabular-nums">
                  {formatDateTime(sbom.uploaded_at)}
                </TableCell>
                <TableCell className="w-20 min-w-20 text-center">
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    className="text-muted-foreground hover:text-destructive focus-visible:text-destructive"
                    aria-label={`Delete SBOM ${label}`}
                    onClick={(event) => {
                      event.stopPropagation()
                      onDeleteSbom(sbom)
                    }}
                    onKeyDown={(event) => event.stopPropagation()}
                  >
                    <Trash2 aria-hidden="true" />
                  </Button>
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}

export function SbomsTableSkeleton() {
  return (
    <div aria-label="Loading SBOM table">
      <Table>
        <TableCaption className="sr-only">
          Loading SBOM inventory
        </TableCaption>
        <TableHeader className="bg-muted/45">
          <TableRow>
            {columnHeaders.map(({ label, className }) => (
              <TableHead key={label} className={className}>
                {label}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: 8 }, (_, rowIndex) => (
            <TableRow key={rowIndex}>
              {Array.from({ length: 7 }, (_, cellIndex) => (
                <TableCell key={cellIndex}>
                  <Skeleton
                    className={skeletonClassNames[cellIndex]}
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
