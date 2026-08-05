import { ChevronRight } from "lucide-react"
import type { KeyboardEvent } from "react"

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

interface SbomsTableProps {
  sboms: SbomDocumentSummary[]
  isRefreshing: boolean
  onSelectSbom: (sbomId: number) => void
}

export function SbomsTable({
  sboms,
  isRefreshing,
  onSelectSbom,
}: SbomsTableProps) {
  return (
    <div
      aria-busy={isRefreshing}
      className={isRefreshing ? "opacity-60" : undefined}
    >
      <Table>
        <TableCaption className="sr-only">
          SBOM documents available for CPE validation
        </TableCaption>
        <TableHeader className="bg-muted/45">
          <TableRow>
            {[
              "Manufacturer",
              "Product",
              "Version",
              "Format",
              "Components",
              "Uploaded",
            ].map((label) => (
              <TableHead key={label}>{label}</TableHead>
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
                onClick={() => onSelectSbom(sbom.id)}
                onKeyDown={(
                  event: KeyboardEvent<HTMLTableRowElement>,
                ) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault()
                    onSelectSbom(sbom.id)
                  }
                }}
              >
                <TableCell>{sbom.manufacturer || "—"}</TableCell>
                <TableCell>
                  <div className="flex min-w-52 items-center gap-3">
                    <span className="min-w-0 flex-1 truncate font-medium">
                      {label}
                    </span>
                    <ChevronRight
                      className="size-4 shrink-0 text-muted-foreground"
                      aria-hidden="true"
                    />
                  </div>
                </TableCell>
                <TableCell>{sbom.product_version || "—"}</TableCell>
                <TableCell>{formatLabel(sbom)}</TableCell>
                <TableCell>
                  {formatInteger(sbom.component_count)}
                </TableCell>
                <TableCell>{formatDateTime(sbom.uploaded_at)}</TableCell>
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
            {[
              "Manufacturer",
              "Product",
              "Version",
              "Format",
              "Components",
              "Uploaded",
            ].map((label) => (
              <TableHead key={label}>{label}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: 8 }, (_, rowIndex) => (
            <TableRow key={rowIndex}>
              {Array.from({ length: 6 }, (_, cellIndex) => (
                <TableCell key={cellIndex}>
                  <Skeleton
                    className={
                      cellIndex === 1
                        ? "h-5 w-44"
                        : "h-5 w-24"
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
