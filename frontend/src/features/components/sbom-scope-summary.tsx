import { FileText, FilterX } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import type { SbomReference } from "@/features/components/components-types"
import { formatInteger } from "@/lib/format"

function sbomLabel(sbomId: number, sbom: SbomReference | null) {
  if (!sbom) return `SBOM #${sbomId}`

  if (sbom.product_name) {
    return [
      sbom.manufacturer,
      sbom.product_name,
      sbom.product_version,
    ]
      .filter(Boolean)
      .join(" ")
  }
  return sbom.original_filename || `SBOM #${sbom.id}`
}

interface SbomScopeSummaryProps {
  sbomId: number
  sbom: SbomReference | null
  componentCount?: number
  onClearSbomFilter: () => void
}

export function SbomScopeSummary({
  sbomId,
  sbom,
  componentCount,
  onClearSbomFilter,
}: SbomScopeSummaryProps) {
  return (
    <Card>
      <CardHeader className="sm:grid-cols-[1fr_auto]">
        <div>
          <CardTitle className="flex items-center gap-2">
            <FileText
              className="size-4 text-cyan-700"
              aria-hidden="true"
            />
            {sbomLabel(sbomId, sbom)}
          </CardTitle>
          <p className="mt-1 text-sm text-muted-foreground">
            Components from the selected SBOM document.
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="mt-3 sm:mt-0"
          onClick={onClearSbomFilter}
        >
          <FilterX aria-hidden="true" />
          Clear SBOM filter
        </Button>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <div className="rounded-lg border bg-muted/30 px-3 py-2.5">
            <dt className="text-xs text-muted-foreground">
              Primary CPE Components
            </dt>
            <dd className="mt-1 font-heading text-base font-semibold">
              {componentCount === undefined
                ? "Loading"
                : formatInteger(componentCount)}
            </dd>
          </div>
          <div className="rounded-lg border bg-muted/30 px-3 py-2.5">
            <dt className="text-xs text-muted-foreground">
              SBOM document
            </dt>
            <dd className="mt-1 font-heading text-base font-semibold">
              #{sbomId}
            </dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  )
}
