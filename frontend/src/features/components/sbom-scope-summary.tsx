import { FileText, FilterX } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Card,
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
  const componentCountLabel =
    componentCount === undefined
      ? "Loading Primary CPE component count"
      : `${formatInteger(componentCount)} Primary CPE ${
          componentCount === 1 ? "component" : "components"
        }`

  return (
    <Card className="gap-0 py-3">
      <CardHeader className="sm:grid-cols-[1fr_auto] sm:items-center">
        <div className="min-w-0">
          <CardTitle className="flex items-center gap-2">
            <FileText
              className="size-4 text-cyan-700"
              aria-hidden="true"
            />
            {sbomLabel(sbomId, sbom)}
          </CardTitle>
          <p className="mt-1 text-sm font-medium text-muted-foreground">
            {componentCountLabel}
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
    </Card>
  )
}
