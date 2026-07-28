import {
  Box,
  TriangleAlert,
} from "lucide-react"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import type { ComponentDetail } from "@/features/components/components-types"
import {
  dictionaryStatusClassName,
  dictionaryStatusLabels,
} from "@/features/components/dictionary-status"
import { cn } from "@/lib/utils"

const relevantPropertyTerms = [
  "source",
  "upstream",
  "package",
  "manager",
  "type",
  "ecosystem",
  "foundby",
  "cpe",
  "location",
  "path",
]

function MetadataField({
  label,
  value,
  className,
  wrap = false,
  monospace = false,
}: {
  label: string
  value: string
  className: string
  wrap?: boolean
  monospace?: boolean
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <dt className="text-xs font-medium text-muted-foreground">
        {label}
      </dt>
      <dd
        className={cn(
          "mt-1 text-sm",
          wrap
            ? "min-w-0 max-w-full whitespace-normal break-all"
            : "truncate",
          monospace && "font-mono text-xs leading-5",
        )}
        title={wrap ? undefined : value || undefined}
      >
        {value || "Not provided"}
      </dd>
    </div>
  )
}

export function GroundTruthComponentContext({
  detail,
  loading,
  error,
}: {
  detail: ComponentDetail | null
  loading: boolean
  error: string | null
}) {
  if (loading) {
    return (
      <Card aria-busy="true">
        <CardContent className="text-sm text-muted-foreground">
          Loading Component context…
        </CardContent>
      </Card>
    )
  }
  if (error) {
    return (
      <Alert variant="destructive">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>Component context unavailable</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    )
  }
  if (!detail) return null

  const relevantProperties = detail.properties.filter((property) =>
    relevantPropertyTerms.some((term) =>
      property.name.toLowerCase().includes(term),
    ),
  )
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Box className="size-4 text-cyan-700" aria-hidden="true" />
          <CardTitle>Component context</CardTitle>
          <Badge variant="outline">Read only</Badge>
        </div>
        <CardDescription>
          Compare this SBOM evidence with Dictionary records. No
          result is applied automatically.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <dl
          className="grid min-w-0 grid-cols-1 gap-x-6 gap-y-4 md:grid-cols-2 xl:grid-cols-12"
          data-testid="component-context-metadata-grid"
        >
          <MetadataField
            label="Name"
            value={detail.name}
            className="xl:col-span-3"
          />
          <MetadataField
            label="Version"
            value={detail.version}
            className="xl:col-span-3"
          />
          <MetadataField
            label="Group"
            value={detail.group}
            className="xl:col-span-3"
          />
          <MetadataField
            label="Publisher"
            value={detail.publisher}
            className="xl:col-span-3"
          />
          <MetadataField
            label="Type"
            value={detail.component_type}
            className="xl:col-span-3"
          />
          <MetadataField
            label="Docker image"
            value={`${detail.image.repository}:${detail.image.tag}`}
            className="xl:col-span-3"
          />
          <MetadataField
            label="SBOM document"
            value={`${detail.sbom_document.id} · ${detail.sbom_document.source_path}`}
            className="xl:col-span-3"
          />
          <div className="min-w-0 xl:col-span-3">
            <dt className="text-xs font-medium text-muted-foreground">
              Exact Match
            </dt>
            <dd className="mt-1 text-sm">
              <Badge
                variant="outline"
                className={cn(
                  dictionaryStatusClassName(
                    detail.dictionary_status,
                  ),
                )}
              >
                {dictionaryStatusLabels[detail.dictionary_status]}
              </Badge>
            </dd>
          </div>
          <MetadataField
            label="Primary CPE"
            value={detail.cpe}
            className="md:col-span-2 xl:col-span-6"
            wrap
            monospace
          />
          <MetadataField
            label="PURL"
            value={detail.purl}
            className="md:col-span-2 xl:col-span-6"
            wrap
            monospace
          />
        </dl>

        {relevantProperties.length > 0 ? (
          <details className="rounded-lg border bg-muted/20 px-3 py-2">
            <summary className="cursor-pointer text-sm font-medium">
              Relevant package properties (
              {relevantProperties.length})
            </summary>
            <dl className="mt-3 space-y-2">
              {relevantProperties.map((property, index) => (
                <div key={`${property.name}-${index}`}>
                  <dt className="text-xs text-muted-foreground">
                    {property.name}
                  </dt>
                  <dd className="break-all font-mono text-xs">
                    {property.value}
                  </dd>
                </div>
              ))}
            </dl>
          </details>
        ) : null}
      </CardContent>
    </Card>
  )
}
