import {
  Box,
  Search,
  TriangleAlert,
} from "lucide-react"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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

type FillField = "q" | "product"

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

function purlPackageName(purl: string): string | null {
  if (!purl.startsWith("pkg:")) return null
  const path = purl
    .slice(4)
    .split(/[?#]/, 1)[0]
    ?.split("@", 1)[0]
  const encodedName = path?.split("/").at(-1)
  if (!encodedName) return null
  try {
    return decodeURIComponent(encodedName)
  } catch {
    return null
  }
}

export function CpeDictionaryComponentContext({
  detail,
  loading,
  error,
  onFill,
}: {
  detail: ComponentDetail | null
  loading: boolean
  error: string | null
  onFill: (field: FillField, value: string) => void
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

  const purlName = purlPackageName(detail.purl)
  const relevantProperties = detail.properties.filter((property) =>
    relevantPropertyTerms.some((term) =>
      property.name.toLowerCase().includes(term),
    ),
  )
  const conveniences = [
    detail.name
      ? {
          label: "Use component name",
          field: "q" as const,
          value: detail.name,
        }
      : null,
    detail.cpe_fields?.product
      ? {
          label: "Use existing CPE product",
          field: "product" as const,
          value: detail.cpe_fields.product,
        }
      : null,
    purlName
      ? {
          label: "Use PURL package name",
          field: "q" as const,
          value: purlName,
        }
      : null,
    detail.publisher
      ? {
          label: "Use publisher",
          field: "q" as const,
          value: detail.publisher,
        }
      : null,
  ].filter((item) => item !== null)

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
        <dl className="grid grid-cols-4 gap-x-5 gap-y-3">
          {[
            ["Name", detail.name],
            ["Version", detail.version],
            ["Group", detail.group],
            ["Publisher", detail.publisher],
            ["Type", detail.component_type],
            ["PURL", detail.purl],
            [
              "Docker image",
              `${detail.image.repository}:${detail.image.tag}`,
            ],
            [
              "SBOM document",
              `${detail.sbom_document.id} · ${detail.sbom_document.source_path}`,
            ],
            ["Primary CPE", detail.cpe],
          ].map(([label, value]) => (
            <div key={label} className="min-w-0">
              <dt className="text-xs font-medium text-muted-foreground">
                {label}
              </dt>
              <dd
                className="mt-1 truncate text-sm"
                title={value || undefined}
              >
                {value || "Not provided"}
              </dd>
            </div>
          ))}
          <div>
            <dt className="text-xs font-medium text-muted-foreground">
              Dictionary status
            </dt>
            <dd className="mt-1">
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
        </dl>

        {conveniences.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {conveniences.map((item) => (
              <Button
                key={item.label}
                type="button"
                variant="outline"
                size="sm"
                onClick={() => onFill(item.field, item.value)}
              >
                <Search aria-hidden="true" />
                {item.label}
              </Button>
            ))}
          </div>
        ) : null}

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
