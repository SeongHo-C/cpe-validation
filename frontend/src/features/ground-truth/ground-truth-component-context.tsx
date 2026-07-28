import {
  Box,
  Clipboard,
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
          ].map(([label, value]) => {
            const isPurl = label === "PURL"
            return (
              <div
                key={label}
                className={cn(
                  "min-w-0",
                  isPurl &&
                    "col-span-2 max-w-full xl:col-span-4",
                )}
              >
                <dt className="text-xs font-medium text-muted-foreground">
                  {label}
                </dt>
                {isPurl ? (
                  <dd className="mt-1 flex min-w-0 max-w-full items-start gap-2">
                    <code className="min-w-0 max-w-full flex-1 whitespace-normal break-all font-mono text-xs leading-5">
                      {value || "Not provided"}
                    </code>
                    {value ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon-sm"
                        className="shrink-0"
                        aria-label="Copy PURL"
                        onClick={() =>
                          void navigator.clipboard.writeText(value)
                        }
                      >
                        <Clipboard aria-hidden="true" />
                      </Button>
                    ) : null}
                  </dd>
                ) : (
                  <dd
                    className="mt-1 truncate text-sm"
                    title={value || undefined}
                  >
                    {value || "Not provided"}
                  </dd>
                )}
              </div>
            )
          })}
          <div>
            <dt className="text-xs font-medium text-muted-foreground">
              Exact Match
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
