import { ChevronRight } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import type {
  ComponentDetail,
  ComponentProperty,
} from "@/features/components/components-types"
import { cn } from "@/lib/utils"

function DetailSection({
  title,
  description,
  children,
}: {
  title: string
  description?: string
  children: React.ReactNode
}) {
  return (
    <section className="space-y-3">
      <div>
        <h3 className="font-heading text-sm font-semibold">
          {title}
        </h3>
        {description ? (
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            {description}
          </p>
        ) : null}
      </div>
      {children}
    </section>
  )
}

function EvidenceValue({
  children,
  monospace = false,
}: {
  children: React.ReactNode
  monospace?: boolean
}) {
  return (
    <dd
      className={cn(
        "mt-1 break-all text-sm text-foreground",
        monospace && "font-mono text-xs leading-5",
      )}
    >
      {children}
    </dd>
  )
}

function EvidenceGrid({
  fields,
}: {
  fields: Array<{
    label: string
    value: React.ReactNode
    monospace?: boolean
  }>
}) {
  return (
    <dl className="grid grid-cols-1 gap-3">
      {fields.map((field) => (
        <div
          key={field.label}
          className="min-w-0 rounded-lg border bg-muted/20 px-3 py-2.5"
        >
          <dt className="text-xs font-medium text-muted-foreground">
            {field.label}
          </dt>
          <EvidenceValue monospace={field.monospace}>
            {field.value || "Not provided"}
          </EvidenceValue>
        </div>
      ))}
    </dl>
  )
}

function PropertyList({
  properties,
  primaryCpe,
  candidates = false,
}: {
  properties: ComponentProperty[]
  primaryCpe: string
  candidates?: boolean
}) {
  return (
    <ol className="space-y-2">
      {properties.map((property, index) => (
        <li
          key={`${property.name}-${index}`}
          className="rounded-lg border bg-muted/20 px-3 py-2.5"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-muted-foreground">
              {candidates
                ? `Candidate ${index + 1}`
                : property.name}
            </span>
            {candidates &&
            property.value === primaryCpe ? (
              <Badge
                variant="outline"
                className="border-cyan-200 bg-cyan-50 text-cyan-700"
              >
                Same as primary
              </Badge>
            ) : null}
          </div>
          <p className="mt-1 break-all font-mono text-xs leading-5">
            {property.value}
          </p>
        </li>
      ))}
    </ol>
  )
}

export function ComponentDetailContent({
  detail,
}: {
  detail: ComponentDetail
}) {
  const otherProperties = detail.properties.filter(
    (property) => property.name !== "syft:cpe23",
  )
  const showStructuralValidation =
    detail.structural_status !== "STRUCTURALLY_VALID" ||
    detail.structural_error_message !== null
  const evidenceLabelId = `additional-sbom-evidence-${detail.id}`

  return (
    <div className="space-y-6 p-4">
      <DetailSection title="Component Metadata">
        <EvidenceGrid
          fields={[
            { label: "Version", value: detail.version, monospace: true },
            { label: "Publisher", value: detail.publisher },
            { label: "PURL", value: detail.purl, monospace: true },
          ]}
        />
      </DetailSection>

      <DetailSection title="Primary CPE">
        {detail.cpe ? (
          <div className="rounded-lg border bg-muted/20 px-3 py-2.5">
            <p className="text-xs font-medium text-muted-foreground">
              Raw CPE
            </p>
            <p className="mt-1 break-all font-mono text-xs leading-5">
              {detail.cpe}
            </p>
          </div>
        ) : (
          <p className="rounded-lg border bg-muted/20 p-3 text-sm text-muted-foreground">
            No primary CPE
          </p>
        )}
      </DetailSection>

      {showStructuralValidation ? (
        <DetailSection
          title="Structural Validation"
          description="Checks the CPE 2.3 formatted-string structure only."
        >
          <EvidenceGrid
            fields={[
              {
                label: "Structural status",
                value: detail.structural_status,
              },
              {
                label: "Parser result",
                value:
                  detail.structural_error_message ??
                  "No structural issues detected by the formatted-string parser.",
              },
            ]}
          />
        </DetailSection>
      ) : null}

      <section aria-labelledby={evidenceLabelId}>
        <details
          key={detail.id}
          className="group rounded-lg border bg-muted/20"
        >
          <summary className="flex cursor-pointer list-none items-center gap-2 rounded-lg px-3 py-2.5 outline-none focus-visible:ring-2 focus-visible:ring-cyan-600 [&::-webkit-details-marker]:hidden">
            <span
              id={evidenceLabelId}
              className="font-heading text-sm font-semibold"
            >
              Additional SBOM Evidence
            </span>
            <span className="ml-auto text-xs text-muted-foreground">
              {otherProperties.length}{" "}
              {otherProperties.length === 1
                ? "property"
                : "properties"}
            </span>
            <ChevronRight
              className="size-4 text-muted-foreground transition-transform group-open:rotate-90"
              aria-hidden="true"
            />
          </summary>
          <div className="border-t px-3 py-3">
            {otherProperties.length > 0 ? (
              <PropertyList
                properties={otherProperties}
                primaryCpe={detail.cpe}
              />
            ) : (
              <p className="text-sm text-muted-foreground">
                No additional SBOM evidence was found.
              </p>
            )}
          </div>
        </details>
      </section>
    </div>
  )
}
