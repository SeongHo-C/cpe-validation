import { Badge } from "@/components/ui/badge"
import type {
  ComponentDetail,
  ComponentProperty,
  DictionaryStatus,
} from "@/features/components/components-types"
import { formatInteger } from "@/lib/format"
import { cn } from "@/lib/utils"

const cpeFieldNames = [
  "part",
  "vendor",
  "product",
  "version",
  "update",
  "edition",
  "language",
  "sw_edition",
  "target_sw",
  "target_hw",
  "other",
] as const

function statusClassName(status: string): string {
  if (status === "STRUCTURALLY_VALID") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700"
  }
  if (status === "NOT_PRESENT") {
    return "border-border bg-muted text-muted-foreground"
  }
  return "border-red-200 bg-red-50 text-red-700"
}

const dictionaryStatusPresentation: Record<
  DictionaryStatus,
  {
    title: string
    badge: string
    description: string
    className: string
  }
> = {
  OFFICIAL_ACTIVE: {
    title: "Official Dictionary Match",
    badge: "Active",
    description:
      "The raw CPE string exactly matches an active entry in the selected NVD CPE Dictionary snapshot.",
    className:
      "border-emerald-200 bg-emerald-50 text-emerald-700",
  },
  OFFICIAL_DEPRECATED: {
    title: "Official Dictionary Match",
    badge: "Deprecated",
    description:
      "The raw CPE string exactly matches a deprecated entry in the selected NVD CPE Dictionary snapshot.",
    className:
      "border-amber-200 bg-amber-50 text-amber-700",
  },
  NOT_IN_DICTIONARY: {
    title: "Not Found in Dictionary",
    badge: "No raw-string match",
    description:
      "No identical raw CPE string was found in the selected NVD CPE Dictionary snapshot.",
    className: "border-slate-200 bg-slate-50 text-slate-700",
  },
  NOT_PRESENT: {
    title: "Primary CPE Not Present",
    badge: "Not present",
    description:
      "This SBOM Component does not provide a Primary CPE to compare.",
    className: "border-border bg-muted text-muted-foreground",
  },
}

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
  const syftCandidates = detail.properties.filter(
    (property) => property.name === "syft:cpe23",
  )
  const otherProperties = detail.properties.filter(
    (property) => property.name !== "syft:cpe23",
  )
  const cpeFields = detail.cpe_fields
  const dictionaryPresentation =
    dictionaryStatusPresentation[detail.dictionary_status]

  return (
    <div className="space-y-6 p-4">
      <DetailSection title="Status Summary">
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-lg border bg-muted/20 p-3">
            <p className="text-xs text-muted-foreground">
              Structural Status
            </p>
            <Badge
              variant="outline"
              className={cn(
                "mt-2",
                statusClassName(detail.structural_status),
              )}
            >
              {detail.structural_status}
            </Badge>
          </div>
          <div className="rounded-lg border bg-muted/20 p-3">
            <p className="text-xs text-muted-foreground">
              Primary CPE
            </p>
            <Badge variant="secondary" className="mt-2">
              {detail.cpe ? "Present" : "Not present"}
            </Badge>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">
              {detail.cpe
                ? "A Primary CPE is present in the SBOM Component."
                : "No Primary CPE is present in the SBOM Component."}
            </p>
          </div>
        </div>
      </DetailSection>

      <DetailSection title="Component Metadata">
        <EvidenceGrid
          fields={[
            { label: "Name", value: detail.name },
            { label: "Version", value: detail.version, monospace: true },
            { label: "Type", value: detail.component_type },
            { label: "Publisher", value: detail.publisher },
            { label: "PURL", value: detail.purl, monospace: true },
            { label: "bom-ref", value: detail.bom_ref, monospace: true },
            {
              label: "Docker repository",
              value: detail.image.repository,
              monospace: true,
            },
            {
              label: "Docker tag",
              value: detail.image.tag,
              monospace: true,
            },
            {
              label: "SBOM document id",
              value: String(detail.sbom_document_id),
              monospace: true,
            },
          ]}
        />
      </DetailSection>

      <DetailSection title="Primary CPE">
        {detail.cpe ? (
          <div className="space-y-3">
            <div className="rounded-lg border bg-muted/20 px-3 py-2.5">
              <p className="text-xs font-medium text-muted-foreground">
                Raw CPE
              </p>
              <p className="mt-1 break-all font-mono text-xs leading-5">
                {detail.cpe}
              </p>
            </div>
            {cpeFields ? (
              <EvidenceGrid
                fields={[
                  {
                    label: "part",
                    value: cpeFields.part,
                    monospace: true,
                  },
                  {
                    label: "vendor",
                    value: cpeFields.vendor,
                    monospace: true,
                  },
                  {
                    label: "product",
                    value: cpeFields.product,
                    monospace: true,
                  },
                  {
                    label: "version",
                    value: cpeFields.version,
                    monospace: true,
                  },
                ]}
              />
            ) : null}
          </div>
        ) : (
          <p className="rounded-lg border bg-muted/20 p-3 text-sm text-muted-foreground">
            No primary CPE
          </p>
        )}
      </DetailSection>

      <DetailSection title="CPE 2.3 Fields">
        {cpeFields ? (
          <EvidenceGrid
            fields={cpeFieldNames.map((fieldName) => ({
              label: fieldName,
              value: cpeFields[fieldName],
              monospace: true,
            }))}
          />
        ) : (
          <p className="rounded-lg border bg-muted/20 p-3 text-sm text-muted-foreground">
            CPE fields are not available.
          </p>
        )}
      </DetailSection>

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

      <DetailSection title="Exact Match">
        <div className="space-y-3 rounded-lg border bg-muted/20 p-3">
          <div>
            <p className="text-sm font-medium">
              {dictionaryPresentation.title}
            </p>
            <Badge
              variant="outline"
              className={cn(
                "mt-2",
                dictionaryPresentation.className,
              )}
            >
              {dictionaryPresentation.badge}
            </Badge>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              {dictionaryPresentation.description}
            </p>
          </div>
          <EvidenceGrid
            fields={[
              {
                label: "Snapshot ID",
                value: detail.dictionary_match.snapshot_id,
                monospace: true,
              },
              ...(detail.dictionary_match.cpe_name_id
                ? [
                    {
                      label: "NVD CPE UUID",
                      value:
                        detail.dictionary_match.cpe_name_id,
                      monospace: true,
                    },
                  ]
                : []),
              ...(detail.dictionary_match.deprecated !== null
                ? [
                    {
                      label: "Deprecated",
                      value: detail.dictionary_match.deprecated
                        ? "Yes"
                        : "No",
                    },
                  ]
                : []),
            ]}
          />
          <p className="text-xs leading-5 text-muted-foreground">
            Dictionary exact match is automated evidence and does not
            establish semantic correctness for this component.
          </p>
        </div>
      </DetailSection>

      <DetailSection title="Syft CPE Candidates">
        <p className="text-xs text-muted-foreground">
          {formatInteger(syftCandidates.length)} candidate
          {syftCandidates.length === 1 ? "" : "s"}
        </p>
        {syftCandidates.length > 0 ? (
          <PropertyList
            properties={syftCandidates}
            primaryCpe={detail.cpe}
            candidates
          />
        ) : (
          <p className="rounded-lg border bg-muted/20 p-3 text-sm text-muted-foreground">
            No `syft:cpe23` candidate properties were found.
          </p>
        )}
      </DetailSection>

      <DetailSection title="Other SBOM Properties">
        {otherProperties.length > 0 ? (
          <PropertyList
            properties={otherProperties}
            primaryCpe={detail.cpe}
          />
        ) : (
          <p className="rounded-lg border bg-muted/20 p-3 text-sm text-muted-foreground">
            No other SBOM properties were found.
          </p>
        )}
      </DetailSection>

      <DetailSection title="SBOM Source">
        <EvidenceGrid
          fields={[
            {
              label: "Source path",
              value: detail.sbom_document.source_path,
              monospace: true,
            },
            {
              label: "Spec version",
              value: detail.sbom_document.spec_version,
              monospace: true,
            },
            {
              label: "Generator name",
              value: detail.sbom_document.generator_name,
            },
            {
              label: "Generator version",
              value: detail.sbom_document.generator_version,
              monospace: true,
            },
            {
              label: "Source type",
              value: detail.sbom_document.source_type,
            },
            {
              label: "Scope",
              value: detail.sbom_document.scope,
            },
            {
              label: "Document id",
              value: String(detail.sbom_document.id),
              monospace: true,
            },
          ]}
        />
      </DetailSection>
    </div>
  )
}
