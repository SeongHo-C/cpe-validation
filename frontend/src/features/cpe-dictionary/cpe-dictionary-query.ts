import type {
  CpeDictionaryPageSize,
  CpeDictionaryQuery,
  CpePart,
  DeprecatedFilter,
} from "@/features/cpe-dictionary/cpe-dictionary-types"

export const DEFAULT_CPE_DICTIONARY_QUERY: CpeDictionaryQuery = {
  q: "",
  part: "",
  vendor: "",
  product: "",
  version: "",
  cpe_name: "",
  deprecated: "active",
  page: 1,
  page_size: 25,
}

function positiveInteger(value: string | null, fallback: number) {
  if (!value) return fallback
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed > 0
    ? parsed
    : fallback
}

export function parseCpeDictionaryUrlQuery(
  parameters: URLSearchParams,
): CpeDictionaryQuery {
  const rawPart = parameters.get("part")
  const part: CpePart =
    rawPart === "a" || rawPart === "o" || rawPart === "h"
      ? rawPart
      : ""
  const rawDeprecated = parameters.get("deprecated")
  const deprecated: DeprecatedFilter =
    rawDeprecated === "all" ||
    rawDeprecated === "deprecated" ||
    rawDeprecated === "active"
      ? rawDeprecated
      : "active"
  const rawPageSize = positiveInteger(
    parameters.get("page_size"),
    25,
  )
  const page_size: CpeDictionaryPageSize =
    rawPageSize === 50 || rawPageSize === 100
      ? rawPageSize
      : 25

  return {
    q: parameters.get("q")?.trim() ?? "",
    part,
    vendor: parameters.get("vendor")?.trim() ?? "",
    product: parameters.get("product")?.trim() ?? "",
    version: parameters.get("version")?.trim() ?? "",
    cpe_name: parameters.get("cpe_name")?.trim() ?? "",
    deprecated,
    page: positiveInteger(parameters.get("page"), 1),
    page_size,
  }
}

export function hasCpeDictionarySearchTerm(
  query: CpeDictionaryQuery,
): boolean {
  return Boolean(
    query.q ||
      query.vendor ||
      query.product ||
      query.version ||
      query.cpe_name,
  )
}

export function writeCpeDictionaryUrlQuery(
  query: CpeDictionaryQuery,
  componentId?: string,
): URLSearchParams {
  const parameters = new URLSearchParams()
  if (componentId) parameters.set("component_id", componentId)
  for (const field of [
    "q",
    "part",
    "vendor",
    "product",
    "version",
    "cpe_name",
  ] as const) {
    if (query[field]) parameters.set(field, query[field])
  }
  parameters.set("deprecated", query.deprecated)
  parameters.set("page", String(query.page))
  parameters.set("page_size", String(query.page_size))
  return parameters
}
