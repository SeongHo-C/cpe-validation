import {
  isDictionaryStatus,
} from "@/features/components/dictionary-status"
import type { DictionaryStatus } from "@/features/components/components-types"

export const DEFAULT_COMPONENT_ORDERING = "name"
export const DEFAULT_COMPONENT_PAGE = 1
export const DEFAULT_COMPONENT_PAGE_SIZE = 50

export const componentPageSizes = [25, 50, 100, 200] as const

export const componentOrderings = [
  "name",
  "-name",
  "version",
  "-version",
  "component_type",
  "-component_type",
  "publisher",
  "-publisher",
  "repository",
  "-repository",
  "tag",
  "-tag",
] as const

export type ComponentPageSize =
  (typeof componentPageSizes)[number]
export type ComponentOrdering =
  (typeof componentOrderings)[number]

export interface ComponentsUrlState {
  imageId?: number
  invalidImageId: boolean
  sbomId?: number
  invalidSbomId: boolean
  conflictingScopeFilters: boolean
  componentId?: number
  invalidComponentId: boolean
  search: string
  ordering: ComponentOrdering
  page: number
  pageSize: ComponentPageSize
  dictionaryStatus?: DictionaryStatus
}

function isPositiveInteger(value: string | null): boolean {
  return (
    value !== null &&
    /^[1-9]\d*$/.test(value) &&
    Number.isSafeInteger(Number(value))
  )
}

function isComponentOrdering(
  value: string | null,
): value is ComponentOrdering {
  return (
    value !== null &&
    (componentOrderings as readonly string[]).includes(value)
  )
}

function isComponentPageSize(
  value: number,
): value is ComponentPageSize {
  return (componentPageSizes as readonly number[]).includes(value)
}

export function parseComponentsUrlState(
  searchParameters: URLSearchParams,
): ComponentsUrlState {
  const rawImageId = searchParameters.get("image_id")
  const hasImageId = rawImageId !== null
  const validImageId =
    !hasImageId || isPositiveInteger(rawImageId)
  const rawSbomId = searchParameters.get("sbom_id")
  const hasSbomId = rawSbomId !== null
  const validSbomId = !hasSbomId || isPositiveInteger(rawSbomId)
  const rawComponentId = searchParameters.get("component_id")
  const hasComponentId = rawComponentId !== null
  const validComponentId =
    !hasComponentId || isPositiveInteger(rawComponentId)

  const rawPage = searchParameters.get("page")
  const page = isPositiveInteger(rawPage)
    ? Number(rawPage)
    : DEFAULT_COMPONENT_PAGE

  const rawPageSize = Number(searchParameters.get("page_size"))
  const pageSize = isComponentPageSize(rawPageSize)
    ? rawPageSize
    : DEFAULT_COMPONENT_PAGE_SIZE

  const rawOrdering = searchParameters.get("ordering")
  const ordering = isComponentOrdering(rawOrdering)
    ? rawOrdering
    : DEFAULT_COMPONENT_ORDERING
  const rawDictionaryStatus = searchParameters.get(
    "dictionary_status",
  )

  return {
    imageId:
      hasImageId && validImageId
        ? Number(rawImageId)
        : undefined,
    invalidImageId: hasImageId && !validImageId,
    sbomId:
      hasSbomId && validSbomId
        ? Number(rawSbomId)
        : undefined,
    invalidSbomId: hasSbomId && !validSbomId,
    conflictingScopeFilters: hasImageId && hasSbomId,
    componentId:
      hasComponentId && validComponentId
        ? Number(rawComponentId)
        : undefined,
    invalidComponentId:
      hasComponentId && !validComponentId,
    search: (searchParameters.get("search") ?? "").trim(),
    ordering,
    page,
    pageSize,
    dictionaryStatus: isDictionaryStatus(rawDictionaryStatus)
      ? rawDictionaryStatus
      : undefined,
  }
}

export function canonicalizeComponentsSearch(
  searchParameters: URLSearchParams,
): URLSearchParams {
  const next = new URLSearchParams(searchParameters)
  const state = parseComponentsUrlState(searchParameters)
  const rawPage = searchParameters.get("page")
  const rawPageSize = searchParameters.get("page_size")
  const rawOrdering = searchParameters.get("ordering")
  const rawSearch = searchParameters.get("search")
  const rawDictionaryStatus = searchParameters.get(
    "dictionary_status",
  )

  if (
    rawPage !== null &&
    (!isPositiveInteger(rawPage) ||
      state.page === DEFAULT_COMPONENT_PAGE)
  ) {
    next.delete("page")
  }
  if (
    rawPageSize !== null &&
    (!isComponentPageSize(Number(rawPageSize)) ||
      state.pageSize === DEFAULT_COMPONENT_PAGE_SIZE)
  ) {
    next.delete("page_size")
  }
  if (
    rawOrdering !== null &&
    (!isComponentOrdering(rawOrdering) ||
      state.ordering === DEFAULT_COMPONENT_ORDERING)
  ) {
    next.delete("ordering")
  }
  if (rawSearch !== null) {
    if (state.search) {
      next.set("search", state.search)
    } else {
      next.delete("search")
    }
  }
  if (
    rawDictionaryStatus !== null &&
    !isDictionaryStatus(rawDictionaryStatus)
  ) {
    next.delete("dictionary_status")
  }

  return next
}
