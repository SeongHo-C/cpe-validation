import { getJson } from "@/lib/api-client"

import type {
  ComponentDetail,
  ComponentsQuery,
  ComponentSummary,
  DockerImageDetail,
  PaginatedResponse,
} from "@/features/components/components-types"

export function buildComponentsApiUrl(
  parameters: ComponentsQuery,
): string {
  const searchParameters = new URLSearchParams()
  searchParameters.set(
    "has_cpe",
    parameters.dictionary_status === "NOT_PRESENT"
      ? "false"
      : "true",
  )

  if (parameters.image_id !== undefined) {
    searchParameters.set("image_id", String(parameters.image_id))
  }
  const normalizedSearch = parameters.search?.trim()
  if (normalizedSearch) {
    searchParameters.set("search", normalizedSearch)
  }
  if (parameters.ordering) {
    searchParameters.set("ordering", parameters.ordering)
  }
  if (parameters.page !== undefined) {
    searchParameters.set("page", String(parameters.page))
  }
  if (parameters.page_size !== undefined) {
    searchParameters.set(
      "page_size",
      String(parameters.page_size),
    )
  }
  if (parameters.dictionary_status !== undefined) {
    searchParameters.set(
      "dictionary_status",
      parameters.dictionary_status,
    )
  }

  return `/api/components/?${searchParameters.toString()}`
}

export function getComponents(
  parameters: ComponentsQuery,
  signal?: AbortSignal,
): Promise<PaginatedResponse<ComponentSummary>> {
  return getJson<PaginatedResponse<ComponentSummary>>(
    buildComponentsApiUrl(parameters),
    { signal },
  )
}

export function getDockerImageDetail(
  imageId: number,
  signal?: AbortSignal,
): Promise<DockerImageDetail> {
  return getJson<DockerImageDetail>(
    `/api/images/${imageId}/`,
    { signal },
  )
}

export function getComponentDetail(
  componentId: number,
  signal?: AbortSignal,
): Promise<ComponentDetail> {
  return getJson<ComponentDetail>(
    `/api/components/${componentId}/`,
    { signal },
  )
}
