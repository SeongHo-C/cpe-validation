import type { PaginatedResponse } from "@/features/components/components-types"
import type {
  ComponentCpeGroundTruthResponse,
  ComponentCpeGroundTruthWrite,
  GroundTruthComponentSummary,
  GroundTruthListQuery,
  GroundTruthNavigation,
} from "@/features/ground-truth/ground-truth-types"
import {
  getJson,
  putJson,
} from "@/lib/api-client"

export function buildGroundTruthListApiUrl(
  query: GroundTruthListQuery,
): string {
  const parameters = new URLSearchParams()
  if (query.image_id !== undefined) {
    parameters.set("image_id", String(query.image_id))
  }
  if (query.ground_truth_status) {
    parameters.set(
      "ground_truth_status",
      query.ground_truth_status,
    )
  }
  if (query.dictionary_status) {
    parameters.set(
      "dictionary_status",
      query.dictionary_status,
    )
  }
  if (query.search?.trim()) {
    parameters.set("search", query.search.trim())
  }
  parameters.set("ordering", query.ordering)
  parameters.set("page", String(query.page))
  parameters.set("page_size", String(query.page_size))
  return `/api/ground-truth/components/?${parameters.toString()}`
}

export function getGroundTruthComponents(
  query: GroundTruthListQuery,
  signal?: AbortSignal,
): Promise<PaginatedResponse<GroundTruthComponentSummary>> {
  return getJson<
    PaginatedResponse<GroundTruthComponentSummary>
  >(buildGroundTruthListApiUrl(query), { signal })
}

export function getComponentCpeGroundTruth(
  componentId: number,
  signal?: AbortSignal,
): Promise<ComponentCpeGroundTruthResponse> {
  return getJson<ComponentCpeGroundTruthResponse>(
    `/api/components/${componentId}/cpe-ground-truth/`,
    { signal },
  )
}

export function putComponentCpeGroundTruth(
  componentId: number,
  payload: ComponentCpeGroundTruthWrite,
  signal?: AbortSignal,
): Promise<ComponentCpeGroundTruthResponse> {
  return putJson<ComponentCpeGroundTruthResponse>(
    `/api/components/${componentId}/cpe-ground-truth/`,
    payload,
    { signal },
  )
}

export function getGroundTruthNavigation(
  componentId: number,
  query: GroundTruthListQuery,
  signal?: AbortSignal,
): Promise<GroundTruthNavigation> {
  const listUrl = new URL(
    buildGroundTruthListApiUrl(query),
    "http://local.invalid",
  )
  listUrl.searchParams.delete("page")
  listUrl.searchParams.delete("page_size")
  return getJson<GroundTruthNavigation>(
    `/api/ground-truth/components/${componentId}/navigation/?${listUrl.searchParams.toString()}`,
    { signal },
  )
}
