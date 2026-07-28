import {
  getJson,
  putJson,
} from "@/lib/api-client"

import type {
  CpeDictionaryDetail,
  CpeDictionaryQuery,
  CpeDictionarySearchResponse,
  CpeDictionarySnapshot,
  ComponentCpeGroundTruthResponse,
  ComponentCpeGroundTruthWrite,
} from "@/features/cpe-dictionary/cpe-dictionary-types"

export function buildCpeDictionaryApiUrl(
  query: CpeDictionaryQuery,
): string {
  const parameters = new URLSearchParams()
  for (const name of [
    "q",
    "part",
    "vendor",
    "product",
    "version",
    "cpe_name",
  ] as const) {
    if (query[name]) parameters.set(name, query[name])
  }
  parameters.set("deprecated", query.deprecated)
  parameters.set("page", String(query.page))
  parameters.set("page_size", String(query.page_size))
  return `/api/cpe-dictionary/?${parameters.toString()}`
}

export function getCpeDictionaryResults(
  query: CpeDictionaryQuery,
  signal?: AbortSignal,
): Promise<CpeDictionarySearchResponse> {
  return getJson<CpeDictionarySearchResponse>(
    buildCpeDictionaryApiUrl(query),
    { signal },
  )
}

export function getCpeDictionarySnapshot(
  signal?: AbortSignal,
): Promise<CpeDictionarySnapshot> {
  return getJson<CpeDictionarySnapshot>(
    "/api/cpe-dictionary/snapshot/",
    { signal },
  )
}

export function getCpeDictionaryDetail(
  cpeNameId: string,
  signal?: AbortSignal,
): Promise<CpeDictionaryDetail> {
  return getJson<CpeDictionaryDetail>(
    `/api/cpe-dictionary/${encodeURIComponent(cpeNameId)}/`,
    { signal },
  )
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
