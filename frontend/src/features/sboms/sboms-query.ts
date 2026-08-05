import { getJson } from "@/lib/api-client"
import type {
  SbomPage,
  SbomsQuery,
} from "@/features/sboms/sboms-types"

export const DEFAULT_SBOM_PAGE = 1
export const DEFAULT_SBOM_PAGE_SIZE = 50

export function buildSbomsApiUrl(query: SbomsQuery): string {
  const parameters = new URLSearchParams({
    page: String(query.page),
    page_size: String(query.page_size),
  })
  return `/api/sboms/?${parameters.toString()}`
}

export function getSboms(
  query: SbomsQuery,
  signal?: AbortSignal,
): Promise<SbomPage> {
  return getJson<SbomPage>(buildSbomsApiUrl(query), { signal })
}
