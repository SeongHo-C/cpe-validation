import {
  deleteNoContent,
  getJson,
  postFormData,
} from "@/lib/api-client"
import type {
  SbomDocumentDetail,
  SbomPage,
  SbomsQuery,
  UploadSbomInput,
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

export function uploadSbom(
  input: UploadSbomInput,
  signal?: AbortSignal,
): Promise<SbomDocumentDetail> {
  const formData = new FormData()
  formData.append("file", input.file)
  if (input.manufacturer) {
    formData.append("manufacturer", input.manufacturer)
  }
  if (input.productName) {
    formData.append("product_name", input.productName)
  }
  if (input.productVersion) {
    formData.append("product_version", input.productVersion)
  }
  return postFormData<SbomDocumentDetail>(
    "/api/sboms/upload/",
    formData,
    { signal },
  )
}

export function deleteSbom(
  sbomId: number,
  signal?: AbortSignal,
): Promise<void> {
  return deleteNoContent(`/api/sboms/${sbomId}/`, { signal })
}
