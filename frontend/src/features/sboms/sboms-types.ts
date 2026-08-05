import type { PaginatedResponse } from "@/lib/api-types"

export interface SbomDocumentSummary {
  id: number
  manufacturer: string
  product_name: string
  product_version: string
  original_filename: string
  format: string
  spec_version: string
  generator_name: string
  generator_version: string
  component_count: number
  uploaded_at: string
}

export interface SbomsQuery {
  page: number
  page_size: SbomPageSize
}

export type SbomPage = PaginatedResponse<SbomDocumentSummary>

export const sbomPageSizes = [25, 50, 100, 200] as const
export type SbomPageSize = (typeof sbomPageSizes)[number]
