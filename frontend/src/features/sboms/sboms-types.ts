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

export interface SbomDocumentDetail extends SbomDocumentSummary {
  file_sha256: string
  serial_number: string
  document_version: number
  generated_at: string | null
  source_artifact: SourceArtifactMetadata | null
}

export interface SourceArtifactMetadata {
  id: number
  original_filename: string
  file_sha256: string
  size: number
  uploaded_at: string
  stored_path: string
}

export interface UploadSbomInput {
  file: File
  sourceArchive?: File | null
  manufacturer: string
  productName: string
  productVersion: string
}

export interface SbomsQuery {
  page: number
  page_size: SbomPageSize
}

export type SbomPage = PaginatedResponse<SbomDocumentSummary>

export const sbomPageSizes = [25, 50, 100, 200] as const
export type SbomPageSize = (typeof sbomPageSizes)[number]
