export interface ComponentImageReference {
  id: number
  repository: string
  tag: string
}

export interface CpeFields {
  part: string
  vendor: string
  product: string
  version: string
  update: string
  edition: string
  language: string
  sw_edition: string
  target_sw: string
  target_hw: string
  other: string
}

export interface ComponentSummary {
  id: number
  image: ComponentImageReference
  sbom_document_id: number
  component_type: string
  name: string
  version: string
  publisher: string
  purl: string
  cpe: string
  structural_status: string
  cpe_fields: CpeFields | null
}

export interface PaginatedResponse<T> {
  count: number
  page: number
  page_size: number
  total_pages: number
  next: string | null
  previous: string | null
  results: T[]
}

export interface DockerImageDetail {
  id: number
  repository: string
  tag: string
  platform: string
  manifest_digest: string
  pinned_reference: string
  sbom_count: number
  total_components: number
  components_with_primary_cpe: number
  components_without_primary_cpe: number
  primary_cpe_ratio: number
  unique_primary_cpes: number
}

export interface ComponentsQuery {
  image_id?: number
  search?: string
  ordering?: string
  page?: number
  page_size?: number
}
