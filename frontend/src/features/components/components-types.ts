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

export type DictionaryStatus =
  | "OFFICIAL_ACTIVE"
  | "OFFICIAL_DEPRECATED"
  | "NOT_IN_DICTIONARY"
  | "NOT_PRESENT"

export interface ComponentSummary {
  id: number
  image: ComponentImageReference
  sbom_document_id: number
  component_type: string
  group: string
  name: string
  version: string
  publisher: string
  purl: string
  cpe: string
  structural_status: string
  cpe_fields: CpeFields | null
  dictionary_status: DictionaryStatus
}

export interface ComponentProperty {
  name: string
  value: string
}

export interface ComponentSbomDocument {
  id: number
  source_path: string
  spec_version: string
  generator_name: string
  generator_version: string
  source_type: string
  scope: string
}

export interface DictionaryMatch {
  snapshot_id: string
  cpe_name_id: string | null
  matched_cpe_name: string | null
  deprecated: boolean | null
}

export interface ComponentDetail extends ComponentSummary {
  bom_ref: string
  properties: ComponentProperty[]
  sbom_document: ComponentSbomDocument
  structural_error_message: string | null
  dictionary_status: DictionaryStatus
  dictionary_match: DictionaryMatch
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
  dictionary_status?: DictionaryStatus
}
