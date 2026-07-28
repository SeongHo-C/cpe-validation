export type CpePart = "" | "a" | "o" | "h"
export type DeprecatedFilter = "all" | "active" | "deprecated"
export type CpeDictionaryPageSize = 25 | 50 | 100

export interface CpeDictionaryQuery {
  q: string
  part: CpePart
  vendor: string
  product: string
  version: string
  cpe_name: string
  deprecated: DeprecatedFilter
  page: number
  page_size: CpeDictionaryPageSize
}

export interface CpeDictionarySnapshot {
  snapshot_id: string
  manifest_sha256: string
  status: "COMPLETE"
}

export interface CpeDictionaryResult {
  id: number
  cpe_name_id: string
  cpe_name: string
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
  deprecated: boolean
  title: string
  snapshot_id: string
}

export interface CpeDictionarySearchResponse {
  snapshot: CpeDictionarySnapshot
  query: Omit<CpeDictionaryQuery, "page" | "page_size">
  count: number
  page: number
  page_size: CpeDictionaryPageSize
  results: CpeDictionaryResult[]
}

export interface CpeTitle {
  lang?: string
  title?: string
}

export interface CpeReference {
  url: string
  type: string
}

export interface CpeDictionaryDetail {
  id: number
  cpe_name_id: string
  cpe_name: string
  snapshot_id: string
  snapshot_manifest_sha256: string
  deprecated: boolean
  deprecated_by: unknown[]
  deprecates: unknown[]
  created_at_nvd: string
  last_modified_at_nvd: string
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
  titles: CpeTitle[]
  references: CpeReference[]
}

export interface CpeGroundTruthCandidate {
  id: number
  cpe_name: string
  cpe_uuid: string
  deprecated: boolean
  part: string
  vendor: string
  product: string
  version: string
}

export interface ComponentCpeGroundTruthRecord {
  id: number
  ground_truth_cpe: CpeGroundTruthCandidate | null
  decision_type: string
  note: string
  created_at: string
  updated_at: string
}

export interface ComponentCpeGroundTruthResponse {
  component_id: number
  snapshot_id: string
  ground_truth: ComponentCpeGroundTruthRecord | null
}

export interface ComponentCpeGroundTruthWrite {
  ground_truth_cpe_id: number | null
  decision_type: string
  note: string
}
