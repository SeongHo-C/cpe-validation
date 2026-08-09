import type { CpeDictionaryCandidate } from "@/features/cpe-dictionary/cpe-dictionary-types"
import type {
  ComponentSummary,
  DictionaryStatus,
} from "@/features/components/components-types"

export type GroundTruthSource = "DICTIONARY" | "MANUAL" | "NONE"
export type GroundTruthStatus = "UNREVIEWED" | "COMPLETED"
export type GroundTruthOrdering = "id" | "-id"
export type GroundTruthResolutionOutcomeCode =
  | "ORIGINAL_OFFICIAL_CONFIRMED"
  | "CORRECTED_TO_DICTIONARY"
  | "MANUAL_FROM_OFFICIAL_FAMILY"
  | "DIRECT_OFFICIAL_NOT_CONFIRMED"
  | "UNRESOLVED"

export type GroundTruthDecisionCode =
  | "CPE_CONFIRMED"
  | "OFFICIAL_CPE_MAPPED"
  | "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
  | "UNRESOLVED"

export interface GroundTruthDecision {
  code: GroundTruthDecisionCode
  name: string
}

export interface GroundTruthResolutionOutcome {
  code: GroundTruthResolutionOutcomeCode
  label: string
}

export interface GroundTruthCorrectionType {
  id: number
  code: string
  name: string
  description: string
  is_active: boolean
  usage_count?: number
}

export interface GroundTruthDiscrepancyType {
  id: number
  code: string
  name: string
  description: string
  is_active: boolean
  usage_count?: number
}

export interface ComponentCpeGroundTruthRecord {
  id: number
  source: GroundTruthSource
  dictionary_cpe: CpeDictionaryCandidate | null
  manual_cpe: string | null
  decision: GroundTruthDecision
  discrepancy_types: GroundTruthDiscrepancyType[]
  resolution_outcome: GroundTruthResolutionOutcome
  correction_types: GroundTruthCorrectionType[]
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
  decision: GroundTruthDecisionCode
  dictionary_cpe_id: number | null
  manual_cpe: string | null
  discrepancy_type_ids: number[]
  note: string
}

export interface GroundTruthComponentSummary
  extends ComponentSummary {
  ground_truth_status: GroundTruthStatus
  ground_truth: ComponentCpeGroundTruthRecord | null
  decision: GroundTruthDecision | null
  discrepancy_types: GroundTruthDiscrepancyType[]
  resolution_outcome: GroundTruthResolutionOutcome | null
  correction_types: GroundTruthCorrectionType[]
}

export interface GroundTruthListQuery {
  image_id?: number
  sbom_id?: number
  ground_truth_status?: GroundTruthStatus
  dictionary_status?: DictionaryStatus
  decision?: GroundTruthDecisionCode
  discrepancy_type?: string
  resolution_outcome?: GroundTruthResolutionOutcomeCode
  correction_type?: string
  search?: string
  ordering: GroundTruthOrdering
  page: number
  page_size: number
}

export interface GroundTruthDistributionItem {
  code: string
  name: string
  count: number
}

export interface GroundTruthSummary {
  total_records: number
  decision_distribution: GroundTruthDistributionItem[]
  discrepancy_type_distribution: GroundTruthDistributionItem[]
}

export interface GroundTruthNavigation {
  component_id: number
  previous_component_id: number | null
  next_component_id: number | null
}
