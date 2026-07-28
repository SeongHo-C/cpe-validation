import type { CpeDictionaryCandidate } from "@/features/cpe-dictionary/cpe-dictionary-types"
import type {
  ComponentSummary,
  DictionaryStatus,
} from "@/features/components/components-types"

export type GroundTruthSource = "DICTIONARY" | "MANUAL" | "NONE"
export type GroundTruthStatus = "UNREVIEWED" | "COMPLETED"
export type GroundTruthOrdering = "id" | "-id"

export interface GroundTruthDecisionType {
  id: number
  name: string
  description: string
  is_active: boolean
  usage_count?: number
}

export interface ComponentCpeGroundTruthRecord {
  id: number
  source: GroundTruthSource
  dictionary_cpe: CpeDictionaryCandidate | null
  ground_truth_cpe: CpeDictionaryCandidate | null
  manual_cpe: string | null
  decision_type: GroundTruthDecisionType
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
  dictionary_cpe_id: number | null
  manual_cpe: string | null
  decision_type_id: number
  note: string
}

export interface GroundTruthComponentSummary
  extends ComponentSummary {
  ground_truth_status: GroundTruthStatus
  ground_truth: ComponentCpeGroundTruthRecord | null
  decision_type: GroundTruthDecisionType | null
}

export interface GroundTruthListQuery {
  image_id?: number
  ground_truth_status?: GroundTruthStatus
  dictionary_status?: DictionaryStatus
  search?: string
  ordering: GroundTruthOrdering
  page: number
  page_size: number
}

export interface GroundTruthNavigation {
  component_id: number
  previous_component_id: number | null
  next_component_id: number | null
}
