import { getJson } from "@/lib/api-client"

export type CpeAnalysisAlgorithmStatus = "COMPLETED" | "NOT_RUN"

export interface CpeAnalysisMetrics {
  top1_accuracy: number | null
  recall_at_5: number | null
  recall_at_10: number | null
  mrr: number | null
}

export interface CpeAnalysisAlgorithmResult {
  algorithm_id: string
  status: CpeAnalysisAlgorithmStatus
  query_count: number | null
  candidate_family_count: number | null
  metrics: CpeAnalysisMetrics | null
}

export interface CpeAnalysisSummary {
  positive_gt_components_at_validation: number
  searchable_candidate_families: number
  method_count: number
  completed_method_count: number
  algorithms: CpeAnalysisAlgorithmResult[]
}

export function getCpeAnalysisSummary(
  signal?: AbortSignal,
): Promise<CpeAnalysisSummary> {
  return getJson<CpeAnalysisSummary>(
    "/api/cpe-analysis/summary/",
    { signal },
  )
}
