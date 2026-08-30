import { getJson } from "@/lib/api-client"

export interface CpeAnalysisSummary {
  positive_gt_components_at_validation: number
  searchable_candidate_families: number
}

export function getCpeAnalysisSummary(
  signal?: AbortSignal,
): Promise<CpeAnalysisSummary> {
  return getJson<CpeAnalysisSummary>(
    "/api/cpe-analysis/summary/",
    { signal },
  )
}
