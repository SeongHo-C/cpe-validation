import type { GroundTruthStatus } from "@/features/ground-truth/ground-truth-types"

export const groundTruthStatusLabels: Record<
  GroundTruthStatus,
  string
> = {
  UNREVIEWED: "Not Reviewed",
  COMPLETED: "Completed",
}
