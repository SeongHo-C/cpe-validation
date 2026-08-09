import type { GroundTruthDecisionCode } from "@/features/ground-truth/ground-truth-types"

export const groundTruthDecisionCodes = [
  "CPE_CONFIRMED",
  "OFFICIAL_CPE_MAPPED",
  "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
  "UNRESOLVED",
] as const satisfies readonly GroundTruthDecisionCode[]

export const groundTruthDecisionNames: Record<
  GroundTruthDecisionCode,
  string
> = {
  CPE_CONFIRMED: "CPE Confirmed",
  OFFICIAL_CPE_MAPPED: "Official CPE mapped",
  DIRECT_OFFICIAL_CPE_NOT_CONFIRMED:
    "Direct official CPE not confirmed",
  UNRESOLVED: "Unresolved",
}

export function isGroundTruthDecisionCode(
  value: string | null,
): value is GroundTruthDecisionCode {
  return groundTruthDecisionCodes.some(
    (decision) => decision === value,
  )
}
