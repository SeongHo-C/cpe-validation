import type { GroundTruthDecisionCode } from "@/features/ground-truth/ground-truth-types"

export const groundTruthDecisionCodes = [
  "CPE_CONFIRMED",
  "OFFICIAL_CPE_MAPPED",
  "VERSION_NOT_IN_DICTIONARY",
  "NVD_CONFIGURATION_ONLY",
  "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
  "UNRESOLVED",
] as const satisfies readonly GroundTruthDecisionCode[]

export const groundTruthDecisionNames: Record<
  GroundTruthDecisionCode,
  string
> = {
  CPE_CONFIRMED: "CPE Confirmed",
  OFFICIAL_CPE_MAPPED: "Correct CPE Found",
  VERSION_NOT_IN_DICTIONARY: "Version Not Registered",
  NVD_CONFIGURATION_ONLY: "NVD Configuration Only",
  DIRECT_OFFICIAL_CPE_NOT_CONFIRMED: "No Direct CPE Found",
  UNRESOLVED: "Unable to Determine",
}

export const groundTruthDecisionDescriptions: Record<
  GroundTruthDecisionCode,
  string
> = {
  CPE_CONFIRMED: "The original CPE is correct.",
  OFFICIAL_CPE_MAPPED:
    "The original CPE was incorrect, and the correct official CPE was identified.",
  VERSION_NOT_IN_DICTIONARY:
    "The product exists in the CPE Dictionary, but this version is not registered.",
  NVD_CONFIGURATION_ONLY:
    "The product is not in the CPE Dictionary but is referenced in an NVD CVE Configuration.",
  DIRECT_OFFICIAL_CPE_NOT_CONFIRMED:
    "The software product was identified, but no direct CPE could be confirmed.",
  UNRESOLVED:
    "The software product or version could not be determined with sufficient evidence.",
}

export function isGroundTruthDecisionCode(
  value: string | null,
): value is GroundTruthDecisionCode {
  return groundTruthDecisionCodes.some(
    (decision) => decision === value,
  )
}
