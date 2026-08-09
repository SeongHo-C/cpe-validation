import type { CpeDictionaryCandidate } from "@/features/cpe-dictionary/cpe-dictionary-types"
import type {
  GroundTruthResolutionOutcome,
  GroundTruthResolutionOutcomeCode,
} from "@/features/ground-truth/ground-truth-types"

export const resolutionOutcomeLabels: Record<
  GroundTruthResolutionOutcomeCode,
  string
> = {
  ORIGINAL_OFFICIAL_CONFIRMED:
    "Original CPE confirmed",
  CORRECTED_TO_DICTIONARY:
    "Corrected to official CPE",
  MANUAL_FROM_OFFICIAL_FAMILY:
    "Manual CPE from official family",
  DIRECT_OFFICIAL_NOT_CONFIRMED:
    "Direct official CPE not confirmed",
  UNRESOLVED: "Unresolved",
}

export const resolutionOutcomeCodes =
  Object.keys(
    resolutionOutcomeLabels,
  ) as GroundTruthResolutionOutcomeCode[]

export function isResolutionOutcomeCode(
  value: string | null,
): value is GroundTruthResolutionOutcomeCode {
  return (
    value !== null &&
    resolutionOutcomeCodes.includes(
      value as GroundTruthResolutionOutcomeCode,
    )
  )
}

export function expectedResolutionOutcome(
  originalCpe: string,
  selectedCpe: CpeDictionaryCandidate | null,
  manualCpe: string,
): GroundTruthResolutionOutcome {
  let code: GroundTruthResolutionOutcomeCode
  if (selectedCpe) {
    code =
      selectedCpe.cpe_name === originalCpe
        ? "ORIGINAL_OFFICIAL_CONFIRMED"
        : "CORRECTED_TO_DICTIONARY"
  } else if (manualCpe.trim()) {
    code = "MANUAL_FROM_OFFICIAL_FAMILY"
  } else {
    code = "DIRECT_OFFICIAL_NOT_CONFIRMED"
  }
  return {
    code,
    label: resolutionOutcomeLabels[code],
  }
}

export function resolutionAllowsCorrections(
  code: GroundTruthResolutionOutcomeCode,
): boolean {
  return (
    code === "CORRECTED_TO_DICTIONARY" ||
    code === "MANUAL_FROM_OFFICIAL_FAMILY"
  )
}
