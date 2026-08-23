import {
  CheckCircle2,
  ClipboardPen,
  LoaderCircle,
  Save,
  TriangleAlert,
  X,
} from "lucide-react"
import { useEffect, useMemo, useState } from "react"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { selectControlClassName } from "@/components/form-control-styles"
import type { CpeDictionaryCandidate } from "@/features/cpe-dictionary/cpe-dictionary-types"
import {
  getComponentCpeGroundTruth,
  putComponentCpeGroundTruth,
} from "@/features/ground-truth/ground-truth-api"
import {
  groundTruthDecisionCodes,
  groundTruthDecisionDescriptions,
  groundTruthDecisionNames,
} from "@/features/ground-truth/ground-truth-decision"
import { GroundTruthDiscrepancyTypeField } from "@/features/ground-truth/ground-truth-discrepancy-type-field"
import type {
  ComponentCpeGroundTruthResponse,
  GroundTruthDecisionCode,
  GroundTruthDiscrepancyType,
} from "@/features/ground-truth/ground-truth-types"
import { ApiError, isAbortError } from "@/lib/api-client"

function requestError(error: unknown): string {
  if (error instanceof ApiError) {
    return error.detail ?? error.message
  }
  return "Unable to complete the Ground Truth request."
}

function stateSignature(
  decision: GroundTruthDecisionCode | "",
  selectedCpe: CpeDictionaryCandidate | null,
  manualCpe: string,
  discrepancyTypes: GroundTruthDiscrepancyType[],
  note: string,
): string {
  return JSON.stringify({
    decision,
    dictionary_cpe_id: selectedCpe?.id ?? null,
    manual_cpe: manualCpe,
    discrepancy_type_ids: discrepancyTypes
      .map((discrepancyType) => discrepancyType.id)
      .sort((left, right) => left - right),
    note,
  })
}

function decisionValidationMessage(
  decision: GroundTruthDecisionCode | "",
  originalCpe: string,
  selectedCpe: CpeDictionaryCandidate | null,
  manualCpe: string,
  discrepancyTypes: GroundTruthDiscrepancyType[],
): string | null {
  const groundTruthCpe = selectedCpe?.cpe_name ?? manualCpe.trim()
  if (!decision) return "Select a CPE Validation Result."
  if (decision === "CPE_CONFIRMED") {
    if (!originalCpe) {
      return "CPE Confirmed requires an original SBOM CPE."
    }
    if (selectedCpe?.cpe_name !== originalCpe) {
      return "Select the original CPE from the Dictionary to confirm it."
    }
    if (discrepancyTypes.length) {
      return "CPE Confirmed cannot include Incorrect CPE Fields."
    }
  }
  if (decision === "OFFICIAL_CPE_MAPPED") {
    if (!groundTruthCpe) {
      return "Correct CPE Found requires a Ground Truth CPE."
    }
    if (groundTruthCpe === originalCpe) {
      return "Correct CPE Found requires a CPE different from the original."
    }
    if (!discrepancyTypes.length) {
      return "Select at least one Incorrect CPE Field for Correct CPE Found."
    }
  }
  if (
    decision === "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED" &&
    groundTruthCpe
  ) {
    return "No Direct CPE Found requires an empty Ground Truth CPE."
  }
  return null
}

export function GroundTruthEditor({
  componentId,
  originalCpe,
  selectedCpe,
  manualCpe,
  onSelectedCpeChange,
  onManualCpeChange,
  onDirtyChange,
  canMoveNext,
  onSavedAndNext,
}: {
  componentId: number
  originalCpe: string
  selectedCpe: CpeDictionaryCandidate | null
  manualCpe: string
  onSelectedCpeChange: (
    candidate: CpeDictionaryCandidate | null,
  ) => void
  onManualCpeChange: (rawCpe: string) => void
  onDirtyChange: (dirty: boolean) => void
  canMoveNext: boolean
  onSavedAndNext: () => void
}) {
  const [decision, setDecision] = useState<
    GroundTruthDecisionCode | ""
  >("")
  const [discrepancyTypes, setDiscrepancyTypes] = useState<
    GroundTruthDiscrepancyType[]
  >([])
  const [discrepancyNotice, setDiscrepancyNotice] = useState<
    string | null
  >(null)
  const [note, setNote] = useState("")
  const [snapshotId, setSnapshotId] = useState("")
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [savedSignature, setSavedSignature] = useState<
    string | null
  >(null)

  const currentSignature = useMemo(
    () =>
      stateSignature(
        decision,
        selectedCpe,
        manualCpe,
        discrepancyTypes,
        note,
      ),
    [decision, discrepancyTypes, manualCpe, note, selectedCpe],
  )
  const validationMessage = decisionValidationMessage(
    decision,
    originalCpe,
    selectedCpe,
    manualCpe,
    discrepancyTypes,
  )
  const discrepancyValidationMessage =
    decision === "OFFICIAL_CPE_MAPPED" &&
    discrepancyTypes.length === 0
      ? "Select at least one Incorrect CPE Field for Correct CPE Found."
      : undefined
  const discrepancyTypesDisabled =
    decision === "" || decision === "CPE_CONFIRMED"
  const groundTruthCpeDisabled =
    decision === "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
  const displayedGroundTruthCpe =
    selectedCpe?.cpe_name ?? manualCpe.trim()
  const groundTruthCpeSource = selectedCpe
    ? "Dictionary"
    : manualCpe.trim()
      ? "Manual"
      : "Not selected"

  useEffect(() => {
    onDirtyChange(
      savedSignature !== null &&
        currentSignature !== savedSignature,
    )
  }, [currentSignature, onDirtyChange, savedSignature])

  useEffect(() => {
    if (decision !== "CPE_CONFIRMED") {
      setDiscrepancyNotice(null)
      return
    }
    if (discrepancyTypes.length) {
      setDiscrepancyTypes([])
      setDiscrepancyNotice(
        "Incorrect CPE Fields were cleared because the original CPE is confirmed.",
      )
    }
  }, [decision, discrepancyTypes.length])

  useEffect(() => {
    if (
      decision === "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED" &&
      (selectedCpe !== null || manualCpe.trim())
    ) {
      onSelectedCpeChange(null)
      onManualCpeChange("")
    }
  }, [
    decision,
    manualCpe,
    onManualCpeChange,
    onSelectedCpeChange,
    selectedCpe,
  ])

  useEffect(() => {
    const controller = new AbortController()
    setDecision("")
    setDiscrepancyTypes([])
    setDiscrepancyNotice(null)
    setNote("")
    setSnapshotId("")
    setLoading(true)
    setSaving(false)
    setError(null)
    setSuccess(null)
    setSavedSignature(null)
    onSelectedCpeChange(null)
    onManualCpeChange("")

    getComponentCpeGroundTruth(componentId, controller.signal)
      .then((response) => {
        const groundTruth = response.ground_truth
        const restoredDecision = groundTruth?.decision.code ?? ""
        const restoredCandidate = groundTruth?.dictionary_cpe ?? null
        const restoredManual = groundTruth?.manual_cpe ?? ""
        const restoredDiscrepancies =
          groundTruth?.discrepancy_types ?? []
        const restoredNote = groundTruth?.note ?? ""
        setSnapshotId(response.snapshot_id)
        setDecision(restoredDecision)
        setDiscrepancyTypes(restoredDiscrepancies)
        setNote(restoredNote)
        onSelectedCpeChange(restoredCandidate)
        onManualCpeChange(restoredManual)
        setSavedSignature(
          stateSignature(
            restoredDecision,
            restoredCandidate,
            restoredManual,
            restoredDiscrepancies,
            restoredNote,
          ),
        )
        setLoading(false)
      })
      .catch((reason: unknown) => {
        if (isAbortError(reason)) return
        setError(requestError(reason))
        setLoading(false)
      })

    return () => controller.abort()
  }, [
    componentId,
    onManualCpeChange,
    onSelectedCpeChange,
  ])

  useEffect(() => {
    setError(null)
    setSuccess(null)
  }, [manualCpe, selectedCpe?.id])

  const saveGroundTruth = async (
    moveNext: boolean,
  ): Promise<void> => {
    if (!decision) return
    if (validationMessage) {
      setError(validationMessage)
      setSuccess(null)
      return
    }
    setSaving(true)
    setError(null)
    setSuccess(null)
    try {
      const response: ComponentCpeGroundTruthResponse =
        await putComponentCpeGroundTruth(componentId, {
          decision,
          dictionary_cpe_id: selectedCpe?.id ?? null,
          manual_cpe: manualCpe.trim() || null,
          discrepancy_type_ids: discrepancyTypes.map(
            (discrepancyType) => discrepancyType.id,
          ),
          note,
        })
      const groundTruth = response.ground_truth
      const restoredDecision = groundTruth?.decision.code ?? ""
      const restoredCandidate = groundTruth?.dictionary_cpe ?? null
      const restoredManual = groundTruth?.manual_cpe ?? ""
      const restoredDiscrepancies =
        groundTruth?.discrepancy_types ?? []
      const restoredNote = groundTruth?.note ?? ""
      setSnapshotId(response.snapshot_id)
      setDecision(restoredDecision)
      setDiscrepancyTypes(restoredDiscrepancies)
      setNote(restoredNote)
      onSelectedCpeChange(restoredCandidate)
      onManualCpeChange(restoredManual)
      setSavedSignature(
        stateSignature(
          restoredDecision,
          restoredCandidate,
          restoredManual,
          restoredDiscrepancies,
          restoredNote,
        ),
      )
      setSuccess("Ground Truth saved.")
      if (moveNext) onSavedAndNext()
    } catch (reason: unknown) {
      setError(requestError(reason))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card
      aria-busy={loading || saving}
      className="gap-0 py-0 xl:max-h-[calc(100dvh-2.5rem)]"
    >
      <CardHeader className="shrink-0 border-b py-3">
        <div className="flex items-center gap-2">
          <ClipboardPen
            className="size-4 text-cyan-700"
            aria-hidden="true"
          />
          <CardTitle>Expected Ground Truth CPE</CardTitle>
          <Badge variant="outline">Human review</Badge>
        </div>
        <CardDescription className="text-xs">
          Record the final decision independently from the discrepancy
          reasons and search scores.
          {snapshotId ? ` Snapshot: ${snapshotId}` : ""}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex min-h-0 flex-1 flex-col px-0">
        {loading ? (
          <div className="flex min-h-24 items-center justify-center gap-2 text-sm text-muted-foreground">
            <LoaderCircle
              className="size-4 animate-spin"
              aria-hidden="true"
            />
            Loading existing Ground Truth…
          </div>
        ) : (
          <>
            <div
              data-testid="ground-truth-editor-scroll-region"
              className="space-y-3 px-4 py-3 xl:min-h-0 xl:flex-1 xl:overflow-y-auto"
            >
              <section
                aria-labelledby={`ground-truth-cpe-title-${componentId}`}
                data-testid="ground-truth-cpe-primary"
                className="rounded-lg border border-ring bg-background p-3 shadow-sm xl:sticky xl:top-0 xl:z-10"
              >
                <div className="flex items-center justify-between gap-2">
                  <h3
                    id={`ground-truth-cpe-title-${componentId}`}
                    className="text-sm font-semibold"
                  >
                    Ground Truth CPE
                  </h3>
                  <Badge
                    variant={
                      displayedGroundTruthCpe
                        ? "secondary"
                        : "outline"
                    }
                  >
                    {groundTruthCpeSource}
                  </Badge>
                </div>
                {selectedCpe ? (
                  <div className="mt-2 space-y-2">
                    <p className="break-all font-mono text-xs leading-5">
                      {selectedCpe.cpe_name}
                    </p>
                    <details className="text-xs text-muted-foreground">
                      <summary className="cursor-pointer font-medium text-foreground">
                        CPE record details
                      </summary>
                      <p className="mt-2 break-all font-mono text-[11px]">
                        UUID: {selectedCpe.cpe_uuid}
                      </p>
                      <div className="mt-2 flex flex-wrap gap-1">
                        {[
                          selectedCpe.part,
                          selectedCpe.vendor,
                          selectedCpe.product,
                          selectedCpe.version,
                        ].map((value) => (
                          <Badge key={value} variant="outline">
                            {value}
                          </Badge>
                        ))}
                        <Badge variant="secondary">
                          {selectedCpe.deprecated
                            ? "Deprecated"
                            : "Active"}
                        </Badge>
                      </div>
                    </details>
                    <div className="flex flex-wrap gap-1.5">
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={groundTruthCpeDisabled}
                        onClick={() => {
                          onManualCpeChange(selectedCpe.cpe_name)
                          onSelectedCpeChange(null)
                        }}
                      >
                        Copy to Manual CPE
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={groundTruthCpeDisabled}
                        onClick={() => onSelectedCpeChange(null)}
                      >
                        <X aria-hidden="true" />
                        Change CPE
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="mt-2">
                    <label
                      htmlFor={`manual-ground-truth-cpe-${componentId}`}
                      className="sr-only"
                    >
                      Manual CPE 2.3
                    </label>
                    <textarea
                      id={`manual-ground-truth-cpe-${componentId}`}
                      className="min-h-16 w-full resize-y rounded-lg border border-input bg-transparent px-3 py-2 font-mono text-xs outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50"
                      value={manualCpe}
                      disabled={groundTruthCpeDisabled}
                      aria-describedby={`ground-truth-cpe-help-${componentId}`}
                      placeholder="cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*"
                      onChange={(event) => {
                        onManualCpeChange(event.target.value)
                        setError(null)
                        setSuccess(null)
                      }}
                    />
                    <p
                      id={`ground-truth-cpe-help-${componentId}`}
                      className="mt-1 text-xs text-muted-foreground"
                    >
                      Select an official record from the evidence panel,
                      or enter a manual CPE.
                    </p>
                  </div>
                )}
              </section>

              <section
                aria-labelledby={`classification-title-${componentId}`}
                data-testid="ground-truth-classification"
                className="space-y-3 rounded-lg border bg-muted/20 p-3"
              >
                <h3
                  id={`classification-title-${componentId}`}
                  className="text-sm font-semibold"
                >
                  Classification
                </h3>
                <div className="space-y-1.5">
                  <label
                    htmlFor={`ground-truth-decision-${componentId}`}
                    className="text-sm font-medium"
                  >
                    CPE Validation Result
                  </label>
                  <select
                    id={`ground-truth-decision-${componentId}`}
                    aria-label="CPE Validation Result"
                    aria-describedby={
                      decision
                        ? `ground-truth-decision-description-${componentId}`
                        : undefined
                    }
                    className={`${selectControlClassName} w-full`}
                    value={decision}
                    onChange={(event) => {
                      setDecision(
                        event.target.value as
                          | GroundTruthDecisionCode
                          | "",
                      )
                      setError(null)
                      setSuccess(null)
                    }}
                  >
                    <option value="">
                      Select a validation result
                    </option>
                    {groundTruthDecisionCodes.map((code) => (
                      <option key={code} value={code}>
                        {groundTruthDecisionNames[code]}
                      </option>
                    ))}
                  </select>
                  {decision ? (
                    <p
                      id={`ground-truth-decision-description-${componentId}`}
                      className="text-xs leading-4 text-muted-foreground"
                    >
                      {groundTruthDecisionDescriptions[decision]}
                    </p>
                  ) : null}
                </div>

                <GroundTruthDiscrepancyTypeField
                  value={discrepancyTypes}
                  onChange={setDiscrepancyTypes}
                  disabled={discrepancyTypesDisabled}
                  disabledMessage={
                    decision === "CPE_CONFIRMED"
                      ? "A confirmed original CPE has no incorrect fields."
                      : decision === ""
                        ? "Select a CPE Validation Result first."
                        : undefined
                  }
                  validationMessage={discrepancyValidationMessage}
                  onInteraction={() => {
                    setError(null)
                    setSuccess(null)
                  }}
                />
              </section>

              {discrepancyNotice ? (
                <p className="text-xs text-amber-700">
                  {discrepancyNotice}
                </p>
              ) : null}

              <details className="rounded-lg border bg-muted/20 px-3 py-2">
                <summary className="cursor-pointer text-sm font-medium">
                  Review details
                  {note ? " · Note saved" : ""}
                </summary>
                <label
                  htmlFor={`ground-truth-note-${componentId}`}
                  className="mt-3 block text-xs font-medium"
                >
                  Note
                </label>
                <textarea
                  id={`ground-truth-note-${componentId}`}
                  className="mt-1.5 min-h-24 w-full resize-y rounded-lg border border-input bg-background px-3 py-2 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                  value={note}
                  placeholder="Optional"
                  onChange={(event) => {
                    setNote(event.target.value)
                    setSuccess(null)
                  }}
                />
              </details>

              {error ? (
                <Alert variant="destructive">
                  <TriangleAlert aria-hidden="true" />
                  <AlertTitle>Unable to save</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              ) : null}
              {success ? (
                <Alert>
                  <CheckCircle2
                    className="text-emerald-700"
                    aria-hidden="true"
                  />
                  <AlertTitle>Saved</AlertTitle>
                  <AlertDescription>{success}</AlertDescription>
                </Alert>
              ) : null}
            </div>

            <div
              data-testid="ground-truth-editor-actions"
              className="sticky bottom-0 z-10 flex shrink-0 flex-wrap gap-2 border-t bg-background/95 px-4 py-3 backdrop-blur-sm"
            >
              <Button
                type="button"
                disabled={saving || !decision}
                onClick={() => void saveGroundTruth(false)}
              >
                {saving ? (
                  <LoaderCircle
                    className="animate-spin"
                    aria-hidden="true"
                  />
                ) : (
                  <Save aria-hidden="true" />
                )}
                {saving ? "Saving…" : "Save Ground Truth"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={saving || !canMoveNext || !decision}
                onClick={() => void saveGroundTruth(true)}
              >
                Save and Next
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}
