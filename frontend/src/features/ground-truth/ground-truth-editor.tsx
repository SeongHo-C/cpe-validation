import {
  CheckCircle2,
  ClipboardPen,
  LoaderCircle,
  Save,
  TriangleAlert,
  X,
} from "lucide-react"
import {
  useEffect,
  useMemo,
  useState,
} from "react"

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
import { Input } from "@/components/ui/input"
import type { CpeDictionaryCandidate } from "@/features/cpe-dictionary/cpe-dictionary-types"
import {
  getComponentCpeGroundTruth,
  putComponentCpeGroundTruth,
} from "@/features/ground-truth/ground-truth-api"
import type { ComponentCpeGroundTruthResponse } from "@/features/ground-truth/ground-truth-types"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"

function requestError(error: unknown): string {
  if (error instanceof ApiError) {
    return error.detail ?? error.message
  }
  return "Unable to complete the Ground Truth request."
}

function stateSignature(
  selectedCpe: CpeDictionaryCandidate | null,
  manualCpe: string,
  decisionType: string,
  note: string,
): string {
  return JSON.stringify({
    dictionary_cpe_id: selectedCpe?.id ?? null,
    manual_cpe: manualCpe,
    decision_type: decisionType,
    note,
  })
}

export function GroundTruthEditor({
  componentId,
  selectedCpe,
  manualCpe,
  onSelectedCpeChange,
  onManualCpeChange,
  onDirtyChange,
  canMoveNext,
  onSavedAndNext,
}: {
  componentId: number
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
  const [decisionType, setDecisionType] = useState("")
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
        selectedCpe,
        manualCpe,
        decisionType,
        note,
      ),
    [decisionType, manualCpe, note, selectedCpe],
  )

  useEffect(() => {
    onDirtyChange(
      savedSignature !== null &&
        currentSignature !== savedSignature,
    )
  }, [currentSignature, onDirtyChange, savedSignature])

  useEffect(() => {
    const controller = new AbortController()
    setDecisionType("")
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
        const restoredCandidate =
          groundTruth?.dictionary_cpe ??
          groundTruth?.ground_truth_cpe ??
          null
        const restoredManual = groundTruth?.manual_cpe ?? ""
        const restoredDecision =
          groundTruth?.decision_type ?? ""
        const restoredNote = groundTruth?.note ?? ""
        setSnapshotId(response.snapshot_id)
        setDecisionType(restoredDecision)
        setNote(restoredNote)
        onSelectedCpeChange(restoredCandidate)
        onManualCpeChange(restoredManual)
        setSavedSignature(
          stateSignature(
            restoredCandidate,
            restoredManual,
            restoredDecision,
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
    if (!decisionType.trim()) {
      setSuccess(null)
      setError("Decision Type is required.")
      return
    }
    setSaving(true)
    setError(null)
    setSuccess(null)
    try {
      const response: ComponentCpeGroundTruthResponse =
        await putComponentCpeGroundTruth(componentId, {
          dictionary_cpe_id: selectedCpe?.id ?? null,
          manual_cpe: manualCpe.trim() || null,
          decision_type: decisionType,
          note,
        })
      const groundTruth = response.ground_truth
      const restoredCandidate =
        groundTruth?.dictionary_cpe ??
        groundTruth?.ground_truth_cpe ??
        null
      const restoredManual = groundTruth?.manual_cpe ?? ""
      const restoredDecision =
        groundTruth?.decision_type ?? ""
      const restoredNote = groundTruth?.note ?? ""
      setSnapshotId(response.snapshot_id)
      setDecisionType(restoredDecision)
      setNote(restoredNote)
      onSelectedCpeChange(restoredCandidate)
      onManualCpeChange(restoredManual)
      setSavedSignature(
        stateSignature(
          restoredCandidate,
          restoredManual,
          restoredDecision,
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
    <Card aria-busy={loading || saving}>
      <CardHeader>
        <div className="flex items-center gap-2">
          <ClipboardPen
            className="size-4 text-cyan-700"
            aria-hidden="true"
          />
          <CardTitle>Expected Ground Truth CPE</CardTitle>
          <Badge variant="outline">Human review</Badge>
        </div>
        <CardDescription>
          Record an expected CPE independently of search rankings and
          scores.
          {snapshotId ? ` Snapshot: ${snapshotId}` : ""}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
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
            <section className="rounded-lg border bg-muted/20 p-3">
              <p className="text-xs font-medium text-muted-foreground">
                Dictionary CPE
              </p>
              {selectedCpe ? (
                <div className="mt-2 space-y-2">
                  <p className="break-all font-mono text-xs leading-5">
                    {selectedCpe.cpe_name}
                  </p>
                  <p className="break-all font-mono text-[11px] text-muted-foreground">
                    UUID: {selectedCpe.cpe_uuid}
                  </p>
                  <div className="flex flex-wrap gap-2">
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
                  <div className="flex flex-wrap gap-2">
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
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
                      onClick={() =>
                        onSelectedCpeChange(null)
                      }
                    >
                      <X aria-hidden="true" />
                      Remove Selection
                    </Button>
                  </div>
                </div>
              ) : (
                <p className="mt-2 text-sm text-muted-foreground">
                  No Dictionary CPE selected
                </p>
              )}
            </section>

            <label className="block space-y-1.5 text-sm font-medium">
              <span>Manual CPE 2.3</span>
              <textarea
                className="min-h-24 w-full resize-y rounded-lg border border-input bg-transparent px-3 py-2 font-mono text-xs outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                value={manualCpe}
                placeholder="cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*"
                onChange={(event) => {
                  onManualCpeChange(event.target.value)
                  if (event.target.value) {
                    onSelectedCpeChange(null)
                  }
                  setSuccess(null)
                }}
              />
              <span className="block text-xs font-normal text-muted-foreground">
                You may enter a CPE that is not in the Dictionary. The
                server validates its CPE 2.3 structure.
              </span>
            </label>

            <label className="block space-y-1.5 text-sm font-medium">
              <span>
                Decision Type <span className="text-red-600">*</span>
              </span>
              <Input
                value={decisionType}
                placeholder="Enter a free-form decision type"
                onChange={(event) => {
                  setDecisionType(event.target.value)
                  setSuccess(null)
                }}
              />
            </label>

            <details className="rounded-lg border bg-muted/20 px-3 py-2">
              <summary className="cursor-pointer text-sm font-medium">
                Add Note
                {note ? " · Saved note" : ""}
              </summary>
              <textarea
                className="mt-3 min-h-28 w-full resize-y rounded-lg border border-input bg-background px-3 py-2 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
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

            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                disabled={saving}
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
                disabled={saving || !canMoveNext}
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
