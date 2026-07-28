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
  return "Ground Truth 요청을 완료하지 못했습니다."
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
      setError("판정 유형은 필수 입력입니다.")
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
      setSuccess("검토 결과가 저장되었습니다.")
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
          <CardTitle>예상 Ground Truth</CardTitle>
          <Badge variant="outline">Human review</Badge>
        </div>
        <CardDescription>
          검색 순위나 점수와 독립적으로 정답을 기록합니다.
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
            기존 Ground Truth를 불러오는 중…
          </div>
        ) : (
          <>
            <section className="rounded-lg border bg-muted/20 p-3">
              <p className="text-xs font-medium text-muted-foreground">
                Dictionary Ground Truth CPE
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
                      수동 CPE로 복사
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
                      CPE 선택 해제
                    </Button>
                  </div>
                </div>
              ) : (
                <p className="mt-2 text-sm text-muted-foreground">
                  선택된 Dictionary CPE 없음
                </p>
              )}
            </section>

            <label className="block space-y-1.5 text-sm font-medium">
              <span>수동 CPE 2.3</span>
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
                Dictionary에 없는 CPE도 입력할 수 있으며 서버가
                CPE 2.3 구조를 검증합니다.
              </span>
            </label>

            <label className="block space-y-1.5 text-sm font-medium">
              <span>
                판정 유형 <span className="text-red-600">*</span>
              </span>
              <Input
                value={decisionType}
                placeholder="판정 유형을 자유롭게 입력"
                onChange={(event) => {
                  setDecisionType(event.target.value)
                  setSuccess(null)
                }}
              />
            </label>

            <details className="rounded-lg border bg-muted/20 px-3 py-2">
              <summary className="cursor-pointer text-sm font-medium">
                메모 추가
                {note ? " · 저장된 메모 있음" : ""}
              </summary>
              <textarea
                className="mt-3 min-h-28 w-full resize-y rounded-lg border border-input bg-background px-3 py-2 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                value={note}
                placeholder="선택 사항"
                onChange={(event) => {
                  setNote(event.target.value)
                  setSuccess(null)
                }}
              />
            </details>

            {error ? (
              <Alert variant="destructive">
                <TriangleAlert aria-hidden="true" />
                <AlertTitle>저장할 수 없습니다</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            {success ? (
              <Alert>
                <CheckCircle2
                  className="text-emerald-700"
                  aria-hidden="true"
                />
                <AlertTitle>저장 완료</AlertTitle>
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
                {saving ? "저장 중…" : "검토 결과 저장"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={saving || !canMoveNext}
                onClick={() => void saveGroundTruth(true)}
              >
                저장 후 다음
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}
