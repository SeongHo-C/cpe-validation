import {
  CheckCircle2,
  LoaderCircle,
  Save,
  TriangleAlert,
  X,
} from "lucide-react"
import {
  useEffect,
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
import {
  getComponentCpeGroundTruth,
  putComponentCpeGroundTruth,
} from "@/features/cpe-dictionary/cpe-dictionary-api"
import type { CpeGroundTruthCandidate } from "@/features/cpe-dictionary/cpe-dictionary-types"
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

export function CpeGroundTruthEditor({
  componentId,
  selectedCpe,
  onSelectedCpeChange,
}: {
  componentId: number
  selectedCpe: CpeGroundTruthCandidate | null
  onSelectedCpeChange: (
    candidate: CpeGroundTruthCandidate | null,
  ) => void
}) {
  const [decisionType, setDecisionType] = useState("")
  const [note, setNote] = useState("")
  const [snapshotId, setSnapshotId] = useState("")
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setDecisionType("")
    setNote("")
    setSnapshotId("")
    setLoading(true)
    setSaving(false)
    setError(null)
    setSuccess(null)
    onSelectedCpeChange(null)

    getComponentCpeGroundTruth(componentId, controller.signal)
      .then((response) => {
        setSnapshotId(response.snapshot_id)
        setDecisionType(
          response.ground_truth?.decision_type ?? "",
        )
        setNote(response.ground_truth?.note ?? "")
        onSelectedCpeChange(
          response.ground_truth?.ground_truth_cpe ?? null,
        )
        setLoading(false)
      })
      .catch((reason: unknown) => {
        if (isAbortError(reason)) return
        setError(requestError(reason))
        setLoading(false)
      })

    return () => controller.abort()
  }, [componentId, onSelectedCpeChange])

  useEffect(() => {
    setError(null)
    setSuccess(null)
  }, [selectedCpe?.id])

  const saveGroundTruth = async () => {
    if (!decisionType.trim()) {
      setSuccess(null)
      setError("판정 유형은 필수 입력입니다.")
      return
    }
    setSaving(true)
    setError(null)
    setSuccess(null)
    try {
      const response = await putComponentCpeGroundTruth(
        componentId,
        {
          ground_truth_cpe_id: selectedCpe?.id ?? null,
          decision_type: decisionType,
          note,
        },
      )
      setSnapshotId(response.snapshot_id)
      setDecisionType(
        response.ground_truth?.decision_type ?? "",
      )
      setNote(response.ground_truth?.note ?? "")
      onSelectedCpeChange(
        response.ground_truth?.ground_truth_cpe ?? null,
      )
      setSuccess("검토 결과가 저장되었습니다.")
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
          <CardTitle>예상 Ground Truth</CardTitle>
          <Badge variant="outline">Human review</Badge>
        </div>
        <CardDescription>
          SBOM 원본 CPE를 변경하지 않고 현재 Dictionary snapshot에
          대한 예상 판정만 별도로 저장합니다.
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
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-xs font-medium text-muted-foreground">
                    예상 Ground Truth CPE
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
                        <Badge variant="secondary">
                          {selectedCpe.part}
                        </Badge>
                        <Badge variant="outline">
                          {selectedCpe.vendor}
                        </Badge>
                        <Badge variant="outline">
                          {selectedCpe.product}
                        </Badge>
                        <Badge variant="outline">
                          {selectedCpe.version}
                        </Badge>
                        <Badge
                          variant="outline"
                          className={
                            selectedCpe.deprecated
                              ? "border-amber-200 bg-amber-50 text-amber-700"
                              : "border-emerald-200 bg-emerald-50 text-emerald-700"
                          }
                        >
                          {selectedCpe.deprecated
                            ? "Deprecated"
                            : "Active"}
                        </Badge>
                      </div>
                    </div>
                  ) : (
                    <p className="mt-2 text-sm text-muted-foreground">
                      선택된 Ground Truth CPE 없음
                    </p>
                  )}
                </div>
                {selectedCpe ? (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      onSelectedCpeChange(null)
                      setSuccess(null)
                    }}
                  >
                    <X aria-hidden="true" />
                    CPE 선택 해제
                  </Button>
                ) : null}
              </div>
            </section>

            <label className="block space-y-1.5 text-sm font-medium">
              <span>
                판정 유형 <span className="text-red-600">*</span>
              </span>
              <Input
                value={decisionType}
                placeholder="새로운 판정 유형을 자유롭게 입력"
                onChange={(event) => {
                  setDecisionType(event.target.value)
                  setSuccess(null)
                }}
              />
            </label>

            <label className="block space-y-1.5 text-sm font-medium">
              <span>검토 메모</span>
              <textarea
                className="min-h-28 w-full resize-y rounded-lg border border-input bg-transparent px-3 py-2 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                value={note}
                placeholder="판정 근거와 추가 검토 내용을 입력"
                onChange={(event) => {
                  setNote(event.target.value)
                  setSuccess(null)
                }}
              />
            </label>

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

            <Button
              type="button"
              disabled={saving}
              onClick={() => void saveGroundTruth()}
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
          </>
        )}
      </CardContent>
    </Card>
  )
}
