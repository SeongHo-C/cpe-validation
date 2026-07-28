import {
  ChevronLeft,
  ChevronRight,
  ClipboardCheck,
  List,
  TriangleAlert,
} from "lucide-react"
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react"
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { CpeDictionarySearch } from "@/features/cpe-dictionary/cpe-dictionary-search"
import type { CpeDictionaryCandidate } from "@/features/cpe-dictionary/cpe-dictionary-types"
import { getComponentDetail } from "@/features/components/components-api"
import type { ComponentDetail } from "@/features/components/components-types"
import { getGroundTruthNavigation } from "@/features/ground-truth/ground-truth-api"
import { GroundTruthComponentContext } from "@/features/ground-truth/ground-truth-component-context"
import { GroundTruthEditor } from "@/features/ground-truth/ground-truth-editor"
import {
  groundTruthListPath,
  parseGroundTruthQueue,
} from "@/features/ground-truth/ground-truth-query"
import type { GroundTruthNavigation } from "@/features/ground-truth/ground-truth-types"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"

const preservedGroundTruthQueryKeys = ["queue"] as const

function loadError(error: unknown): string {
  if (error instanceof ApiError) {
    return error.detail ?? error.message
  }
  return "Component Ground Truth 화면을 불러오지 못했습니다."
}

export function GroundTruthEditorPage() {
  const { componentId: rawComponentId } = useParams()
  const componentId =
    rawComponentId && /^[1-9]\d*$/.test(rawComponentId)
      ? Number(rawComponentId)
      : undefined
  const [searchParameters] = useSearchParams()
  const searchSignature = searchParameters.toString()
  const queueQuery = useMemo(
    () =>
      parseGroundTruthQueue(
        new URLSearchParams(searchSignature),
      ),
    [searchSignature],
  )
  const navigate = useNavigate()
  const [component, setComponent] =
    useState<ComponentDetail | null>(null)
  const [componentLoading, setComponentLoading] = useState(true)
  const [componentError, setComponentError] = useState<
    string | null
  >(null)
  const [navigation, setNavigation] =
    useState<GroundTruthNavigation | null>(null)
  const [selectedCpe, setSelectedCpe] =
    useState<CpeDictionaryCandidate | null>(null)
  const [manualCpe, setManualCpe] = useState("")
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    if (!componentId) {
      setComponent(null)
      setComponentLoading(false)
      setComponentError("Component ID가 올바르지 않습니다.")
      return
    }
    const controller = new AbortController()
    setComponent(null)
    setComponentLoading(true)
    setComponentError(null)
    getComponentDetail(componentId, controller.signal)
      .then((response) => {
        setComponent(response)
        setComponentLoading(false)
      })
      .catch((error: unknown) => {
        if (isAbortError(error)) return
        setComponentError(loadError(error))
        setComponentLoading(false)
      })
    return () => controller.abort()
  }, [componentId])

  useEffect(() => {
    if (!componentId) {
      setNavigation(null)
      return
    }
    const controller = new AbortController()
    getGroundTruthNavigation(
      componentId,
      queueQuery,
      controller.signal,
    )
      .then(setNavigation)
      .catch((error: unknown) => {
        if (isAbortError(error)) return
        setNavigation(null)
      })
    return () => controller.abort()
  }, [componentId, queueQuery])

  const moveTo = useCallback(
    (
      nextComponentId: number | null,
      ignoreDirty = false,
    ) => {
      if (!nextComponentId) return
      if (
        !ignoreDirty &&
        dirty &&
        !window.confirm(
          "저장하지 않은 변경사항이 있습니다. 이동할까요?",
        )
      ) {
        return
      }
      navigate(
        `/ground-truth/components/${nextComponentId}${
          searchSignature ? `?${searchSignature}` : ""
        }`,
      )
    },
    [dirty, navigate, searchSignature],
  )

  if (!componentId) {
    return (
      <Alert variant="destructive">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>잘못된 Component</AlertTitle>
        <AlertDescription>
          양의 정수 Component ID가 필요합니다.
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <div className="mx-auto min-w-[1280px] max-w-[2200px] space-y-5">
      <header className="flex items-start justify-between gap-6">
        <div>
          <div className="flex items-center gap-2">
            <ClipboardCheck
              className="size-5 text-cyan-700"
              aria-hidden="true"
            />
            <h1 className="font-heading text-2xl font-semibold tracking-tight">
              Ground Truth 작성
            </h1>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            검색 알고리즘 후보와 점수를 보지 않고 Component의 예상
            정답을 독립적으로 기록합니다.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline">
            <Link
              to={groundTruthListPath(
                new URLSearchParams(searchSignature),
              )}
            >
              <List aria-hidden="true" />
              목록
            </Link>
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!navigation?.previous_component_id}
            onClick={() =>
              moveTo(
                navigation?.previous_component_id ?? null,
              )
            }
          >
            <ChevronLeft aria-hidden="true" />
            이전
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!navigation?.next_component_id}
            onClick={() =>
              moveTo(navigation?.next_component_id ?? null)
            }
          >
            다음
            <ChevronRight aria-hidden="true" />
          </Button>
        </div>
      </header>

      <GroundTruthComponentContext
        detail={component}
        loading={componentLoading}
        error={componentError}
      />

      <div className="grid grid-cols-[minmax(0,1fr)_390px] items-start gap-5">
        <CpeDictionarySearch
          preserveQueryKeys={preservedGroundTruthQueryKeys}
          onSelectCandidate={(candidate) => {
            setManualCpe("")
            setSelectedCpe(candidate)
          }}
          onCopyToManual={(rawCpe) => {
            setSelectedCpe(null)
            setManualCpe(rawCpe)
          }}
        />
        <aside className="sticky top-5">
          <GroundTruthEditor
            key={componentId}
            componentId={componentId}
            selectedCpe={selectedCpe}
            manualCpe={manualCpe}
            onSelectedCpeChange={setSelectedCpe}
            onManualCpeChange={setManualCpe}
            onDirtyChange={setDirty}
            canMoveNext={Boolean(
              navigation?.next_component_id,
            )}
            onSavedAndNext={() =>
              moveTo(
                navigation?.next_component_id ?? null,
                true,
              )
            }
          />
          {navigation && !navigation.next_component_id ? (
            <p className="mt-2 text-center text-xs text-muted-foreground">
              현재 필터 기준 마지막 Component입니다.
            </p>
          ) : null}
        </aside>
      </div>
    </div>
  )
}
