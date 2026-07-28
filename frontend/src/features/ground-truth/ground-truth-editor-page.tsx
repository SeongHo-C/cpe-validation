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
import { PageContent } from "@/components/page-content"
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
  return "Unable to load the Component Ground Truth screen."
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
      setComponentError("The Component ID is invalid.")
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
          "You have unsaved changes. Leave this component?",
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
      <PageContent>
        <Alert variant="destructive">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>Invalid Component</AlertTitle>
          <AlertDescription>
            A positive integer Component ID is required.
          </AlertDescription>
        </Alert>
      </PageContent>
    )
  }

  return (
    <PageContent className="space-y-5">
      <section className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ClipboardCheck
              className="size-5 text-cyan-700"
              aria-hidden="true"
            />
            <h2 className="font-heading text-lg font-semibold tracking-tight">
              Ground Truth Review
            </h2>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Assign an expected CPE without viewing algorithmic
            candidates or scores.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button asChild variant="outline">
            <Link
              to={groundTruthListPath(
                new URLSearchParams(searchSignature),
              )}
            >
              <List aria-hidden="true" />
              Back to Review Queue
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
            Previous
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!navigation?.next_component_id}
            onClick={() =>
              moveTo(navigation?.next_component_id ?? null)
            }
          >
            Next
            <ChevronRight aria-hidden="true" />
          </Button>
        </div>
      </section>

      <GroundTruthComponentContext
        detail={component}
        loading={componentLoading}
        error={componentError}
      />

      <div className="grid min-w-0 grid-cols-1 items-start gap-5 xl:grid-cols-[minmax(0,1fr)_390px]">
        <CpeDictionarySearch
          preserveQueryKeys={preservedGroundTruthQueryKeys}
          showSnapshotSummary={false}
          onSelectCandidate={(candidate) => {
            setManualCpe("")
            setSelectedCpe(candidate)
          }}
          onCopyToManual={(rawCpe) => {
            setSelectedCpe(null)
            setManualCpe(rawCpe)
          }}
        />
        <aside className="xl:sticky xl:top-5">
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
              This is the last component in the current review queue.
            </p>
          ) : null}
        </aside>
      </div>
    </PageContent>
  )
}
