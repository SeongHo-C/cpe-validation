import { TriangleAlert } from "lucide-react"
import {
  useEffect,
  useState,
  type ReactNode,
} from "react"

import { DataPanelHeader } from "@/components/data-panel-header"
import { PageContent } from "@/components/page-content"
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  getCpeAnalysisSummary,
  type CpeAnalysisAlgorithmStatus,
  type CpeAnalysisMetrics,
  type CpeAnalysisSummary,
} from "@/features/cpe-analysis/cpe-analysis-api"
import { isAbortError } from "@/lib/api-client"
import { formatInteger } from "@/lib/format"
import { cn } from "@/lib/utils"

interface AlgorithmDefinition {
  id: string
  name: string
  descriptor: string
}

interface AlgorithmView extends AlgorithmDefinition {
  status: CpeAnalysisAlgorithmStatus
  metrics: CpeAnalysisMetrics | null
}

const algorithms: readonly AlgorithmDefinition[] = [
  {
    id: "length_normalized_levenshtein",
    name: "Levenshtein",
    descriptor: "Edit distance",
  },
  {
    id: "jaro_winkler",
    name: "Jaro-Winkler",
    descriptor: "Character position",
  },
  {
    id: "character_trigram_dice",
    name: "Character n-gram",
    descriptor: "Character fragments",
  },
  {
    id: "ratcliff_obershelp",
    name: "Ratcliff–Obershelp",
    descriptor: "Common substring",
  },
]

const metricColumns = [
  { key: "top1_accuracy", label: "Top-1 Accuracy", type: "percent" },
  { key: "recall_at_5", label: "Recall@5", type: "percent" },
  { key: "recall_at_10", label: "Recall@10", type: "percent" },
  { key: "mrr", label: "MRR", type: "decimal" },
] as const
const percentMetricFormatter = new Intl.NumberFormat("en-US", {
  style: "percent",
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
})
const statusLabels: Record<CpeAnalysisAlgorithmStatus, string> = {
  COMPLETED: "Completed",
  NOT_RUN: "Not Run",
}
const statusBadgeClasses: Record<CpeAnalysisAlgorithmStatus, string> = {
  COMPLETED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  NOT_RUN: "border-border/70 bg-muted/60 text-muted-foreground",
}

function mergeAlgorithmResults(
  summary: CpeAnalysisSummary | null,
): AlgorithmView[] {
  const results = new Map(
    summary?.algorithms.map((result) => [result.algorithm_id, result]),
  )

  return algorithms.map((algorithm) => {
    const result = results.get(algorithm.id)
    return {
      ...algorithm,
      status: result?.status ?? "NOT_RUN",
      metrics: result?.metrics ?? null,
    }
  })
}

function formatMetric(
  value: number | null | undefined,
  type: "percent" | "decimal",
): string | null {
  if (value === null || value === undefined) return null
  return type === "percent"
    ? percentMetricFormatter.format(value)
    : value.toFixed(4)
}

function AlgorithmStatusBadge({
  status,
}: {
  status: CpeAnalysisAlgorithmStatus
}) {
  return (
    <Badge
      variant="outline"
      className={cn("shrink-0", statusBadgeClasses[status])}
    >
      {statusLabels[status]}
    </Badge>
  )
}

function SummarySkeleton() {
  return (
    <section aria-label="Loading experiment summary">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <Card key={index} size="sm">
            <CardContent>
              <Skeleton className="h-3 w-28" />
              <Skeleton className="mt-3 h-7 w-20" />
              <Skeleton className="mt-2 h-3 w-44 max-w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  )
}

function ExperimentSummary({
  summary,
}: {
  summary: CpeAnalysisSummary
}) {
  const benchmarkProgress =
    summary.method_count > 0
      ? Math.min(
          Math.max(
            (summary.completed_method_count / summary.method_count) * 100,
            0,
          ),
          100,
        )
      : 0
  const metrics: readonly {
    label: string
    value: ReactNode
    description: string
    progress?: number
  }[] = [
    {
      label: "Evaluation Set",
      value: formatInteger(
        summary.positive_gt_components_at_validation,
      ),
      description: "Components with a Ground Truth CPE",
    },
    {
      label: "Candidate Families",
      value: formatInteger(summary.searchable_candidate_families),
      description: "Searchable CPE product families",
    },
    {
      label: "Methods",
      value: formatInteger(summary.method_count),
      description: "Character-level similarity methods",
    },
    {
      label: "Benchmark",
      value: `${formatInteger(
        summary.completed_method_count,
      )} / ${formatInteger(summary.method_count)}`,
      description: "Methods evaluated",
      progress: benchmarkProgress,
    },
  ]

  return (
    <section aria-labelledby="experiment-summary-title">
      <h2 id="experiment-summary-title" className="sr-only">
        Experiment Summary
      </h2>
      <dl className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => (
          <Card
            key={metric.label}
            size="sm"
            className="gap-0 px-3 py-3"
          >
            <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              {metric.label}
            </dt>
            <dd className="mt-2">
              <span className="flex min-h-7 items-center font-heading text-2xl font-bold tracking-tight tabular-nums text-foreground">
                {metric.value}
              </span>
              <span className="mt-1.5 block text-xs text-muted-foreground">
                {metric.description}
              </span>
              {metric.progress !== undefined ? (
                <Progress
                  value={metric.progress}
                  aria-label="Benchmark progress"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={metric.progress}
                  aria-valuetext={`${formatInteger(
                    summary.completed_method_count,
                  )} of ${formatInteger(summary.method_count)} methods evaluated`}
                  className="mt-2.5 [&_[data-slot=progress-indicator]]:bg-emerald-500/75"
                />
              ) : null}
            </dd>
          </Card>
        ))}
      </dl>
    </section>
  )
}

function AlgorithmCards({ algorithms }: { algorithms: AlgorithmView[] }) {
  return (
    <section aria-labelledby="algorithms-title">
      <div className="mb-3 space-y-1">
        <h2
          id="algorithms-title"
          className="font-heading text-base font-semibold tracking-tight"
        >
          Algorithms
        </h2>
        <p className="text-sm text-muted-foreground">
          Matching methods included in the product-family evaluation.
        </p>
      </div>
      <ul
        className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"
      >
        {algorithms.map((algorithm) => (
          <li key={algorithm.id} className="min-w-0">
            <Card
              size="sm"
              className={cn(
                "h-full min-h-28 gap-0 px-3 py-3",
                algorithm.status === "COMPLETED" &&
                  "bg-emerald-50/35 ring-emerald-200/80",
              )}
            >
              <div className="flex items-start justify-between gap-2">
                <h3 className="font-heading text-sm font-semibold leading-snug">
                  {algorithm.name}
                </h3>
                <AlgorithmStatusBadge status={algorithm.status} />
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                {algorithm.descriptor}
              </p>
            </Card>
          </li>
        ))}
      </ul>
    </section>
  )
}

function PerformanceTable({ algorithms }: { algorithms: AlgorithmView[] }) {
  return (
    <section aria-labelledby="performance-title">
      <Card className="gap-0 py-0">
        <DataPanelHeader
          title={<h2 id="performance-title">Performance</h2>}
          description="Latest completed product-family retrieval benchmark metrics."
        />
        <Table className="min-w-[820px] table-fixed">
          <TableCaption className="sr-only">
            Product-family retrieval performance leaderboard
          </TableCaption>
          <TableHeader className="bg-muted/40">
            <TableRow>
              <TableHead scope="col" className="w-[34%] px-4">
                Algorithm
              </TableHead>
              <TableHead scope="col" className="w-28">
                Status
              </TableHead>
              {metricColumns.map((column) => (
                <TableHead
                  key={column.key}
                  scope="col"
                  className="text-center"
                >
                  {column.label}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {algorithms.map((algorithm) => (
              <TableRow
                key={algorithm.id}
                className={cn(
                  algorithm.status === "COMPLETED" &&
                    "bg-emerald-50/25 hover:bg-emerald-50/40",
                )}
              >
                <TableCell className="px-4 py-2.5">
                  <span
                    className={cn(
                      "flex items-center gap-2 font-medium",
                      algorithm.status === "COMPLETED" &&
                        "font-semibold text-foreground",
                    )}
                  >
                    {algorithm.name}
                  </span>
                  <span className="mt-0.5 block text-xs text-muted-foreground">
                    {algorithm.descriptor}
                  </span>
                </TableCell>
                <TableCell className="py-2.5">
                  <AlgorithmStatusBadge status={algorithm.status} />
                </TableCell>
                {metricColumns.map((column) => {
                  const value = formatMetric(
                    algorithm.metrics?.[column.key],
                    column.type,
                  )
                  return (
                    <TableCell
                      key={column.key}
                      className={cn(
                        "py-2.5 text-center tabular-nums",
                        value === null
                          ? "text-muted-foreground/70"
                          : "font-medium text-foreground",
                      )}
                    >
                      {value ?? (
                        <span aria-label="Not evaluated">-</span>
                      )}
                    </TableCell>
                  )
                })}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </section>
  )
}

export function CpeAnalysisPage() {
  const [summary, setSummary] =
    useState<CpeAnalysisSummary | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [hasError, setHasError] = useState(false)
  const [reloadToken, setReloadToken] = useState(0)
  const displayedAlgorithms = mergeAlgorithmResults(summary)

  useEffect(() => {
    const controller = new AbortController()
    let active = true

    setIsLoading(true)
    setHasError(false)
    getCpeAnalysisSummary(controller.signal)
      .then((nextSummary) => {
        if (!active) return
        setSummary(nextSummary)
        setIsLoading(false)
      })
      .catch((error: unknown) => {
        if (!active || isAbortError(error)) return
        setHasError(true)
        setIsLoading(false)
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [reloadToken])

  return (
    <PageContent
      id="cpe-analysis"
      className="space-y-5"
      aria-busy={isLoading}
    >
      {isLoading ? <SummarySkeleton /> : null}

      {!isLoading && hasError ? (
        <Alert variant="destructive" className="p-4">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>Unable to load experiment summary</AlertTitle>
          <AlertDescription>
            The candidate universe metadata is unavailable.
          </AlertDescription>
          <div className="col-start-2 mt-3">
            <Button
              type="button"
              variant="outline"
              onClick={() =>
                setReloadToken((current) => current + 1)
              }
            >
              Retry
            </Button>
          </div>
        </Alert>
      ) : null}

      {!isLoading && !hasError && summary ? (
        <ExperimentSummary summary={summary} />
      ) : null}

      <AlgorithmCards algorithms={displayedAlgorithms} />
      <PerformanceTable algorithms={displayedAlgorithms} />
    </PageContent>
  )
}
