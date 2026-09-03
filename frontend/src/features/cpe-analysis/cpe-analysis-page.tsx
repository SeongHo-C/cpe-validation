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
type MetricKey = (typeof metricColumns)[number]["key"]

const percentMetricFormatter = new Intl.NumberFormat("en-US", {
  style: "percent",
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
})

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
      metrics:
        result?.status === "COMPLETED" ? result.metrics : null,
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

function highestMetric(
  algorithms: AlgorithmView[],
  key: MetricKey,
): number | null {
  return algorithms.reduce<number | null>((highest, algorithm) => {
    const value = algorithm.metrics?.[key]
    if (value === null || value === undefined) return highest
    return highest === null || value > highest ? value : highest
  }, null)
}

function bestAlgorithmId(algorithms: AlgorithmView[]): string | null {
  let bestId: string | null = null
  let bestMrr: number | null = null

  for (const algorithm of algorithms) {
    const mrr = algorithm.metrics?.mrr
    if (mrr === null || mrr === undefined) continue
    if (bestMrr === null || mrr > bestMrr) {
      bestId = algorithm.id
      bestMrr = mrr
    }
  }

  return bestId
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
  algorithms,
}: {
  summary: CpeAnalysisSummary
  algorithms: AlgorithmView[]
}) {
  const metrics: readonly {
    label: string
    value: ReactNode
    description: string
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
      label: "Best Top-1",
      value:
        formatMetric(
          highestMetric(algorithms, "top1_accuracy"),
          "percent",
        ) ?? "-",
      description: "Highest observed Top-1 accuracy",
    },
    {
      label: "Best Recall@10",
      value:
        formatMetric(
          highestMetric(algorithms, "recall_at_10"),
          "percent",
        ) ?? "-",
      description: "Highest observed Recall@10",
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
            </dd>
          </Card>
        ))}
      </dl>
    </section>
  )
}

function PerformanceTable({ algorithms }: { algorithms: AlgorithmView[] }) {
  const bestId = bestAlgorithmId(algorithms)
  const bestMetrics = Object.fromEntries(
    metricColumns.map((column) => [
      column.key,
      highestMetric(algorithms, column.key),
    ]),
  ) as Record<MetricKey, number | null>

  return (
    <section aria-labelledby="performance-title">
      <Card className="gap-0 py-0">
        <DataPanelHeader
          title={<h2 id="performance-title">Performance</h2>}
          description="Latest completed product-family retrieval benchmark metrics."
        />
        <Table className="min-w-[700px] table-fixed">
          <TableCaption className="sr-only">
            Product-family retrieval performance leaderboard
          </TableCaption>
          <TableHeader className="bg-slate-50">
            <TableRow>
              <TableHead scope="col" className="w-[36%] px-4">
                Algorithm
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
            {algorithms.map((algorithm) => {
              const isBest = algorithm.id === bestId
              return (
                <TableRow
                  key={algorithm.id}
                  className="hover:bg-slate-50"
                >
                  <TableCell
                    className={cn(
                      "px-4 py-2.5",
                      isBest && "border-l-2 border-l-cyan-600",
                    )}
                  >
                    <span className="flex items-center gap-2 font-medium text-foreground">
                      {algorithm.name}
                      {isBest ? (
                        <Badge
                          variant="outline"
                          className="h-4 border-cyan-600/20 bg-transparent px-1.5 py-0 text-[10px] text-cyan-700"
                        >
                          Best
                        </Badge>
                      ) : null}
                    </span>
                    <span className="mt-0.5 block text-xs text-muted-foreground">
                      {algorithm.descriptor}
                    </span>
                  </TableCell>
                  {metricColumns.map((column) => {
                    const rawValue = algorithm.metrics?.[column.key]
                    const value = formatMetric(rawValue, column.type)
                    const isBestMetric =
                      rawValue !== null &&
                      rawValue !== undefined &&
                      rawValue === bestMetrics[column.key]
                    return (
                      <TableCell
                        key={column.key}
                        className={cn(
                          "py-2.5 text-center tabular-nums",
                          value === null
                            ? "text-muted-foreground/70"
                            : isBestMetric
                              ? "font-semibold text-foreground"
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
              )
            })}
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
        <ExperimentSummary
          summary={summary}
          algorithms={displayedAlgorithms}
        />
      ) : null}

      <PerformanceTable algorithms={displayedAlgorithms} />
    </PageContent>
  )
}
