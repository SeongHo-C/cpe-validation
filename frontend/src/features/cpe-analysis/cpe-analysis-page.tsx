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
  type CpeAnalysisAlgorithmStatus,
  type CpeAnalysisMetrics,
  type CpeAnalysisSummary,
} from "@/features/cpe-analysis/cpe-analysis-api"
import { isAbortError } from "@/lib/api-client"
import { formatInteger, formatPercent } from "@/lib/format"

interface AlgorithmDefinition {
  id: string
  name: string
  descriptor: string
  baseline?: boolean
}

interface AlgorithmView extends AlgorithmDefinition {
  status: CpeAnalysisAlgorithmStatus
  metrics: CpeAnalysisMetrics | null
}

const algorithms: readonly AlgorithmDefinition[] = [
  {
    id: "exact_match",
    name: "Exact Match",
    descriptor: "Exact baseline",
    baseline: true,
  },
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
    id: "character_ngram",
    name: "Character n-gram",
    descriptor: "Character fragments",
  },
  {
    id: "token_jaccard",
    name: "Token Jaccard",
    descriptor: "Token overlap",
  },
  {
    id: "tfidf_cosine",
    name: "TF-IDF + Cosine",
    descriptor: "Weighted token vector",
  },
]

const metricColumns = [
  { key: "top1_accuracy", label: "Top-1 Accuracy", type: "percent" },
  { key: "recall_at_5", label: "Recall@5", type: "percent" },
  { key: "recall_at_10", label: "Recall@10", type: "percent" },
  { key: "mrr", label: "MRR", type: "decimal" },
] as const
const statusLabels: Record<CpeAnalysisAlgorithmStatus, string> = {
  COMPLETED: "Completed",
  NOT_RUN: "Not Run",
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
    ? formatPercent(value, 2)
    : value.toFixed(4)
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
      label: "Methods",
      value: formatInteger(summary.method_count),
      description: "1 baseline · 5 similarity methods",
    },
    {
      label: "Benchmark",
      value: `${formatInteger(
        summary.completed_method_count,
      )} / ${formatInteger(summary.method_count)}`,
      description: "Methods evaluated",
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
              <span className="flex min-h-7 items-center font-heading text-2xl font-semibold tracking-tight">
                {metric.value}
              </span>
              <span className="mt-1 block text-xs text-muted-foreground">
                {metric.description}
              </span>
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
      <div className="mb-3">
        <h2
          id="algorithms-title"
          className="font-heading text-base font-semibold tracking-tight"
        >
          Algorithms
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Matching methods included in the product-family evaluation.
        </p>
      </div>
      <ul
        className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6"
      >
        {algorithms.map((algorithm) => (
          <li key={algorithm.id} className="min-w-0">
            <Card size="sm" className="h-full min-h-28 gap-0 px-3 py-3">
              <div className="flex items-start justify-between gap-2">
                <h3 className="font-heading text-sm font-semibold leading-snug">
                  {algorithm.name}
                </h3>
                <Badge variant="secondary" className="shrink-0">
                  {statusLabels[algorithm.status]}
                </Badge>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                {algorithm.descriptor}
              </p>
              <div className="mt-auto min-h-5 pt-3">
                {algorithm.baseline ? (
                  <Badge variant="outline">Baseline</Badge>
                ) : null}
              </div>
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
          <TableHeader className="bg-muted/45">
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
              <TableRow key={algorithm.id}>
                <TableCell className="px-4 py-2.5">
                  <span className="flex items-center gap-2 font-medium">
                    {algorithm.name}
                    {algorithm.baseline ? (
                      <Badge variant="outline">Baseline</Badge>
                    ) : null}
                  </span>
                  <span className="mt-0.5 block text-xs text-muted-foreground">
                    {algorithm.descriptor}
                  </span>
                </TableCell>
                <TableCell className="py-2.5">
                  <Badge variant="secondary">
                    {statusLabels[algorithm.status]}
                  </Badge>
                </TableCell>
                {metricColumns.map((column) => {
                  const value = formatMetric(
                    algorithm.metrics?.[column.key],
                    column.type,
                  )
                  return (
                    <TableCell
                      key={column.key}
                      className="py-2.5 text-center tabular-nums text-muted-foreground"
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
