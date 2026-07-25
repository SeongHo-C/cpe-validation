import {
  Boxes,
  FileStack,
  Gauge,
  ShieldCheck,
} from "lucide-react"
import type { LucideIcon } from "lucide-react"

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type { DockerImageSummary } from "@/features/images/images-types"
import { formatInteger, formatPercent } from "@/lib/format"

interface ImagesSummaryProps {
  images: DockerImageSummary[]
}

interface SummaryMetric {
  label: string
  value: string
  description: string
  icon: LucideIcon
}

export function ImagesSummary({ images }: ImagesSummaryProps) {
  const totalComponents = images.reduce(
    (total, image) => total + image.total_components,
    0,
  )
  const primaryCpes = images.reduce(
    (total, image) =>
      total + image.components_with_primary_cpe,
    0,
  )
  const coverage =
    totalComponents === 0 ? 0 : primaryCpes / totalComponents

  const metrics: SummaryMetric[] = [
    {
      label: "Total Images",
      value: formatInteger(images.length),
      description: "Docker Official Image samples",
      icon: Boxes,
    },
    {
      label: "Total Components",
      value: formatInteger(totalComponents),
      description: "CycloneDX components inventoried",
      icon: FileStack,
    },
    {
      label: "Primary CPEs",
      value: formatInteger(primaryCpes),
      description: "Components with a primary CPE",
      icon: ShieldCheck,
    },
    {
      label: "CPE Coverage",
      value: formatPercent(coverage),
      description: "Primary CPE share of components",
      icon: Gauge,
    },
  ]

  return (
    <section aria-labelledby="images-summary-title">
      <h2 id="images-summary-title" className="sr-only">
        Docker image summary
      </h2>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => {
          const Icon = metric.icon
          return (
            <Card key={metric.label} className="gap-3">
              <CardHeader className="grid grid-cols-[1fr_auto] items-center">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  {metric.label}
                </CardTitle>
                <div className="flex size-8 items-center justify-center rounded-lg bg-cyan-50 text-cyan-700">
                  <Icon className="size-4" aria-hidden="true" />
                </div>
              </CardHeader>
              <CardContent>
                <p className="font-heading text-2xl font-semibold tracking-tight">
                  {metric.value}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {metric.description}
                </p>
              </CardContent>
            </Card>
          )
        })}
      </div>
    </section>
  )
}

export function ImagesSummarySkeleton() {
  return (
    <section aria-label="Loading summary metrics">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <Card key={index} className="gap-3">
            <CardHeader className="grid grid-cols-[1fr_auto] items-center">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="size-8 rounded-lg" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-8 w-28" />
              <Skeleton className="mt-2 h-3 w-40 max-w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  )
}
