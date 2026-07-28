import {
  isDictionaryStatus,
} from "@/features/components/dictionary-status"
import type {
  GroundTruthListQuery,
  GroundTruthOrdering,
  GroundTruthStatus,
} from "@/features/ground-truth/ground-truth-types"

export const DEFAULT_GROUND_TRUTH_QUERY: GroundTruthListQuery = {
  ordering: "id",
  page: 1,
  page_size: 50,
}

function positiveInteger(
  value: string | null,
): number | undefined {
  if (!value || !/^[1-9]\d*$/.test(value)) return undefined
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) ? parsed : undefined
}

export function parseGroundTruthListQuery(
  parameters: URLSearchParams,
): GroundTruthListQuery {
  const rawStatus = parameters.get("ground_truth_status")
  const groundTruthStatus: GroundTruthStatus | undefined =
    rawStatus === "UNREVIEWED" || rawStatus === "COMPLETED"
      ? rawStatus
      : undefined
  const rawOrdering = parameters.get("ordering")
  const ordering: GroundTruthOrdering =
    rawOrdering === "-id" ? "-id" : "id"
  const pageSize = positiveInteger(
    parameters.get("page_size"),
  )
  const rawDictionaryStatus = parameters.get(
    "dictionary_status",
  )

  return {
    image_id: positiveInteger(parameters.get("image_id")),
    ground_truth_status: groundTruthStatus,
    dictionary_status: isDictionaryStatus(rawDictionaryStatus)
      ? rawDictionaryStatus
      : undefined,
    search: parameters.get("search")?.trim() || undefined,
    ordering,
    page: positiveInteger(parameters.get("page")) ?? 1,
    page_size:
      pageSize === 25 ||
      pageSize === 50 ||
      pageSize === 100 ||
      pageSize === 200
        ? pageSize
        : 50,
  }
}

export function writeGroundTruthListQuery(
  query: GroundTruthListQuery,
): URLSearchParams {
  const parameters = new URLSearchParams()
  if (query.image_id !== undefined) {
    parameters.set("image_id", String(query.image_id))
  }
  if (query.ground_truth_status) {
    parameters.set(
      "ground_truth_status",
      query.ground_truth_status,
    )
  }
  if (query.dictionary_status) {
    parameters.set(
      "dictionary_status",
      query.dictionary_status,
    )
  }
  if (query.search?.trim()) {
    parameters.set("search", query.search.trim())
  }
  if (query.ordering !== "id") {
    parameters.set("ordering", query.ordering)
  }
  if (query.page !== 1) {
    parameters.set("page", String(query.page))
  }
  if (query.page_size !== 50) {
    parameters.set("page_size", String(query.page_size))
  }
  return parameters
}

export function groundTruthDetailPath(
  componentId: number,
  listParameters: URLSearchParams,
): string {
  const detailParameters = new URLSearchParams()
  const queue = listParameters.toString()
  if (queue) detailParameters.set("queue", queue)
  const suffix = detailParameters.toString()
  return `/ground-truth/components/${componentId}${
    suffix ? `?${suffix}` : ""
  }`
}

export function parseGroundTruthQueue(
  parameters: URLSearchParams,
): GroundTruthListQuery {
  return parseGroundTruthListQuery(
    new URLSearchParams(parameters.get("queue") ?? ""),
  )
}

export function groundTruthListPath(
  parameters: URLSearchParams,
): string {
  const queue = parameters.get("queue")
  return `/ground-truth${queue ? `?${queue}` : ""}`
}
