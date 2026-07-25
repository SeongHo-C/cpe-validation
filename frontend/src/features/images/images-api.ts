import { getJson } from "@/lib/api-client"

import type {
  ApiHealth,
  DockerImageSummary,
} from "@/features/images/images-types"

export function getApiHealth(signal?: AbortSignal): Promise<ApiHealth> {
  return getJson<ApiHealth>("/api/health/", { signal })
}

export function getDockerImages(
  signal?: AbortSignal,
): Promise<DockerImageSummary[]> {
  return getJson<DockerImageSummary[]>("/api/images/", { signal })
}
