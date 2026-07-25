export interface ApiHealth {
  status: "ok" | "error"
  database: "ok" | "unavailable"
}

export interface DockerImageSummary {
  id: number
  repository: string
  tag: string
  platform: string
  manifest_digest: string
  pinned_reference: string
  sbom_count: number
  total_components: number
  components_with_primary_cpe: number
  components_without_primary_cpe: number
  primary_cpe_ratio: number
  unique_primary_cpes: number
}
