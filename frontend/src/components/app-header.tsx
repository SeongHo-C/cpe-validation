import {
  ApiStatus,
  type ApiConnectionStatus,
} from "@/components/api-status"
import { useLocation } from "react-router-dom"

interface AppHeaderProps {
  apiStatus: ApiConnectionStatus
}

const routeMetadata = {
  "/images": {
    eyebrow: "Inventory",
    title: "Docker Images",
    description: "Syft-generated CycloneDX SBOM inventory",
  },
  "/components": {
    eyebrow: "Validation Queue",
    title: "Primary CPE Components",
    description: "Components selected for CPE validation",
  },
} as const

export function AppHeader({ apiStatus }: AppHeaderProps) {
  const location = useLocation()
  const metadata =
    routeMetadata[
      location.pathname as keyof typeof routeMetadata
    ] ?? routeMetadata["/images"]

  return (
    <header className="border-b bg-card">
      <div className="flex min-h-20 items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-[0.16em] text-cyan-700">
            {metadata.eyebrow}
          </p>
          <h1 className="mt-1 font-heading text-2xl font-semibold tracking-tight text-foreground">
            {metadata.title}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {metadata.description}
          </p>
        </div>
        <ApiStatus status={apiStatus} />
      </div>
    </header>
  )
}
