import {
  ApiStatus,
  type ApiConnectionStatus,
} from "@/components/api-status"

interface AppHeaderProps {
  apiStatus: ApiConnectionStatus
}

export function AppHeader({ apiStatus }: AppHeaderProps) {
  return (
    <header className="border-b bg-card">
      <div className="flex min-h-20 items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-[0.16em] text-cyan-700">
            Inventory
          </p>
          <h1 className="mt-1 font-heading text-2xl font-semibold tracking-tight text-foreground">
            Docker Images
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Syft-generated CycloneDX SBOM inventory
          </p>
        </div>
        <ApiStatus status={apiStatus} />
      </div>
    </header>
  )
}
