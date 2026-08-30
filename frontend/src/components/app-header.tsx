import {
  ApiStatus,
  type ApiConnectionStatus,
} from "@/components/api-status"
import { useLocation } from "react-router-dom"

interface AppHeaderProps {
  apiStatus: ApiConnectionStatus
}

const routeMetadata = {
  "/sboms": {
    eyebrow: "Inventory",
    title: "SBOMs",
    description: "SBOM documents available for CPE validation",
  },
  "/components": {
    eyebrow: "Validation Queue",
    title: "Primary CPE Components",
    description: "Components selected for CPE validation",
  },
  "/ground-truth": {
    eyebrow: "Reference Dataset",
    title: "Ground Truth",
    description: "Independent human-authored CPE answers",
  },
  "/cpe-dictionary": {
    eyebrow: "Official Reference",
    title: "CPE Dictionary",
    description: "NVD CPE Dictionary exploration",
  },
  "/cpe-analysis": {
    eyebrow: "Research Evaluation",
    title: "CPE Analysis",
    description:
      "Compare CPE product-family matching performance across algorithms.",
  },
} as const

export function AppHeader({ apiStatus }: AppHeaderProps) {
  const location = useLocation()
  const metadata = location.pathname.startsWith(
    "/ground-truth/components/",
  )
    ? routeMetadata["/ground-truth"]
    : (routeMetadata[
        location.pathname as keyof typeof routeMetadata
      ] ?? routeMetadata["/sboms"])

  return (
    <header className="border-b bg-card">
      <div className="mx-auto flex min-h-20 w-full max-w-[2200px] items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
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
