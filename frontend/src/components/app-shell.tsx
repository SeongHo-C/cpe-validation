import {
  useCallback,
  useMemo,
  useState,
} from "react"
import { Outlet } from "react-router-dom"

import { AppHeader } from "@/components/app-header"
import { AppSidebar } from "@/components/app-sidebar"
import { useApiHealth } from "@/hooks/use-api-health"

export interface AppShellOutletContext {
  setSbomCount: (count: number | undefined) => void
}

export function AppShell() {
  const apiStatus = useApiHealth()
  const [sbomCount, setSbomCountState] = useState<number>()

  const setSbomCount = useCallback(
    (count: number | undefined) => setSbomCountState(count),
    [],
  )
  const outletContext = useMemo<AppShellOutletContext>(
    () => ({ setSbomCount }),
    [setSbomCount],
  )

  return (
    <div className="min-h-screen bg-muted/35">
      <AppSidebar sbomCount={sbomCount} />

      <div className="min-w-0 pl-60">
        <AppHeader apiStatus={apiStatus} />
        <main className="px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet context={outletContext} />
        </main>
      </div>
    </div>
  )
}
