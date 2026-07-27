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
  setImageCount: (count: number | undefined) => void
}

export function AppShell() {
  const apiStatus = useApiHealth()
  const [imageCount, setImageCountState] = useState<number>()

  const setImageCount = useCallback(
    (count: number | undefined) => setImageCountState(count),
    [],
  )
  const outletContext = useMemo<AppShellOutletContext>(
    () => ({ setImageCount }),
    [setImageCount],
  )

  return (
    <div className="min-h-screen min-w-[1180px] bg-muted/35">
      <AppSidebar imageCount={imageCount} />

      <div className="min-w-0 pl-60">
        <AppHeader apiStatus={apiStatus} />
        <main className="px-8 py-8">
          <Outlet context={outletContext} />
        </main>
      </div>
    </div>
  )
}
