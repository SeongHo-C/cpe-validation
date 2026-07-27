import { Menu, ShieldCheck } from "lucide-react"
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react"
import {
  Outlet,
  useLocation,
} from "react-router-dom"

import { AppHeader } from "@/components/app-header"
import {
  AppNavigation,
  AppSidebar,
} from "@/components/app-sidebar"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { useApiHealth } from "@/hooks/use-api-health"

export interface AppShellOutletContext {
  setImageCount: (count: number | undefined) => void
}

export function AppShell() {
  const location = useLocation()
  const apiStatus = useApiHealth()
  const [imageCount, setImageCountState] = useState<number>()
  const [mobileNavigationOpen, setMobileNavigationOpen] =
    useState(false)

  const setImageCount = useCallback(
    (count: number | undefined) => setImageCountState(count),
    [],
  )
  const outletContext = useMemo<AppShellOutletContext>(
    () => ({ setImageCount }),
    [setImageCount],
  )

  useEffect(() => {
    setMobileNavigationOpen(false)
  }, [location.pathname])

  return (
    <div className="min-h-screen bg-muted/35">
      <AppSidebar imageCount={imageCount} />

      <div className="min-w-0 lg:pl-60">
        <div className="flex h-14 items-center justify-between border-b bg-card px-4 lg:hidden">
          <div className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-lg bg-cyan-600 text-white">
              <ShieldCheck className="size-4" aria-hidden="true" />
            </div>
            <span className="font-heading text-sm font-semibold">
              CPE Validator
            </span>
          </div>

          <Sheet
            open={mobileNavigationOpen}
            onOpenChange={setMobileNavigationOpen}
          >
            <SheetTrigger asChild>
              <Button
                variant="outline"
                size="icon"
                aria-label="Open navigation menu"
              >
                <Menu aria-hidden="true" />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-72 p-0">
              <SheetHeader className="sr-only">
                <SheetTitle>Navigation</SheetTitle>
                <SheetDescription>
                  CPE Validation workbench navigation
                </SheetDescription>
              </SheetHeader>
              <AppNavigation imageCount={imageCount} />
            </SheetContent>
          </Sheet>
        </div>

        <AppHeader apiStatus={apiStatus} />
        <main className="px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet context={outletContext} />
        </main>
      </div>
    </div>
  )
}
