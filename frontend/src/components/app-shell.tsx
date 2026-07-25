import { Menu, ShieldCheck } from "lucide-react"
import type { ReactNode } from "react"

import { AppHeader } from "@/components/app-header"
import {
  AppNavigation,
  AppSidebar,
} from "@/components/app-sidebar"
import type { ApiConnectionStatus } from "@/components/api-status"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"

interface AppShellProps {
  apiStatus: ApiConnectionStatus
  imageCount?: number
  children: ReactNode
}

export function AppShell({
  apiStatus,
  imageCount,
  children,
}: AppShellProps) {
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

          <Sheet>
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
          {children}
        </main>
      </div>
    </div>
  )
}
