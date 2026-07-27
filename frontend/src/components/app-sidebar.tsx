import {
  Boxes,
  Layers3,
  ScanSearch,
  ShieldCheck,
} from "lucide-react"
import { NavLink } from "react-router-dom"

import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { cn } from "@/lib/utils"

interface AppNavigationProps {
  imageCount?: number
  className?: string
}

const navigationItems = [
  {
    label: "Images",
    to: "/images",
    icon: Boxes,
  },
  {
    label: "Components",
    to: "/components",
    icon: Layers3,
  },
] as const

const futureNavigationItems = [
  {
    label: "Workbench",
    icon: ScanSearch,
  },
]

export function AppNavigation({
  imageCount,
  className,
}: AppNavigationProps) {
  return (
    <div className={cn("flex h-full flex-col", className)}>
      <div className="flex h-16 items-center gap-3 px-5">
        <div className="flex size-9 items-center justify-center rounded-lg bg-cyan-600 text-white">
          <ShieldCheck className="size-5" aria-hidden="true" />
        </div>
        <div className="min-w-0">
          <p className="font-heading text-sm font-semibold tracking-tight">
            CPE Validator
          </p>
          <p className="truncate text-xs text-muted-foreground">
            SBOM Research Workbench
          </p>
        </div>
      </div>

      <Separator />

      <nav
        aria-label="Primary navigation"
        className="flex-1 space-y-1 p-3"
      >
        {navigationItems.map((item) => {
          const Icon = item.icon
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  "flex h-9 items-center gap-3 rounded-lg px-3 text-sm outline-none transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-cyan-600",
                  isActive
                    ? "bg-cyan-50 font-medium text-cyan-800 hover:bg-cyan-100"
                    : "text-muted-foreground hover:text-foreground",
                )
              }
            >
              <Icon className="size-4" aria-hidden="true" />
              {item.label}
            </NavLink>
          )
        })}

        {futureNavigationItems.map((item) => {
          const Icon = item.icon
          return (
            <div
              key={item.label}
              aria-disabled="true"
              className="flex h-9 cursor-not-allowed items-center gap-3 rounded-lg px-3 text-sm text-muted-foreground/65"
            >
              <Icon className="size-4" aria-hidden="true" />
              <span>{item.label}</span>
              <Badge
                variant="secondary"
                className="ml-auto h-5 px-1.5 text-[10px]"
              >
                Next
              </Badge>
            </div>
          )
        })}
      </nav>

      <div className="m-3 rounded-lg border bg-muted/40 p-3">
        <p className="text-xs font-medium text-foreground">
          Pilot Dataset
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          {imageCount === undefined
            ? "Docker Official Images"
            : `${imageCount} Docker Official Images`}
        </p>
      </div>
    </div>
  )
}

export function AppSidebar({ imageCount }: { imageCount?: number }) {
  return (
    <aside className="fixed inset-y-0 left-0 z-30 w-60 border-r bg-card">
      <AppNavigation imageCount={imageCount} />
    </aside>
  )
}
