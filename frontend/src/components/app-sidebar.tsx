import {
  BookOpenText,
  Boxes,
  ClipboardCheck,
  Layers3,
  ShieldCheck,
} from "lucide-react"
import { NavLink } from "react-router-dom"

import { Separator } from "@/components/ui/separator"
import { cn } from "@/lib/utils"

interface AppNavigationProps {
  sbomCount?: number
  className?: string
}

const navigationItems = [
  {
    label: "SBOMs",
    to: "/sboms",
    icon: Boxes,
  },
  {
    label: "Components",
    to: "/components",
    icon: Layers3,
  },
  {
    label: "Ground Truth",
    to: "/ground-truth",
    icon: ClipboardCheck,
  },
  {
    label: "CPE Dictionary",
    to: "/cpe-dictionary",
    icon: BookOpenText,
  },
] as const

export function AppNavigation({
  sbomCount,
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
      </nav>

      <div className="m-3 rounded-lg border bg-muted/40 p-3">
        <p className="text-xs font-medium text-foreground">
          SBOM Inventory
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          {sbomCount === undefined
            ? "SBOM documents"
            : `${sbomCount} SBOM documents`}
        </p>
      </div>
    </div>
  )
}

export function AppSidebar({ sbomCount }: { sbomCount?: number }) {
  return (
    <aside className="fixed inset-y-0 left-0 z-30 w-60 border-r bg-card">
      <AppNavigation sbomCount={sbomCount} />
    </aside>
  )
}
