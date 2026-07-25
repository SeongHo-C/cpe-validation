import {
  CheckCircle2,
  Database,
  LoaderCircle,
  XCircle,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export type ApiConnectionStatus =
  | "checking"
  | "connected"
  | "unavailable"

interface ApiStatusProps {
  status: ApiConnectionStatus
}

const statusDetails = {
  checking: {
    label: "Checking API",
    icon: LoaderCircle,
    className: "border-border bg-muted text-muted-foreground",
    iconClassName: "animate-spin",
  },
  connected: {
    label: "API Connected",
    icon: CheckCircle2,
    className:
      "border-emerald-200 bg-emerald-50 text-emerald-700",
    iconClassName: "",
  },
  unavailable: {
    label: "API Unavailable",
    icon: XCircle,
    className: "border-red-200 bg-red-50 text-red-700",
    iconClassName: "",
  },
} as const

export function ApiStatus({ status }: ApiStatusProps) {
  const details = statusDetails[status]
  const StatusIcon = details.icon

  return (
    <Badge
      variant="outline"
      className={cn(
        "h-7 gap-1.5 rounded-md px-2.5",
        details.className,
      )}
    >
      {status === "connected" ? (
        <Database aria-hidden="true" />
      ) : (
        <StatusIcon
          aria-hidden="true"
          className={details.iconClassName}
        />
      )}
      {details.label}
    </Badge>
  )
}
