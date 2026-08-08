import type { ReactNode } from "react"

import {
  CardAction,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

export function DataPanelHeader({
  title,
  description,
  children,
  className,
  actionClassName,
}: {
  title: ReactNode
  description?: ReactNode
  children?: ReactNode
  className?: string
  actionClassName?: string
}) {
  return (
    <CardHeader className={cn("border-b p-4", className)}>
      <CardTitle>{title}</CardTitle>
      {description ? (
        <CardDescription>{description}</CardDescription>
      ) : null}
      {children ? (
        <CardAction className={actionClassName}>
          {children}
        </CardAction>
      ) : null}
    </CardHeader>
  )
}
