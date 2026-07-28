import type { ReactNode } from "react"

import {
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
}: {
  title: ReactNode
  description?: ReactNode
  children?: ReactNode
  className?: string
}) {
  return (
    <CardHeader className={cn("border-b p-4", className)}>
      <CardTitle>{title}</CardTitle>
      {description ? (
        <CardDescription>{description}</CardDescription>
      ) : null}
      {children}
    </CardHeader>
  )
}
