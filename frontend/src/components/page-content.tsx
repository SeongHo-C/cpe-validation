import type { ComponentProps } from "react"

import { cn } from "@/lib/utils"

export function PageContent({
  className,
  ...props
}: ComponentProps<"div">) {
  return (
    <div
      className={cn(
        "mx-auto w-full min-w-0 max-w-[2200px]",
        className,
      )}
      {...props}
    />
  )
}
