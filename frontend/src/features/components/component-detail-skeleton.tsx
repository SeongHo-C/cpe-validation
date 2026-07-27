import { Skeleton } from "@/components/ui/skeleton"

export function ComponentDetailSkeleton() {
  return (
    <div
      aria-label="Loading component details"
      className="space-y-6 p-4"
    >
      <div className="grid grid-cols-2 gap-3">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
      {Array.from({ length: 4 }, (_, sectionIndex) => (
        <div key={sectionIndex} className="space-y-3">
          <Skeleton className="h-4 w-36" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      ))}
    </div>
  )
}
