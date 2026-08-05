import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react"

import { Button } from "@/components/ui/button"

interface PagePaginationProps {
  page: number
  totalPages: number
  disabled?: boolean
  onPageChange: (page: number) => void
}

export function PagePagination({
  page,
  totalPages,
  disabled = false,
  onPageChange,
}: PagePaginationProps) {
  const hasPages = totalPages > 0
  const isFirstPage = !hasPages || page <= 1
  const isLastPage = !hasPages || page >= totalPages
  const firstVisiblePage = Math.max(
    1,
    Math.min(page - 2, totalPages - 4),
  )
  const visiblePages = hasPages
    ? Array.from(
        { length: Math.min(5, totalPages) },
        (_, index) => firstVisiblePage + index,
      )
    : []

  return (
    <div className="flex flex-col gap-3 border-t px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
      <p
        className="text-sm text-muted-foreground"
        aria-live="polite"
      >
        {hasPages
          ? `Page ${page} of ${totalPages}`
          : "No pages available"}
      </p>
      <div className="flex items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          aria-label="First page"
          disabled={disabled || isFirstPage}
          onClick={() => onPageChange(1)}
        >
          <ChevronsLeft aria-hidden="true" />
          <span className="hidden sm:inline">First</span>
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          aria-label="Previous page"
          disabled={disabled || isFirstPage}
          onClick={() => onPageChange(page - 1)}
        >
          <ChevronLeft aria-hidden="true" />
          <span className="hidden sm:inline">Previous</span>
        </Button>
        {visiblePages.map((pageNumber) => (
          <Button
            key={pageNumber}
            type="button"
            variant={
              pageNumber === page ? "default" : "outline"
            }
            size="sm"
            aria-label={`Page ${pageNumber}`}
            aria-current={
              pageNumber === page ? "page" : undefined
            }
            disabled={disabled || pageNumber === page}
            onClick={() => onPageChange(pageNumber)}
          >
            {pageNumber}
          </Button>
        ))}
        <Button
          type="button"
          variant="outline"
          size="sm"
          aria-label="Next page"
          disabled={disabled || isLastPage}
          onClick={() => onPageChange(page + 1)}
        >
          <span className="hidden sm:inline">Next</span>
          <ChevronRight aria-hidden="true" />
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          aria-label="Last page"
          disabled={disabled || isLastPage}
          onClick={() => onPageChange(totalPages)}
        >
          <span className="hidden sm:inline">Last</span>
          <ChevronsRight aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}
