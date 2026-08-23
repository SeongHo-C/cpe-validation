import {
  Check,
  ChevronsUpDown,
  LoaderCircle,
} from "lucide-react"
import { useEffect, useMemo, useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { getGroundTruthDiscrepancyTypes } from "@/features/ground-truth/ground-truth-api"
import type { GroundTruthDiscrepancyType } from "@/features/ground-truth/ground-truth-types"
import { isAbortError } from "@/lib/api-client"

const visibleSelectedCount = 2

function selectionLabel(
  value: GroundTruthDiscrepancyType[],
): string {
  if (!value.length) return "Incorrect CPE Fields: None selected"
  return `Incorrect CPE Fields: ${value.map((item) => item.name).join(", ")}`
}

export function GroundTruthDiscrepancyTypeField({
  value,
  onChange,
  disabled = false,
  disabledMessage,
  validationMessage,
  onInteraction,
}: {
  value: GroundTruthDiscrepancyType[]
  onChange: (value: GroundTruthDiscrepancyType[]) => void
  disabled?: boolean
  disabledMessage?: string
  validationMessage?: string
  onInteraction?: () => void
}) {
  const [options, setOptions] = useState<
    GroundTruthDiscrepancyType[]
  >([])
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const selectedIds = useMemo(
    () => new Set(value.map((item) => item.id)),
    [value],
  )
  const availableOptions = useMemo(
    () => [
      ...options,
      ...value.filter(
        (selected) =>
          !options.some((option) => option.id === selected.id),
      ),
    ],
    [options, value],
  )

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    getGroundTruthDiscrepancyTypes({}, controller.signal)
      .then((items) => {
        setOptions(items)
        setLoading(false)
      })
      .catch((reason: unknown) => {
        if (isAbortError(reason)) return
        setError("Unable to load Incorrect CPE Fields.")
        setLoading(false)
      })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (disabled) setOpen(false)
  }, [disabled])

  const toggle = (item: GroundTruthDiscrepancyType) => {
    onInteraction?.()
    const nextSelectedIds = new Set(selectedIds)
    if (nextSelectedIds.has(item.id)) {
      nextSelectedIds.delete(item.id)
    } else {
      if (!item.is_active) return
      nextSelectedIds.add(item.id)
    }
    const knownOptions = availableOptions.filter((option) =>
      nextSelectedIds.has(option.id),
    )
    const unknownRetainedValues = value.filter(
      (selected) =>
        nextSelectedIds.has(selected.id) &&
        !availableOptions.some(
          (option) => option.id === selected.id,
        ),
    )
    onChange([...knownOptions, ...unknownRetainedValues])
  }

  const visibleSelected = value.slice(0, visibleSelectedCount)
  const hiddenSelectedCount = Math.max(
    0,
    value.length - visibleSelected.length,
  )

  return (
    <div
      aria-labelledby="ground-truth-discrepancy-types-title"
      className="space-y-1.5"
    >
      <div className="flex items-center justify-between gap-2">
        <h4
          id="ground-truth-discrepancy-types-title"
          className="text-sm font-medium"
        >
          Incorrect CPE Fields
        </h4>
        {value.length ? (
          <span className="text-xs text-muted-foreground">
            {value.length} selected
          </span>
        ) : null}
      </div>

      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            type="button"
            variant="outline"
            aria-label={selectionLabel(value)}
            aria-invalid={Boolean(validationMessage)}
            disabled={disabled || loading || Boolean(error)}
            className="h-auto min-h-8 w-full justify-between overflow-hidden py-1.5 whitespace-normal"
          >
            <span className="flex min-w-0 items-center gap-1 overflow-hidden">
              {loading ? (
                <>
                  <LoaderCircle
                    className="animate-spin"
                    aria-hidden="true"
                  />
                  <span className="truncate text-muted-foreground">
                    Loading Incorrect CPE Fields…
                  </span>
                </>
              ) : value.length ? (
                <>
                  {visibleSelected.map((item) => (
                    <Badge
                      key={item.id}
                      variant="secondary"
                      className="max-w-32 truncate"
                    >
                      {item.name}
                    </Badge>
                  ))}
                  {hiddenSelectedCount ? (
                    <Badge variant="outline">
                      +{hiddenSelectedCount}
                    </Badge>
                  ) : null}
                </>
              ) : (
                <span className="truncate text-muted-foreground">
                  Select incorrect fields
                </span>
              )}
            </span>
            <ChevronsUpDown
              className="size-4 text-muted-foreground"
              aria-hidden="true"
            />
          </Button>
        </PopoverTrigger>
        <PopoverContent
          align="start"
          aria-label="Incorrect CPE Field options"
          className="w-[var(--radix-popover-trigger-width)] max-w-[calc(100vw-2rem)] p-1"
        >
          <div className="max-h-72 overflow-y-auto p-1">
            {availableOptions.map((item) => {
              const checked = selectedIds.has(item.id)
              const descriptionId =
                `ground-truth-discrepancy-description-${item.id}`
              return (
                <label
                  key={item.id}
                  className="flex cursor-pointer items-start gap-2 rounded-md px-2 py-2 text-sm hover:bg-muted has-focus-visible:bg-muted"
                >
                  <span className="relative mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-sm border border-input bg-background">
                    <input
                      type="checkbox"
                      data-code={item.code}
                      className="peer absolute inset-0 cursor-pointer opacity-0 disabled:cursor-not-allowed"
                      checked={checked}
                      disabled={!item.is_active && !checked}
                      aria-label={item.name}
                      aria-describedby={descriptionId}
                      onChange={() => toggle(item)}
                    />
                    <Check
                      aria-hidden="true"
                      className="size-3 opacity-0 peer-checked:opacity-100"
                    />
                  </span>
                  <span className="min-w-0">
                    <span className="block font-medium">
                      {item.name}
                      {!item.is_active ? " · Inactive" : ""}
                    </span>
                    <span
                      id={descriptionId}
                      className="mt-0.5 block text-xs leading-4 text-muted-foreground"
                    >
                      {item.description}
                    </span>
                  </span>
                </label>
              )
            })}
          </div>
          <div className="border-t p-1 pt-2">
            <Button
              type="button"
              size="sm"
              variant="ghost"
              className="w-full"
              onClick={() => setOpen(false)}
            >
              Done
            </Button>
          </div>
        </PopoverContent>
      </Popover>

      {error ? (
        <p className="text-sm text-destructive">{error}</p>
      ) : null}
      {disabledMessage ? (
        <p className="text-xs text-muted-foreground">
          {disabledMessage}
        </p>
      ) : null}
      {validationMessage ? (
        <p className="text-xs text-destructive" role="alert">
          {validationMessage}
        </p>
      ) : null}
    </div>
  )
}
