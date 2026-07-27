import type { DictionaryStatus } from "@/features/components/components-types"

export const dictionaryStatuses: readonly DictionaryStatus[] = [
  "OFFICIAL_ACTIVE",
  "OFFICIAL_DEPRECATED",
  "NOT_IN_DICTIONARY",
  "NOT_PRESENT",
]

export const dictionaryStatusLabels: Record<
  DictionaryStatus,
  string
> = {
  OFFICIAL_ACTIVE: "Official Active",
  OFFICIAL_DEPRECATED: "Official Deprecated",
  NOT_IN_DICTIONARY: "Not in Dictionary",
  NOT_PRESENT: "Primary CPE Not Present",
}

export function isDictionaryStatus(
  value: string | null,
): value is DictionaryStatus {
  return (
    value !== null &&
    (dictionaryStatuses as readonly string[]).includes(value)
  )
}

export function dictionaryStatusClassName(
  status: DictionaryStatus,
): string {
  if (status === "OFFICIAL_ACTIVE") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700"
  }
  if (status === "OFFICIAL_DEPRECATED") {
    return "border-amber-200 bg-amber-50 text-amber-700"
  }
  if (status === "NOT_IN_DICTIONARY") {
    return "border-slate-200 bg-slate-50 text-slate-700"
  }
  return "border-border bg-muted text-muted-foreground"
}
