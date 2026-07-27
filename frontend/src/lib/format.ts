const integerFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 0,
})

export function formatInteger(value: number): string {
  return integerFormatter.format(Number.isFinite(value) ? value : 0)
}

export function formatPercent(
  ratio: number,
  maximumFractionDigits = 2,
): string {
  const safeRatio = Number.isFinite(ratio)
    ? Math.min(Math.max(ratio, 0), 1)
    : 0

  return new Intl.NumberFormat("en-US", {
    style: "percent",
    maximumFractionDigits,
  }).format(safeRatio)
}
