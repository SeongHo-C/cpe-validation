import {
  Check,
  ChevronsUpDown,
  LoaderCircle,
  Plus,
  Settings2,
  X,
} from "lucide-react"
import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react"
import type {
  KeyboardEvent,
  ReactNode,
} from "react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  createGroundTruthCorrectionType,
  getGroundTruthCorrectionTypes,
  updateGroundTruthCorrectionType,
} from "@/features/ground-truth/ground-truth-api"
import type { GroundTruthCorrectionType } from "@/features/ground-truth/ground-truth-types"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"

const HANGUL_PATTERN =
  /[\u1100-\u11ff\u3130-\u318f\ua960-\ua97f\uac00-\ud7ff\uffa0-\uffdc]/u
const CODE_PATTERN = /^[a-z][a-z0-9_]*$/

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.detail ?? error.message
  }
  return "Unable to update Correction Types."
}

function sortCorrectionTypes(
  correctionTypes: GroundTruthCorrectionType[],
): GroundTruthCorrectionType[] {
  return [...correctionTypes].sort(
    (left, right) =>
      left.name.localeCompare(right.name, undefined, {
        sensitivity: "base",
      }) || left.id - right.id,
  )
}

function codeFromName(name: string): string {
  return name
    .trim()
    .toLocaleLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
}

function CorrectionTypeDialog({
  title,
  children,
  onClose,
}: {
  title: string
  children: ReactNode
  onClose: () => void
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 p-4"
      role="presentation"
      onKeyDown={(event) => {
        if (event.key === "Escape") onClose()
      }}
    >
      <section
        aria-label={title}
        aria-modal="true"
        className="max-h-[85vh] w-full max-w-xl overflow-y-auto rounded-xl border bg-background p-4 shadow-xl"
        role="dialog"
      >
        <div className="mb-4 flex items-center justify-between gap-3">
          <h3 className="text-base font-semibold">{title}</h3>
          <Button
            aria-label={`Close ${title}`}
            size="icon-sm"
            type="button"
            variant="ghost"
            onClick={onClose}
          >
            <X aria-hidden="true" />
          </Button>
        </div>
        {children}
      </section>
    </div>
  )
}

export function GroundTruthCorrectionTypeField({
  value,
  onChange,
  onInteraction,
  disabled,
  disabledMessage,
}: {
  value: GroundTruthCorrectionType[]
  onChange: (
    correctionTypes: GroundTruthCorrectionType[],
  ) => void
  onInteraction: () => void
  disabled: boolean
  disabledMessage?: string
}) {
  const [activeCorrectionTypes, setActiveCorrectionTypes] =
    useState<GroundTruthCorrectionType[]>([])
  const [allCorrectionTypes, setAllCorrectionTypes] =
    useState<GroundTruthCorrectionType[]>([])
  const [query, setQuery] = useState("")
  const [manageQuery, setManageQuery] = useState("")
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(true)
  const [activeIndex, setActiveIndex] = useState(-1)
  const [createOpen, setCreateOpen] = useState(false)
  const [manageOpen, setManageOpen] = useState(false)
  const [createName, setCreateName] = useState("")
  const [createCode, setCreateCode] = useState("")
  const [createDescription, setCreateDescription] = useState("")
  const [creating, setCreating] = useState(false)
  const [managing, setManaging] = useState(false)
  const [pendingDeactivation, setPendingDeactivation] =
    useState<GroundTruthCorrectionType | null>(null)
  const [error, setError] = useState<string | null>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    getGroundTruthCorrectionTypes({}, controller.signal)
      .then((correctionTypes) => {
        setActiveCorrectionTypes(
          sortCorrectionTypes(correctionTypes),
        )
        setLoading(false)
      })
      .catch((reason: unknown) => {
        if (isAbortError(reason)) return
        setError(errorMessage(reason))
        setLoading(false)
      })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!open) return
    const closeOnOutsidePointerDown = (event: PointerEvent) => {
      if (
        event.target instanceof Node &&
        !dropdownRef.current?.contains(event.target)
      ) {
        setOpen(false)
      }
    }
    document.addEventListener(
      "pointerdown",
      closeOnOutsidePointerDown,
    )
    return () =>
      document.removeEventListener(
        "pointerdown",
        closeOnOutsidePointerDown,
      )
  }, [open])

  useEffect(() => {
    if (disabled) setOpen(false)
  }, [disabled])

  const filteredCorrectionTypes = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase()
    if (!normalizedQuery) return activeCorrectionTypes
    return activeCorrectionTypes.filter(
      (correctionType) =>
        correctionType.name
          .toLocaleLowerCase()
          .includes(normalizedQuery) ||
        correctionType.code
          .toLocaleLowerCase()
          .includes(normalizedQuery),
    )
  }, [activeCorrectionTypes, query])
  const exactMatch = activeCorrectionTypes.some(
    (correctionType) =>
      correctionType.name.toLocaleLowerCase() ===
      query.trim().toLocaleLowerCase(),
  )
  const canCreate = Boolean(query.trim()) && !exactMatch
  const optionCount =
    filteredCorrectionTypes.length + (canCreate ? 1 : 0)
  const selectedIds = useMemo(
    () => new Set(value.map((item) => item.id)),
    [value],
  )

  const toggle = (
    correctionType: GroundTruthCorrectionType,
  ) => {
    const next = selectedIds.has(correctionType.id)
      ? value.filter((item) => item.id !== correctionType.id)
      : sortCorrectionTypes([...value, correctionType])
    onChange(next)
    onInteraction()
    setQuery("")
  }

  const openCreate = () => {
    const name = query.trim()
    setCreateName(name)
    setCreateCode(codeFromName(name))
    setCreateDescription("")
    setError(null)
    setCreateOpen(true)
    setOpen(false)
  }

  const handleComboboxKeyDown = (
    event: KeyboardEvent<HTMLInputElement>,
  ) => {
    if (event.key === "Escape") {
      setOpen(false)
      return
    }
    if (event.key === "ArrowDown") {
      event.preventDefault()
      setOpen(true)
      setActiveIndex((index) =>
        optionCount ? (index + 1) % optionCount : -1,
      )
      return
    }
    if (event.key === "ArrowUp") {
      event.preventDefault()
      setOpen(true)
      setActiveIndex((index) =>
        optionCount
          ? index < 0
            ? optionCount - 1
            : (index - 1 + optionCount) % optionCount
          : -1,
      )
      return
    }
    if (event.key !== "Enter" || !open) return
    event.preventDefault()
    const selectedIndex = activeIndex < 0 ? 0 : activeIndex
    const selected = filteredCorrectionTypes[selectedIndex]
    if (selected) {
      toggle(selected)
    } else if (
      canCreate &&
      selectedIndex === filteredCorrectionTypes.length
    ) {
      openCreate()
    }
  }

  const createCorrectionType = async (): Promise<void> => {
    const normalizedName = createName.trim()
    const normalizedCode = createCode.trim().toLocaleLowerCase()
    const normalizedDescription = createDescription.trim()
    if (!normalizedName) {
      setError("Name is required.")
      return
    }
    if (!CODE_PATTERN.test(normalizedCode)) {
      setError(
        "Code must start with a lowercase letter and contain only lowercase letters, digits, and underscores.",
      )
      return
    }
    if (HANGUL_PATTERN.test(normalizedName)) {
      setError(
        "Correction Type names must be written in English.",
      )
      return
    }
    if (HANGUL_PATTERN.test(normalizedDescription)) {
      setError(
        "Correction Type descriptions must be written in English.",
      )
      return
    }
    setCreating(true)
    setError(null)
    try {
      const created = await createGroundTruthCorrectionType({
        code: normalizedCode,
        name: normalizedName,
        description: normalizedDescription,
      })
      setActiveCorrectionTypes((current) =>
        sortCorrectionTypes([...current, created]),
      )
      setAllCorrectionTypes((current) =>
        current.length
          ? sortCorrectionTypes([...current, created])
          : current,
      )
      onChange(sortCorrectionTypes([...value, created]))
      onInteraction()
      setQuery("")
      setCreateOpen(false)
    } catch (reason: unknown) {
      setError(errorMessage(reason))
    } finally {
      setCreating(false)
    }
  }

  const openManage = async (): Promise<void> => {
    setManageOpen(true)
    setManaging(true)
    setError(null)
    try {
      const correctionTypes =
        await getGroundTruthCorrectionTypes({
          is_active: "all",
        })
      setAllCorrectionTypes(
        sortCorrectionTypes(correctionTypes),
      )
    } catch (reason: unknown) {
      setError(errorMessage(reason))
    } finally {
      setManaging(false)
    }
  }

  const setActive = async (
    correctionType: GroundTruthCorrectionType,
    isActive: boolean,
  ): Promise<void> => {
    setManaging(true)
    setError(null)
    try {
      const updated = await updateGroundTruthCorrectionType(
        correctionType.id,
        { is_active: isActive },
      )
      setAllCorrectionTypes((current) =>
        sortCorrectionTypes(
          current.map((item) =>
            item.id === updated.id ? updated : item,
          ),
        ),
      )
      setActiveCorrectionTypes((current) =>
        sortCorrectionTypes(
          isActive
            ? [
                ...current.filter(
                  (item) => item.id !== updated.id,
                ),
                updated,
              ]
            : current.filter((item) => item.id !== updated.id),
        ),
      )
      if (selectedIds.has(updated.id)) {
        onChange(
          value.map((item) =>
            item.id === updated.id ? updated : item,
          ),
        )
      }
      setPendingDeactivation(null)
    } catch (reason: unknown) {
      setError(errorMessage(reason))
    } finally {
      setManaging(false)
    }
  }

  const normalizedManageQuery = manageQuery
    .trim()
    .toLocaleLowerCase()
  const managedCorrectionTypes = allCorrectionTypes.filter(
    (correctionType) =>
      !normalizedManageQuery ||
      correctionType.code
        .toLocaleLowerCase()
        .includes(normalizedManageQuery) ||
      correctionType.name
        .toLocaleLowerCase()
        .includes(normalizedManageQuery) ||
      correctionType.description
        .toLocaleLowerCase()
        .includes(normalizedManageQuery),
  )

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium">
          Correction Types
        </span>
        <Button
          size="sm"
          type="button"
          variant="ghost"
          onClick={() => void openManage()}
        >
          <Settings2 aria-hidden="true" />
          Manage Correction Types
        </Button>
      </div>

      {value.length ? (
        <div className="flex min-w-0 flex-wrap items-center gap-2 rounded-lg border bg-muted/20 p-2">
          {value.map((correctionType) => (
            <div
              className="flex min-w-0 items-center gap-1"
              key={correctionType.id}
            >
              <Badge
                className="max-w-full"
                title={correctionType.name}
                variant="secondary"
              >
                {correctionType.name}
              </Badge>
              {!correctionType.is_active ? (
                <Badge variant="outline">Inactive</Badge>
              ) : null}
              <Button
                aria-label={`Remove correction type ${correctionType.name}`}
                disabled={disabled}
                size="icon-xs"
                type="button"
                variant="ghost"
                onClick={() => toggle(correctionType)}
              >
                <X aria-hidden="true" />
              </Button>
            </div>
          ))}
        </div>
      ) : null}

      <div className="relative" ref={dropdownRef}>
        <Input
          aria-activedescendant={
            open && activeIndex >= 0
              ? activeIndex < filteredCorrectionTypes.length
                ? `ground-truth-correction-type-${filteredCorrectionTypes[activeIndex].id}`
                : "ground-truth-correction-type-create"
              : undefined
          }
          aria-label="Correction Types"
          aria-autocomplete="list"
          aria-controls="ground-truth-correction-type-options"
          aria-expanded={open}
          disabled={disabled}
          placeholder="Search or select correction types..."
          role="combobox"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value)
            setActiveIndex(-1)
            setOpen(true)
          }}
          onClick={() => setOpen((current) => !current)}
          onKeyDown={handleComboboxKeyDown}
        />
        <ChevronsUpDown
          aria-hidden="true"
          className="pointer-events-none absolute top-2 right-2 size-4 text-muted-foreground"
        />
        {open ? (
          <div
            className="absolute z-20 mt-1 max-h-64 w-full overflow-y-auto rounded-lg border bg-background p-1 shadow-lg"
            id="ground-truth-correction-type-options"
            role="listbox"
            aria-multiselectable="true"
          >
            {loading ? (
              <div className="flex items-center gap-2 p-2 text-sm text-muted-foreground">
                <LoaderCircle
                  className="size-4 animate-spin"
                  aria-hidden="true"
                />
                Loading Correction Types…
              </div>
            ) : null}
            {!loading && !optionCount ? (
              <p className="p-2 text-sm text-muted-foreground">
                No active Correction Types found.
              </p>
            ) : null}
            {filteredCorrectionTypes.map(
              (correctionType, index) => (
                <button
                  aria-selected={selectedIds.has(
                    correctionType.id,
                  )}
                  className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted focus:bg-muted focus:outline-none ${
                    activeIndex === index ? "bg-muted" : ""
                  }`}
                  id={`ground-truth-correction-type-${correctionType.id}`}
                  key={correctionType.id}
                  role="option"
                  type="button"
                  onClick={() => toggle(correctionType)}
                  onMouseEnter={() => setActiveIndex(index)}
                >
                  <Check
                    aria-hidden="true"
                    className={
                      selectedIds.has(correctionType.id)
                        ? "size-4"
                        : "size-4 opacity-0"
                    }
                  />
                  <span className="min-w-0 truncate">
                    {correctionType.name}
                  </span>
                </button>
              ),
            )}
            {canCreate ? (
              <button
                className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm text-cyan-800 hover:bg-muted focus:bg-muted focus:outline-none ${
                  activeIndex === filteredCorrectionTypes.length
                    ? "bg-muted"
                    : ""
                }`}
                id="ground-truth-correction-type-create"
                role="option"
                type="button"
                onClick={openCreate}
                onMouseEnter={() =>
                  setActiveIndex(filteredCorrectionTypes.length)
                }
              >
                <Plus className="size-4" aria-hidden="true" />
                <span className="min-w-0 truncate">
                  Create “{query.trim()}”
                </span>
              </button>
            ) : null}
          </div>
        ) : null}
      </div>

      {disabledMessage ? (
        <p className="text-xs text-muted-foreground">
          {disabledMessage}
        </p>
      ) : null}
      {error && !createOpen && !manageOpen ? (
        <p className="text-xs text-destructive">{error}</p>
      ) : null}

      {createOpen ? (
        <CorrectionTypeDialog
          title="Add Correction Type"
          onClose={() => {
            if (!creating) setCreateOpen(false)
          }}
        >
          <div className="space-y-4">
            <label className="block space-y-1.5 text-sm font-medium">
              <span>Name</span>
              <Input
                autoFocus
                value={createName}
                onChange={(event) => {
                  const name = event.target.value
                  setCreateName(name)
                  setCreateCode(codeFromName(name))
                  setError(null)
                }}
              />
            </label>
            <label className="block space-y-1.5 text-sm font-medium">
              <span>Code</span>
              <Input
                value={createCode}
                onChange={(event) => {
                  setCreateCode(event.target.value)
                  setError(null)
                }}
              />
            </label>
            <label className="block space-y-1.5 text-sm font-medium">
              <span>Description</span>
              <textarea
                className="min-h-24 w-full resize-y rounded-lg border border-input bg-transparent px-3 py-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                value={createDescription}
                onChange={(event) =>
                  setCreateDescription(event.target.value)
                }
              />
            </label>
            {error ? (
              <p className="text-sm text-destructive">{error}</p>
            ) : null}
            <div className="flex justify-end gap-2">
              <Button
                disabled={creating}
                type="button"
                variant="outline"
                onClick={() => setCreateOpen(false)}
              >
                Cancel
              </Button>
              <Button
                disabled={creating}
                type="button"
                onClick={() => void createCorrectionType()}
              >
                {creating ? "Creating…" : "Create"}
              </Button>
            </div>
          </div>
        </CorrectionTypeDialog>
      ) : null}

      {manageOpen ? (
        <CorrectionTypeDialog
          title="Manage Correction Types"
          onClose={() => {
            if (!managing) setManageOpen(false)
          }}
        >
          <div className="space-y-4">
            <Input
              autoFocus
              placeholder="Search Correction Types"
              value={manageQuery}
              onChange={(event) =>
                setManageQuery(event.target.value)
              }
            />
            {managing && !allCorrectionTypes.length ? (
              <p className="text-sm text-muted-foreground">
                Loading Correction Types…
              </p>
            ) : null}
            {(["Active", "Inactive"] as const).map((section) => {
              const isActive = section === "Active"
              const items = managedCorrectionTypes.filter(
                (item) => item.is_active === isActive,
              )
              return (
                <section className="space-y-2" key={section}>
                  <h4 className="text-sm font-semibold">{section}</h4>
                  {!items.length ? (
                    <p className="text-sm text-muted-foreground">
                      No {section.toLowerCase()} Correction Types.
                    </p>
                  ) : null}
                  {items.map((item) => (
                    <div
                      className="flex items-start justify-between gap-3 rounded-lg border p-3"
                      key={item.id}
                    >
                      <div className="min-w-0">
                        <p
                          className="truncate text-sm font-medium"
                          title={item.name}
                        >
                          {item.name}
                        </p>
                        <p className="mt-1 font-mono text-[11px] text-muted-foreground">
                          {item.code}
                        </p>
                        {item.description ? (
                          <p className="mt-1 text-xs text-muted-foreground">
                            {item.description}
                          </p>
                        ) : null}
                        {item.usage_count !== undefined ? (
                          <p className="mt-1 text-xs text-muted-foreground">
                            {item.usage_count} Ground Truth reference
                            {item.usage_count === 1 ? "" : "s"}
                          </p>
                        ) : null}
                      </div>
                      <Button
                        disabled={managing}
                        size="sm"
                        type="button"
                        variant="outline"
                        onClick={() => {
                          if (item.is_active) {
                            setPendingDeactivation(item)
                          } else {
                            void setActive(item, true)
                          }
                        }}
                      >
                        {item.is_active
                          ? "Deactivate"
                          : "Reactivate"}
                      </Button>
                    </div>
                  ))}
                </section>
              )
            })}
            {error ? (
              <p className="text-sm text-destructive">{error}</p>
            ) : null}
          </div>
        </CorrectionTypeDialog>
      ) : null}

      {pendingDeactivation ? (
        <CorrectionTypeDialog
          title="Deactivate Correction Type?"
          onClose={() => {
            if (!managing) setPendingDeactivation(null)
          }}
        >
          <p className="text-sm text-muted-foreground">
            Existing Ground Truth records will retain “
            {pendingDeactivation.name}”, but it will no longer be
            available for new selections.
          </p>
          <div className="mt-4 flex justify-end gap-2">
            <Button
              disabled={managing}
              type="button"
              variant="outline"
              onClick={() => setPendingDeactivation(null)}
            >
              Cancel
            </Button>
            <Button
              disabled={managing}
              type="button"
              variant="destructive"
              onClick={() =>
                void setActive(pendingDeactivation, false)
              }
            >
              Deactivate
            </Button>
          </div>
        </CorrectionTypeDialog>
      ) : null}
    </div>
  )
}
