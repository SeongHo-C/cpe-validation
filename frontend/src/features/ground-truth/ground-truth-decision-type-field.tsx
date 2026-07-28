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
  createGroundTruthDecisionType,
  getGroundTruthDecisionTypes,
  updateGroundTruthDecisionType,
} from "@/features/ground-truth/ground-truth-api"
import type { GroundTruthDecisionType } from "@/features/ground-truth/ground-truth-types"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"

const HANGUL_PATTERN =
  /[\u1100-\u11ff\u3130-\u318f\ua960-\ua97f\uac00-\ud7ff\uffa0-\uffdc]/u

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.detail ?? error.message
  }
  return "Unable to update Decision Types."
}

function sortDecisionTypes(
  decisionTypes: GroundTruthDecisionType[],
): GroundTruthDecisionType[] {
  return [...decisionTypes].sort(
    (left, right) =>
      left.name.localeCompare(right.name, undefined, {
        sensitivity: "base",
      }) || left.id - right.id,
  )
}

function DecisionTypeDialog({
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

export function GroundTruthDecisionTypeField({
  value,
  onChange,
  onInteraction,
}: {
  value: GroundTruthDecisionType | null
  onChange: (decisionType: GroundTruthDecisionType | null) => void
  onInteraction: () => void
}) {
  const [activeDecisionTypes, setActiveDecisionTypes] = useState<
    GroundTruthDecisionType[]
  >([])
  const [allDecisionTypes, setAllDecisionTypes] = useState<
    GroundTruthDecisionType[]
  >([])
  const [query, setQuery] = useState("")
  const [manageQuery, setManageQuery] = useState("")
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(true)
  const [activeIndex, setActiveIndex] = useState(-1)
  const [createOpen, setCreateOpen] = useState(false)
  const [manageOpen, setManageOpen] = useState(false)
  const [createName, setCreateName] = useState("")
  const [createDescription, setCreateDescription] = useState("")
  const [creating, setCreating] = useState(false)
  const [managing, setManaging] = useState(false)
  const [pendingDeactivation, setPendingDeactivation] =
    useState<GroundTruthDecisionType | null>(null)
  const [error, setError] = useState<string | null>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    getGroundTruthDecisionTypes({}, controller.signal)
      .then((decisionTypes) => {
        setActiveDecisionTypes(sortDecisionTypes(decisionTypes))
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

  const filteredDecisionTypes = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase()
    if (!normalizedQuery) return activeDecisionTypes
    return activeDecisionTypes.filter((decisionType) =>
      decisionType.name
        .toLocaleLowerCase()
        .includes(normalizedQuery),
    )
  }, [activeDecisionTypes, query])
  const exactMatch = activeDecisionTypes.some(
    (decisionType) =>
      decisionType.name.toLocaleLowerCase() ===
      query.trim().toLocaleLowerCase(),
  )
  const canCreate = Boolean(query.trim()) && !exactMatch
  const optionCount =
    filteredDecisionTypes.length + (canCreate ? 1 : 0)

  const choose = (decisionType: GroundTruthDecisionType) => {
    onChange(decisionType)
    onInteraction()
    setQuery("")
    setOpen(false)
  }

  const openCreate = () => {
    setCreateName(query.trim())
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
    const selected = filteredDecisionTypes[selectedIndex]
    if (selected) {
      choose(selected)
    } else if (
      canCreate &&
      selectedIndex === filteredDecisionTypes.length
    ) {
      openCreate()
    }
  }

  const createDecisionType = async (): Promise<void> => {
    const normalizedName = createName.trim()
    const normalizedDescription = createDescription.trim()
    if (!normalizedName) {
      setError("Name is required.")
      return
    }
    if (HANGUL_PATTERN.test(normalizedName)) {
      setError(
        "Decision Type names must be written in English.",
      )
      return
    }
    if (HANGUL_PATTERN.test(normalizedDescription)) {
      setError(
        "Decision Type descriptions must be written in English.",
      )
      return
    }
    setCreating(true)
    setError(null)
    try {
      const created = await createGroundTruthDecisionType({
        name: normalizedName,
        description: normalizedDescription,
      })
      setActiveDecisionTypes((current) =>
        sortDecisionTypes([...current, created]),
      )
      setAllDecisionTypes((current) =>
        current.length
          ? sortDecisionTypes([...current, created])
          : current,
      )
      onChange(created)
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
      const decisionTypes = await getGroundTruthDecisionTypes({
        is_active: "all",
      })
      setAllDecisionTypes(sortDecisionTypes(decisionTypes))
    } catch (reason: unknown) {
      setError(errorMessage(reason))
    } finally {
      setManaging(false)
    }
  }

  const setActive = async (
    decisionType: GroundTruthDecisionType,
    isActive: boolean,
  ): Promise<void> => {
    setManaging(true)
    setError(null)
    try {
      const updated = await updateGroundTruthDecisionType(
        decisionType.id,
        { is_active: isActive },
      )
      setAllDecisionTypes((current) =>
        sortDecisionTypes(
          current.map((item) =>
            item.id === updated.id ? updated : item,
          ),
        ),
      )
      setActiveDecisionTypes((current) =>
        sortDecisionTypes(
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
      if (value?.id === updated.id) onChange(updated)
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
  const managedDecisionTypes = allDecisionTypes.filter(
    (decisionType) =>
      !normalizedManageQuery ||
      decisionType.name
        .toLocaleLowerCase()
        .includes(normalizedManageQuery) ||
      decisionType.description
        .toLocaleLowerCase()
        .includes(normalizedManageQuery),
  )

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium">
          Decision Type <span className="text-red-600">*</span>
        </span>
        <Button
          size="sm"
          type="button"
          variant="ghost"
          onClick={() => void openManage()}
        >
          <Settings2 aria-hidden="true" />
          Manage Decision Types
        </Button>
      </div>

      {value ? (
        <div className="flex min-w-0 flex-wrap items-center gap-2 rounded-lg border bg-muted/20 p-2">
          <Badge
            className="max-w-full truncate"
            title={value.name}
            variant="secondary"
          >
            {value.name}
          </Badge>
          {!value.is_active ? (
            <Badge variant="outline">Inactive</Badge>
          ) : null}
          <Button
            aria-label="Clear Decision Type"
            size="xs"
            type="button"
            variant="ghost"
            onClick={() => {
              onChange(null)
              onInteraction()
            }}
          >
            <X aria-hidden="true" />
            Clear
          </Button>
        </div>
      ) : null}

      <div className="relative" ref={dropdownRef}>
        <Input
          aria-activedescendant={
            open && activeIndex >= 0
              ? activeIndex < filteredDecisionTypes.length
                ? `ground-truth-decision-type-${filteredDecisionTypes[activeIndex].id}`
                : "ground-truth-decision-type-create"
              : undefined
          }
          aria-label="Decision Type"
          aria-autocomplete="list"
          aria-controls="ground-truth-decision-type-options"
          aria-expanded={open}
          placeholder="Search or select a decision type..."
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
            id="ground-truth-decision-type-options"
            role="listbox"
          >
            {loading ? (
              <div className="flex items-center gap-2 p-2 text-sm text-muted-foreground">
                <LoaderCircle
                  className="size-4 animate-spin"
                  aria-hidden="true"
                />
                Loading Decision Types…
              </div>
            ) : null}
            {!loading && !optionCount ? (
              <p className="p-2 text-sm text-muted-foreground">
                No active Decision Types found.
              </p>
            ) : null}
            {filteredDecisionTypes.map((decisionType, index) => (
              <button
                aria-selected={value?.id === decisionType.id}
                className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted focus:bg-muted focus:outline-none ${
                  activeIndex === index ? "bg-muted" : ""
                }`}
                id={`ground-truth-decision-type-${decisionType.id}`}
                key={decisionType.id}
                role="option"
                type="button"
                onClick={() => choose(decisionType)}
                onMouseEnter={() => setActiveIndex(index)}
              >
                <Check
                  aria-hidden="true"
                  className={
                    value?.id === decisionType.id
                      ? "size-4"
                      : "size-4 opacity-0"
                  }
                />
                <span className="min-w-0 truncate">
                  {decisionType.name}
                </span>
              </button>
            ))}
            {canCreate ? (
              <button
                className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm text-cyan-800 hover:bg-muted focus:bg-muted focus:outline-none ${
                  activeIndex === filteredDecisionTypes.length
                    ? "bg-muted"
                    : ""
                }`}
                id="ground-truth-decision-type-create"
                role="option"
                type="button"
                onClick={openCreate}
                onMouseEnter={() =>
                  setActiveIndex(filteredDecisionTypes.length)
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

      {error && !createOpen && !manageOpen ? (
        <p className="text-xs text-destructive">{error}</p>
      ) : null}

      {createOpen ? (
        <DecisionTypeDialog
          title="Add Decision Type"
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
                  setCreateName(event.target.value)
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
                onClick={() => void createDecisionType()}
              >
                {creating ? "Creating…" : "Create"}
              </Button>
            </div>
          </div>
        </DecisionTypeDialog>
      ) : null}

      {manageOpen ? (
        <DecisionTypeDialog
          title="Manage Decision Types"
          onClose={() => {
            if (!managing) setManageOpen(false)
          }}
        >
          <div className="space-y-4">
            <Input
              autoFocus
              placeholder="Search Decision Types"
              value={manageQuery}
              onChange={(event) =>
                setManageQuery(event.target.value)
              }
            />
            {managing && !allDecisionTypes.length ? (
              <p className="text-sm text-muted-foreground">
                Loading Decision Types…
              </p>
            ) : null}
            {(["Active", "Inactive"] as const).map((section) => {
              const isActive = section === "Active"
              const items = managedDecisionTypes.filter(
                (item) => item.is_active === isActive,
              )
              return (
                <section className="space-y-2" key={section}>
                  <h4 className="text-sm font-semibold">{section}</h4>
                  {!items.length ? (
                    <p className="text-sm text-muted-foreground">
                      No {section.toLowerCase()} Decision Types.
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
        </DecisionTypeDialog>
      ) : null}

      {pendingDeactivation ? (
        <DecisionTypeDialog
          title="Deactivate Decision Type?"
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
        </DecisionTypeDialog>
      ) : null}
    </div>
  )
}
