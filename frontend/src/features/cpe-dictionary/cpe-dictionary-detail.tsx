import {
  BadgeCheck,
  Clipboard,
  ExternalLink,
  LoaderCircle,
  TriangleAlert,
  X,
} from "lucide-react"
import {
  useEffect,
  useState,
} from "react"

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { getCpeDictionaryDetail } from "@/features/cpe-dictionary/cpe-dictionary-api"
import type { CpeDictionaryDetail } from "@/features/cpe-dictionary/cpe-dictionary-types"
import {
  ApiError,
  isAbortError,
} from "@/lib/api-client"

const cpeFields = [
  "part",
  "vendor",
  "product",
  "version",
  "update",
  "edition",
  "language",
  "sw_edition",
  "target_sw",
  "target_hw",
  "other",
] as const

async function copyText(value: string) {
  await navigator.clipboard.writeText(value)
}

export function CpeDictionaryDetailDialog({
  cpeNameId,
  onClose,
  onSelectGroundTruth,
}: {
  cpeNameId: string | null
  onClose: () => void
  onSelectGroundTruth?: (detail: CpeDictionaryDetail) => void
}) {
  const [detail, setDetail] =
    useState<CpeDictionaryDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!cpeNameId) {
      setDetail(null)
      setError(null)
      return
    }
    const controller = new AbortController()
    setDetail(null)
    setError(null)
    getCpeDictionaryDetail(cpeNameId, controller.signal)
      .then(setDetail)
      .catch((reason: unknown) => {
        if (isAbortError(reason)) return
        setError(
          reason instanceof ApiError
            ? (reason.detail ?? reason.message)
            : "The CPE record could not be loaded.",
        )
      })
    return () => controller.abort()
  }, [cpeNameId])

  useEffect(() => {
    if (!cpeNameId) return
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose()
    }
    window.addEventListener("keydown", closeOnEscape)
    return () => window.removeEventListener("keydown", closeOnEscape)
  }, [cpeNameId, onClose])

  if (!cpeNameId) return null

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/35">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="cpe-detail-title"
        className="h-full w-[620px] overflow-y-auto border-l bg-background shadow-2xl"
      >
        <header className="sticky top-0 z-10 flex items-start justify-between border-b bg-background p-5">
          <div>
            <div className="flex items-center gap-2">
              <h2
                id="cpe-detail-title"
                className="font-heading text-lg font-semibold"
              >
                CPE Dictionary record
              </h2>
              <Badge variant="outline">Read only</Badge>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">
              Official snapshot metadata and evidence
            </p>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            aria-label="Close CPE details"
            onClick={onClose}
          >
            <X aria-hidden="true" />
          </Button>
        </header>

        {!detail && !error ? (
          <div
            className="flex items-center gap-2 p-6 text-sm text-muted-foreground"
            aria-live="polite"
          >
            <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
            Loading CPE details…
          </div>
        ) : null}
        {error ? (
          <div className="p-5">
            <Alert variant="destructive">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>Unable to load CPE details</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          </div>
        ) : null}
        {detail ? (
          <div className="space-y-7 p-5">
            <section className="space-y-3">
              <h3 className="font-heading font-semibold">Overview</h3>
              <dl className="grid grid-cols-2 gap-3">
                {[
                  [
                    "Title",
                    detail.titles.find((title) =>
                      title.lang?.toLowerCase().startsWith("en"),
                    )?.title ??
                      detail.titles[0]?.title ??
                      "",
                  ],
                  ["Status", detail.deprecated ? "Deprecated" : "Active"],
                  ["Snapshot", detail.snapshot_id],
                  ["CPE UUID", detail.cpe_name_id],
                ].map(([label, value]) => (
                  <div
                    key={label}
                    className="rounded-lg border bg-muted/20 p-3"
                  >
                    <dt className="text-xs text-muted-foreground">
                      {label}
                    </dt>
                    <dd className="mt-1 break-all text-sm">
                      {value || "Not provided"}
                    </dd>
                  </div>
                ))}
              </dl>
              <div className="rounded-lg border bg-muted/20 p-3">
                <p className="text-xs text-muted-foreground">
                  Raw CPE
                </p>
                <p className="mt-1 break-all font-mono text-xs leading-5">
                  {detail.cpe_name}
                </p>
                <div className="mt-3 flex gap-2">
                  {onSelectGroundTruth ? (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => onSelectGroundTruth(detail)}
                    >
                      <BadgeCheck aria-hidden="true" />
                      Ground Truth로 선택
                    </Button>
                  ) : null}
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    aria-label="Copy raw CPE"
                    onClick={() => void copyText(detail.cpe_name)}
                  >
                    <Clipboard aria-hidden="true" />
                    Copy raw CPE
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    aria-label="Copy CPE UUID"
                    onClick={() =>
                      void copyText(detail.cpe_name_id)
                    }
                  >
                    <Clipboard aria-hidden="true" />
                    Copy UUID
                  </Button>
                </div>
              </div>
              <p className="break-all font-mono text-[11px] text-muted-foreground">
                Manifest SHA-256: {detail.snapshot_manifest_sha256}
              </p>
            </section>

            <section>
              <h3 className="font-heading font-semibold">
                CPE 2.3 fields
              </h3>
              <dl className="mt-3 grid grid-cols-3 gap-2">
                {cpeFields.map((field) => (
                  <div
                    key={field}
                    className="rounded-lg border bg-muted/20 p-2.5"
                  >
                    <dt className="text-xs text-muted-foreground">
                      {field}
                    </dt>
                    <dd className="mt-1 break-all font-mono text-xs">
                      {detail[field] || "Not provided"}
                    </dd>
                  </div>
                ))}
              </dl>
            </section>

            <section>
              <h3 className="font-heading font-semibold">Titles</h3>
              {detail.titles.length > 0 ? (
                <ul className="mt-3 space-y-2">
                  {detail.titles.map((title, index) => (
                    <li
                      key={`${title.lang}-${index}`}
                      className="rounded-lg border p-3 text-sm"
                    >
                      <Badge variant="secondary">
                        {title.lang || "unknown"}
                      </Badge>
                      <span className="ml-2">
                        {title.title || "Not provided"}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2 text-sm text-muted-foreground">
                  No titles are recorded.
                </p>
              )}
            </section>

            <section>
              <h3 className="font-heading font-semibold">
                References
              </h3>
              {detail.references.length > 0 ? (
                <ul className="mt-3 space-y-2">
                  {detail.references.map((reference, index) => (
                    <li
                      key={`${reference.url}-${index}`}
                      className="rounded-lg border p-3"
                    >
                      <Badge variant="secondary">
                        {reference.type || "Reference"}
                      </Badge>
                      {reference.url ? (
                        <a
                          href={reference.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="mt-2 flex items-start gap-1 break-all text-sm text-cyan-700 underline underline-offset-2"
                        >
                          {reference.url}
                          <ExternalLink
                            className="mt-0.5 size-3 shrink-0"
                            aria-hidden="true"
                          />
                        </a>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2 text-sm text-muted-foreground">
                  No references are recorded.
                </p>
              )}
            </section>

            {detail.deprecated ? (
              <section>
                <h3 className="font-heading font-semibold">
                  Deprecated information
                </h3>
                <p className="mt-2 text-sm text-muted-foreground">
                  This record is deprecated. Replacement identifiers
                  are shown only as evidence and are not applied.
                </p>
                <ul className="mt-3 space-y-2">
                  {detail.deprecated_by.map((value, index) => (
                    <li
                      key={index}
                      className="break-all rounded-lg border p-3 font-mono text-xs"
                    >
                      {String(value)}
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
          </div>
        ) : null}
      </section>
    </div>
  )
}
