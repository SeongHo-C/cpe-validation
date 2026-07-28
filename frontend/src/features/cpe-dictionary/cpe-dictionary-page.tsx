import { BookOpenText } from "lucide-react"

import { CpeDictionarySearch } from "@/features/cpe-dictionary/cpe-dictionary-search"

export function CpeDictionaryPage() {
  return (
    <div className="space-y-6">
      <header>
        <div className="flex items-center gap-2">
          <BookOpenText
            className="size-5 text-cyan-700"
            aria-hidden="true"
          />
          <h2 className="font-heading text-xl font-semibold tracking-tight">
            Official CPE search
          </h2>
        </div>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
          Search and inspect the selected official NVD CPE
          Dictionary snapshot. This route is read-only and does not
          contain Ground Truth review state.
        </p>
      </header>

      <CpeDictionarySearch />
    </div>
  )
}
