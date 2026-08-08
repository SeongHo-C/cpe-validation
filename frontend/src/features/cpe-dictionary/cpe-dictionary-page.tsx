import { PageContent } from "@/components/page-content"
import { CpeDictionarySearch } from "@/features/cpe-dictionary/cpe-dictionary-search"

export function CpeDictionaryPage() {
  return (
    <PageContent className="space-y-6">
      <CpeDictionarySearch variant="standalone" />
    </PageContent>
  )
}
