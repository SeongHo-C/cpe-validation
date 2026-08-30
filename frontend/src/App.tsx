import {
  Navigate,
  Route,
  Routes,
} from "react-router-dom"

import { AppShell } from "@/components/app-shell"
import { CpeAnalysisPage } from "@/features/cpe-analysis/cpe-analysis-page"
import { CpeDictionaryPage } from "@/features/cpe-dictionary/cpe-dictionary-page"
import { ComponentsPage } from "@/features/components/components-page"
import { GroundTruthEditorPage } from "@/features/ground-truth/ground-truth-editor-page"
import { GroundTruthListPage } from "@/features/ground-truth/ground-truth-list-page"
import { SbomsPage } from "@/features/sboms/sboms-page"
import { NotFoundPage } from "@/pages/not-found-page"

function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/sboms" replace />} />
        <Route
          path="images"
          element={<Navigate to="/sboms" replace />}
        />
        <Route path="sboms" element={<SbomsPage />} />
        <Route path="components" element={<ComponentsPage />} />
        <Route
          path="ground-truth"
          element={<GroundTruthListPage />}
        />
        <Route
          path="ground-truth/components/:componentId"
          element={<GroundTruthEditorPage />}
        />
        <Route
          path="cpe-dictionary"
          element={<CpeDictionaryPage />}
        />
        <Route path="cpe-analysis" element={<CpeAnalysisPage />} />
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}

export default App
