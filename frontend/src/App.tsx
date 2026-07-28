import {
  Navigate,
  Route,
  Routes,
} from "react-router-dom"

import { AppShell } from "@/components/app-shell"
import { CpeDictionaryPage } from "@/features/cpe-dictionary/cpe-dictionary-page"
import { ComponentsPage } from "@/features/components/components-page"
import { GroundTruthEditorPage } from "@/features/ground-truth/ground-truth-editor-page"
import { GroundTruthListPage } from "@/features/ground-truth/ground-truth-list-page"
import { ImagesPage } from "@/features/images/images-page"
import { NotFoundPage } from "@/pages/not-found-page"

function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/images" replace />} />
        <Route path="images" element={<ImagesPage />} />
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
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}

export default App
