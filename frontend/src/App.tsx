import {
  Navigate,
  Route,
  Routes,
} from "react-router-dom"

import { AppShell } from "@/components/app-shell"
import { ComponentsPage } from "@/features/components/components-page"
import { ImagesPage } from "@/features/images/images-page"
import { NotFoundPage } from "@/pages/not-found-page"

function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/images" replace />} />
        <Route path="images" element={<ImagesPage />} />
        <Route path="components" element={<ComponentsPage />} />
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}

export default App
