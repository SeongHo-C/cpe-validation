import { render } from "@testing-library/react"
import { MemoryRouter } from "react-router-dom"

import App from "@/App"
import { RouteLocationProbe } from "@/test/route-location-probe"

export function renderAppAt(initialEntry: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <App />
      <RouteLocationProbe />
    </MemoryRouter>,
  )
}
