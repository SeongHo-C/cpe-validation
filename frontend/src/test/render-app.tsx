import { render } from "@testing-library/react"
import {
  createMemoryRouter,
  MemoryRouter,
  RouterProvider,
} from "react-router-dom"

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

export function renderAppWithHistory(initialEntries: string[]) {
  const router = createMemoryRouter(
    [
      {
        path: "*",
        element: (
          <>
            <App />
            <RouteLocationProbe />
          </>
        ),
      },
    ],
    { initialEntries },
  )
  return {
    ...render(<RouterProvider router={router} />),
    router,
  }
}
