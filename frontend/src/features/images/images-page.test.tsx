import {
  screen,
  waitFor,
  within,
} from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest"

import type {
  ApiHealth,
  DockerImageSummary,
} from "@/features/images/images-types"
import { renderAppAt } from "@/test/render-app"

const healthResponse: ApiHealth = {
  status: "ok",
  database: "ok",
}

const imageFixtures: DockerImageSummary[] = [
  {
    id: 1,
    repository: "docker.io/library/alpine",
    tag: "3.24.1",
    platform: "linux/amd64",
    manifest_digest: "sha256:alpha",
    pinned_reference: "docker.io/library/alpine@sha256:alpha",
    sbom_count: 1,
    total_components: 1000,
    components_with_primary_cpe: 20,
    components_without_primary_cpe: 980,
    primary_cpe_ratio: 0.02,
    unique_primary_cpes: 20,
  },
  {
    id: 2,
    repository: "docker.io/library/redis",
    tag: "8.8.0",
    platform: "linux/arm64",
    manifest_digest: "sha256:redis",
    pinned_reference: "docker.io/library/redis@sha256:redis",
    sbom_count: 1,
    total_components: 500,
    components_with_primary_cpe: 50,
    components_without_primary_cpe: 450,
    primary_cpe_ratio: 0.1,
    unique_primary_cpes: 49,
  },
]

function jsonResponse<T>(body: T, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function installSuccessfulFetch(
  images: DockerImageSummary[] = imageFixtures,
) {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = String(input)
    if (url === "/api/health/") {
      return Promise.resolve(jsonResponse(healthResponse))
    }
    if (url === "/api/images/") {
      return Promise.resolve(jsonResponse(images))
    }
    return Promise.resolve(jsonResponse({}, 404))
  })
}

async function renderLoadedPage(
  images: DockerImageSummary[] = imageFixtures,
) {
  installSuccessfulFetch(images)
  renderAppAt("/images")
  await screen.findByText("docker.io/library/alpine")
}

function firstRepositoryName(): string {
  const rows = screen.getAllByRole("link", {
    name: /View Primary CPE Components for/,
  })
  return (
    within(rows[0])
      .getByText(/^(alpine|redis)$/)
      .textContent ?? ""
  )
}

describe("ImagesPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("shows summary and table skeletons while loading", () => {
    vi.mocked(fetch).mockImplementation(
      () => new Promise<Response>(() => undefined),
    )

    renderAppAt("/images")

    expect(
      screen.getByLabelText("Loading summary metrics"),
    ).toBeInTheDocument()
    expect(
      screen.getByLabelText("Loading Docker image table"),
    ).toBeInTheDocument()
    expect(screen.getByText("Checking API")).toBeInTheDocument()
  })

  it("renders Docker image fields and coverage", async () => {
    await renderLoadedPage()

    expect(
      screen.getByText("docker.io/library/alpine"),
    ).toBeInTheDocument()
    expect(screen.getByText("3.24.1")).toBeInTheDocument()
    expect(screen.getByText("1,000")).toBeInTheDocument()
    expect(screen.getByText("980")).toBeInTheDocument()
    expect(screen.getByText("2%")).toBeInTheDocument()
    expect(screen.getByText("API Connected")).toBeInTheDocument()
  })

  it("calculates summary metrics from API images", async () => {
    await renderLoadedPage()

    const totalImagesCard = screen
      .getByText("Total Images")
      .closest<HTMLElement>('[data-slot="card"]')
    const totalComponentsCard = screen
      .getByText("Total Components")
      .closest<HTMLElement>('[data-slot="card"]')
    const primaryCpesCard = screen
      .getByText("Primary CPEs")
      .closest<HTMLElement>('[data-slot="card"]')
    const coverageCard = screen
      .getByText("CPE Coverage")
      .closest<HTMLElement>('[data-slot="card"]')

    expect(totalImagesCard).not.toBeNull()
    expect(totalComponentsCard).not.toBeNull()
    expect(primaryCpesCard).not.toBeNull()
    expect(coverageCard).not.toBeNull()
    expect(within(totalImagesCard!).getByText("2")).toBeInTheDocument()
    expect(
      within(totalComponentsCard!).getByText("1,500"),
    ).toBeInTheDocument()
    expect(
      within(primaryCpesCard!).getByText("70"),
    ).toBeInTheDocument()
    expect(
      within(coverageCard!).getByText("4.67%"),
    ).toBeInTheDocument()
  })

  it("searches repository, tag, and platform and can clear", async () => {
    const user = userEvent.setup()
    await renderLoadedPage()
    const input = screen.getByLabelText("Search Docker images")

    await user.type(input, "redis")
    expect(
      screen.queryByText("docker.io/library/alpine"),
    ).not.toBeInTheDocument()
    expect(screen.getByText("1 of 2 images")).toBeInTheDocument()

    await user.clear(input)
    await user.type(input, "3.24.1")
    expect(
      screen.getByText("docker.io/library/alpine"),
    ).toBeInTheDocument()
    expect(
      screen.queryByText("docker.io/library/redis"),
    ).not.toBeInTheDocument()

    await user.clear(input)
    await user.type(input, "arm64")
    expect(
      screen.getByText("docker.io/library/redis"),
    ).toBeInTheDocument()

    await user.clear(input)
    await user.type(input, "no-such-image")
    expect(screen.getByText("No matching images")).toBeInTheDocument()

    await user.click(
      screen.getByRole("button", { name: "Clear search" }),
    )
    expect(
      screen.getByText("docker.io/library/alpine"),
    ).toBeInTheDocument()
    expect(
      screen.getByText("docker.io/library/redis"),
    ).toBeInTheDocument()
  })

  it("shows a safe image API error without response details", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      if (String(input) === "/api/health/") {
        return Promise.resolve(jsonResponse(healthResponse))
      }
      return Promise.reject(
        new Error("<html>SECRET_DB_TRACEBACK</html>"),
      )
    })

    renderAppAt("/images")

    expect(
      await screen.findByText("Unable to load Docker images"),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        "The frontend could not reach the SBOM API.",
      ),
    ).toBeInTheDocument()
    expect(
      screen.queryByText(/SECRET_DB_TRACEBACK/),
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole("button", { name: "Retry" }),
    ).toBeInTheDocument()
  })

  it("retries a failed image request and renders data", async () => {
    const user = userEvent.setup()
    let imageAttempts = 0
    vi.mocked(fetch).mockImplementation((input) => {
      if (String(input) === "/api/health/") {
        return Promise.resolve(jsonResponse(healthResponse))
      }
      imageAttempts += 1
      if (imageAttempts === 1) {
        return Promise.reject(new Error("temporary failure"))
      }
      return Promise.resolve(jsonResponse(imageFixtures))
    })

    renderAppAt("/images")
    await user.click(
      await screen.findByRole("button", { name: "Retry" }),
    )

    expect(
      await screen.findByText("docker.io/library/alpine"),
    ).toBeInTheDocument()
    expect(imageAttempts).toBe(2)
  })

  it("keeps image data visible when health is unavailable", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      if (String(input) === "/api/health/") {
        return Promise.reject(new Error("health unavailable"))
      }
      return Promise.resolve(jsonResponse(imageFixtures))
    })

    renderAppAt("/images")

    expect(
      await screen.findByText("docker.io/library/alpine"),
    ).toBeInTheDocument()
    expect(
      await screen.findByText("API Unavailable"),
    ).toBeInTheDocument()
  })

  it("distinguishes an empty API dataset", async () => {
    installSuccessfulFetch([])
    renderAppAt("/images")

    expect(
      await screen.findByText("No Docker images available"),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        "Import SBOM data before using the validation workbench.",
      ),
    ).toBeInTheDocument()
  })

  it("sorts repository and component columns from keyboard controls", async () => {
    const user = userEvent.setup()
    await renderLoadedPage()

    expect(firstRepositoryName()).toBe("alpine")

    const repositorySort = screen.getByRole("button", {
      name: "Sort by Repository",
    })
    repositorySort.focus()
    await user.keyboard("{Enter}")
    await waitFor(() => {
      expect(firstRepositoryName()).toBe("redis")
    })

    const componentSort = screen.getByRole("button", {
      name: "Sort by Components",
    })
    componentSort.focus()
    await user.keyboard("{Enter}")
    await waitFor(() => {
      expect(firstRepositoryName()).toBe("redis")
    })
  })

  it("opens an image Component queue when its row is clicked", async () => {
    const user = userEvent.setup()
    await renderLoadedPage()

    await user.click(
      screen.getByRole("link", {
        name: /View Primary CPE Components for docker.io\/library\/alpine:3.24.1/,
      }),
    )

    expect(
      await screen.findByRole("heading", {
        name: "Primary CPE Components",
      }),
    ).toBeInTheDocument()
    expect(screen.getByTestId("route-location")).toHaveTextContent(
      "/components?image_id=1",
    )
    expect(
      vi
        .mocked(fetch)
        .mock.calls.filter(
          ([input]) => String(input) === "/api/health/",
        ),
    ).toHaveLength(1)
  })

  it.each([
    ["Enter", "{Enter}"],
    ["Space", " "],
  ])(
    "opens an image Component queue with the %s key",
    async (_keyName, keyboardInput) => {
      const user = userEvent.setup()
      await renderLoadedPage()
      const imageRow = screen.getByRole("link", {
        name: /View Primary CPE Components for docker.io\/library\/alpine:3.24.1/,
      })

      imageRow.focus()
      await user.keyboard(keyboardInput)

      expect(
        await screen.findByRole("heading", {
          name: "Primary CPE Components",
        }),
      ).toBeInTheDocument()
      expect(screen.getByTestId("route-location")).toHaveTextContent(
        "/components?image_id=1",
      )
    },
  )
})
