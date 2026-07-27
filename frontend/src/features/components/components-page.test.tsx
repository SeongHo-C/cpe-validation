import {
  act,
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
  ComponentSummary,
  DockerImageDetail,
  PaginatedResponse,
} from "@/features/components/components-types"
import {
  renderAppAt,
  renderAppWithHistory,
} from "@/test/render-app"

const componentFixture: ComponentSummary = {
  id: 101,
  image: {
    id: 1,
    repository: "docker.io/library/alpine",
    tag: "3.24.1",
  },
  sbom_document_id: 11,
  component_type: "library",
  name: "curl",
  version: "8.14.1-r1",
  publisher: "Daniel Stenberg",
  purl: "pkg:apk/alpine/curl@8.14.1-r1",
  cpe: "cpe:2.3:a:haxx:curl:8.14.1:*:*:*:*:*:*:*",
  structural_status: "STRUCTURALLY_VALID",
  dictionary_status: "OFFICIAL_ACTIVE",
  cpe_fields: {
    part: "a",
    vendor: "haxx",
    product: "curl",
    version: "8.14.1",
    update: "*",
    edition: "*",
    language: "*",
    sw_edition: "*",
    target_sw: "*",
    target_hw: "*",
    other: "*",
  },
}

const imageDetailFixture: DockerImageDetail = {
  id: 1,
  repository: "docker.io/library/alpine",
  tag: "3.24.1",
  platform: "linux/amd64",
  manifest_digest: "sha256:alpha",
  pinned_reference: "docker.io/library/alpine@sha256:alpha",
  sbom_count: 1,
  total_components: 96,
  components_with_primary_cpe: 16,
  components_without_primary_cpe: 80,
  primary_cpe_ratio: 1 / 6,
  unique_primary_cpes: 16,
}

const expectedComponentTableHeaders = [
  "Component",
  "Version",
  "Image",
  "Primary CPE",
  "Dictionary Status",
]

function jsonResponse<T>(body: T, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function paginatedResponse(
  url: URL,
  results: ComponentSummary[] = [componentFixture],
  count = results.length,
): PaginatedResponse<ComponentSummary> {
  const page = Number(url.searchParams.get("page") ?? "1")
  const pageSize = Number(
    url.searchParams.get("page_size") ?? "50",
  )
  const totalPages =
    count === 0 ? 0 : Math.max(Math.ceil(count / pageSize), 1)
  return {
    count,
    page,
    page_size: pageSize,
    total_pages: totalPages,
    next: page < totalPages ? "next" : null,
    previous: page > 1 ? "previous" : null,
    results,
  }
}

function installSuccessfulFetch({
  componentResults = [componentFixture],
  componentCount = componentResults.length,
  imageDetail = imageDetailFixture,
}: {
  componentResults?: ComponentSummary[]
  componentCount?: number
  imageDetail?: DockerImageDetail
} = {}) {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = new URL(String(input), "http://frontend.test")
    if (url.pathname === "/api/health/") {
      return Promise.resolve(
        jsonResponse({ status: "ok", database: "ok" }),
      )
    }
    if (url.pathname === "/api/images/1/") {
      return Promise.resolve(jsonResponse(imageDetail))
    }
    if (url.pathname === "/api/components/") {
      return Promise.resolve(
        jsonResponse(
          paginatedResponse(
            url,
            componentResults,
            componentCount,
          ),
        ),
      )
    }
    if (url.pathname === "/api/images/") {
      return Promise.resolve(jsonResponse([]))
    }
    return Promise.resolve(jsonResponse({}, 404))
  })
}

function componentRequestUrls(): URL[] {
  return vi
    .mocked(fetch)
    .mock.calls.map(([input]) => new URL(String(input), "http://frontend.test"))
    .filter((url) => url.pathname === "/api/components/")
}

async function waitForComponentRequest(
  predicate: (url: URL) => boolean,
): Promise<URL> {
  let matchingUrl: URL | undefined
  await waitFor(() => {
    matchingUrl = componentRequestUrls().find(predicate)
    expect(matchingUrl).toBeDefined()
  })
  return matchingUrl!
}

describe("Components routing and page", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("routes root, images, components, and unknown paths", async () => {
    installSuccessfulFetch()
    const root = renderAppAt("/")
    expect(
      await screen.findByRole("heading", {
        name: "Docker Images",
      }),
    ).toBeInTheDocument()
    expect(screen.getByTestId("route-location")).toHaveTextContent(
      "/images",
    )
    root.unmount()

    renderAppAt("/components")
    expect(
      await screen.findByRole("heading", {
        name: "Primary CPE Components",
      }),
    ).toBeInTheDocument()
    expect(await screen.findByText("curl")).toBeInTheDocument()

    root.unmount()
  })

  it("renders the Not Found route", () => {
    installSuccessfulFetch()
    renderAppAt("/does-not-exist")

    expect(
      screen.getByRole("heading", { name: "Page not found" }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("link", {
        name: "Back to Docker Images",
      }),
    ).toHaveAttribute("href", "/images")
  })

  it("marks route navigation and keeps Workbench disabled", async () => {
    installSuccessfulFetch()
    const view = renderAppAt("/images")
    const imagesLink = screen.getByRole("link", { name: "Images" })
    expect(imagesLink).toHaveAttribute("aria-current", "page")
    view.unmount()

    renderAppAt("/components")
    expect(
      screen.getByRole("link", { name: "Components" }),
    ).toHaveAttribute("aria-current", "page")
    expect(
      screen.getByText("Workbench").closest("[aria-disabled]"),
    ).toHaveAttribute("aria-disabled", "true")
  })

  it("requests the default Primary CPE queue safely", async () => {
    installSuccessfulFetch()
    renderAppAt("/components")

    const request = await waitForComponentRequest(() => true)
    expect(request.searchParams.get("has_cpe")).toBe("true")
    expect(request.searchParams.get("page")).toBe("1")
    expect(request.searchParams.get("page_size")).toBe("50")
    expect(request.searchParams.get("ordering")).toBe("name")
    expect(request.searchParams.has("image_id")).toBe(false)
  })

  it("loads the selected image independently and shows its scope", async () => {
    installSuccessfulFetch({ componentCount: 16 })
    renderAppAt("/components?image_id=1")

    expect(
      await screen.findByText("alpine:3.24.1"),
    ).toBeInTheDocument()
    expect(
      screen.getAllByText("docker.io/library/alpine"),
    ).toHaveLength(2)
    expect(screen.getByText("linux/amd64")).toBeInTheDocument()

    const request = await waitForComponentRequest(
      (url) => url.searchParams.get("image_id") === "1",
    )
    expect(request.searchParams.get("has_cpe")).toBe("true")
    expect(
      vi
        .mocked(fetch)
        .mock.calls.some(
          ([input]) => String(input) === "/api/images/1/",
        ),
    ).toBe(true)
  })

  it("renders only the five manual-review columns", async () => {
    installSuccessfulFetch()
    renderAppAt("/components")

    await screen.findByText("curl")
    const table = screen.getByRole("table")
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent?.trim()),
    ).toEqual(expectedComponentTableHeaders)
    expect(
      within(table).queryByRole("columnheader", {
        name: "Structural Status",
      }),
    ).not.toBeInTheDocument()
    expect(
      within(table).queryByText("STRUCTURALLY_VALID"),
    ).not.toBeInTheDocument()
    expect(
      within(table).queryByRole("columnheader", {
        name: "Type",
      }),
    ).not.toBeInTheDocument()
    expect(
      within(table).queryByRole("columnheader", {
        name: "Publisher",
      }),
    ).not.toBeInTheDocument()
    expect(
      within(table).queryByRole("columnheader", {
        name: "Part",
      }),
    ).not.toBeInTheDocument()

    const componentName = within(table).getByText("curl")
    expect(componentName).toHaveAttribute("title", "curl")
    expect(componentName).toHaveClass("truncate")

    const version = within(table).getByText("8.14.1-r1")
    expect(version).toHaveAttribute("title", "8.14.1-r1")
    expect(version).toHaveClass("truncate")

    const image = within(table).getByText("alpine")
    expect(image).toHaveAttribute(
      "title",
      "docker.io/library/alpine:3.24.1",
    )
    expect(image).toHaveClass("truncate")

    const primaryCpe = within(table).getByText(
      componentFixture.cpe,
    )
    expect(primaryCpe).toHaveAttribute(
      "title",
      componentFixture.cpe,
    )
    expect(primaryCpe).toHaveClass("block", "truncate")
    expect(
      within(table).queryByText("haxx:curl"),
    ).not.toBeInTheDocument()

    expect(
      within(table).getByText("Official Active"),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("columnheader", {
        name: "Dictionary Status",
      }),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole("button", {
        name: "Sort by Dictionary Status",
      }),
    ).not.toBeInTheDocument()
  })

  it("defends the table against long review values", async () => {
    const longName =
      "a-component-name-that-is-deliberately-long-for-table-layout-verification"
    const longVersion =
      "2026.07.27-build-with-an-unusually-long-version-suffix"
    const longRepository =
      "docker.io/research/namespace/with-a-long-path/component-image-with-a-long-name"
    const longTag =
      "release-with-an-unusually-long-tag-for-layout-verification"
    const longCpe =
      "cpe:2.3:a:vendor-with-a-long-name:product-with-a-long-name:2026.07.27:update:edition:language:sw_edition:target_sw:target_hw:other"
    installSuccessfulFetch({
      componentResults: [
        {
          ...componentFixture,
          name: longName,
          version: longVersion,
          image: {
            ...componentFixture.image,
            repository: longRepository,
            tag: longTag,
          },
          cpe: longCpe,
        },
      ],
    })
    renderAppAt("/components")

    await screen.findByText(longName)
    const table = screen.getByRole("table")
    const componentName = within(table).getByText(longName)
    expect(componentName).toHaveAttribute("title", longName)
    expect(componentName).toHaveClass("truncate")

    const version = within(table).getByText(longVersion)
    expect(version).toHaveAttribute("title", longVersion)
    expect(version).toHaveClass("truncate")

    const imageName = within(table).getByText(
      "component-image-with-a-long-name",
    )
    expect(imageName).toHaveAttribute(
      "title",
      `${longRepository}:${longTag}`,
    )
    expect(imageName).toHaveClass("truncate")
    expect(within(table).getByText(longRepository)).toHaveClass(
      "truncate",
    )
    expect(within(table).getByText(longTag)).toHaveClass(
      "truncate",
    )

    const primaryCpe = within(table).getByText(longCpe)
    expect(primaryCpe).toHaveAttribute("title", longCpe)
    expect(primaryCpe).toHaveClass("truncate")
  })

  it("renders all four Dictionary status badges", async () => {
    const statuses = [
      ["OFFICIAL_ACTIVE", "Official Active"],
      ["OFFICIAL_DEPRECATED", "Official Deprecated"],
      ["NOT_IN_DICTIONARY", "Not in Dictionary"],
      ["NOT_PRESENT", "Primary CPE Not Present"],
    ] as const
    installSuccessfulFetch({
      componentResults: statuses.map(
        ([dictionaryStatus], index) => ({
          ...componentFixture,
          id: componentFixture.id + index,
          name: `Component ${index}`,
          cpe:
            dictionaryStatus === "NOT_PRESENT"
              ? ""
              : componentFixture.cpe,
          cpe_fields:
            dictionaryStatus === "NOT_PRESENT"
              ? null
              : componentFixture.cpe_fields,
          structural_status:
            dictionaryStatus === "NOT_PRESENT"
              ? "NOT_PRESENT"
              : "STRUCTURALLY_VALID",
          dictionary_status: dictionaryStatus,
        }),
      ),
    })
    renderAppAt("/components")

    await screen.findByText("Component 0")
    const table = screen.getByRole("table")
    for (const [, label] of statuses) {
      expect(within(table).getByText(label)).toBeInTheDocument()
    }
    const notPresentBadge = within(table).getByText(
      "Primary CPE Not Present",
    )
    const notPresentRow = notPresentBadge.closest("tr")
    expect(notPresentRow).not.toBeNull()
    const emptyCpe = within(notPresentRow!).getByText("—")
    expect(emptyCpe).not.toHaveAttribute("title")
    expect(emptyCpe).toHaveClass("truncate")
  })

  it("filters Dictionary status on the server and preserves URL state", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt(
      "/components?image_id=1&component_id=101&search=curl&page=3&page_size=25",
    )
    await screen.findByText("curl")

    const filter = screen.getByLabelText(
      "Dictionary status filter",
    )
    expect(filter).toHaveValue("")
    expect(
      screen.getByRole("option", {
        name: "All Dictionary Statuses",
      }),
    ).toBeInTheDocument()
    for (const option of [
      "Official Active",
      "Official Deprecated",
      "Not in Dictionary",
      "Primary CPE Not Present",
    ]) {
      expect(
        screen.getByRole("option", { name: option }),
      ).toBeInTheDocument()
    }

    await user.selectOptions(filter, "NOT_IN_DICTIONARY")
    const request = await waitForComponentRequest(
      (url) =>
        url.searchParams.get("dictionary_status")
        === "NOT_IN_DICTIONARY",
    )
    expect(request.searchParams.get("has_cpe")).toBe("true")
    expect(request.searchParams.get("image_id")).toBe("1")
    expect(request.searchParams.get("search")).toBe("curl")
    expect(request.searchParams.get("page_size")).toBe("25")
    expect(request.searchParams.get("page")).toBe("1")
    await waitFor(() => {
      const location =
        screen.getByTestId("route-location").textContent ?? ""
      const parameters = new URL(
        location,
        "http://frontend.test",
      ).searchParams
      expect(parameters.get("dictionary_status")).toBe(
        "NOT_IN_DICTIONARY",
      )
      expect(parameters.get("image_id")).toBe("1")
      expect(parameters.get("search")).toBe("curl")
      expect(parameters.get("page_size")).toBe("25")
      expect(parameters.has("page")).toBe(false)
      expect(parameters.has("component_id")).toBe(false)
    })
  })

  it("removes the Dictionary URL parameter for All", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt(
      "/components?dictionary_status=OFFICIAL_ACTIVE",
    )
    const filter = await screen.findByLabelText(
      "Dictionary status filter",
    )
    expect(filter).toHaveValue("OFFICIAL_ACTIVE")

    await user.selectOptions(filter, "")
    await waitForComponentRequest(
      (url) => !url.searchParams.has("dictionary_status"),
    )
    await waitFor(() => {
      expect(
        screen.getByTestId("route-location"),
      ).not.toHaveTextContent("dictionary_status")
    })
  })

  it("requests missing Primary CPE Components for NOT_PRESENT", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch({
      componentResults: [
        {
          ...componentFixture,
          cpe: "",
          cpe_fields: null,
          structural_status: "NOT_PRESENT",
          dictionary_status: "NOT_PRESENT",
        },
      ],
    })
    renderAppAt("/components")
    await screen.findByText("curl")

    await user.selectOptions(
      screen.getByLabelText("Dictionary status filter"),
      "NOT_PRESENT",
    )
    const request = await waitForComponentRequest(
      (url) =>
        url.searchParams.get("dictionary_status")
        === "NOT_PRESENT",
    )
    expect(request.searchParams.get("has_cpe")).toBe("false")
    const table = screen.getByRole("table")
    const notPresentBadge = within(table).getByText(
      "Primary CPE Not Present",
    )
    const resultRow = notPresentBadge.closest("tr")
    expect(resultRow).not.toBeNull()
    expect(within(resultRow!).getByText("—")).toBeInTheDocument()
    expect(
      screen.getByText(
        "Showing components without a Primary CPE from all pilot images.",
      ),
    ).toBeInTheDocument()
  })

  it("restores Dictionary status through navigation history", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    const { router } = renderAppWithHistory([
      "/components?dictionary_status=OFFICIAL_ACTIVE",
    ])
    const filter = await screen.findByLabelText(
      "Dictionary status filter",
    )
    expect(filter).toHaveValue("OFFICIAL_ACTIVE")

    await user.selectOptions(filter, "NOT_IN_DICTIONARY")
    await waitFor(() => {
      expect(filter).toHaveValue("NOT_IN_DICTIONARY")
    })
    await user.selectOptions(filter, "OFFICIAL_DEPRECATED")
    await waitFor(() => {
      expect(filter).toHaveValue("OFFICIAL_DEPRECATED")
    })

    await act(async () => {
      await router.navigate(-1)
    })
    await waitFor(() => {
      expect(filter).toHaveValue("NOT_IN_DICTIONARY")
    })
    await act(async () => {
      await router.navigate(1)
    })
    await waitFor(() => {
      expect(filter).toHaveValue("OFFICIAL_DEPRECATED")
    })
  })

  it("uses the existing error UI for a status-filter 400", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (
        url.pathname === "/api/components/" &&
        url.searchParams.has("dictionary_status")
      ) {
        return Promise.resolve(jsonResponse({}, 400))
      }
      if (url.pathname === "/api/components/") {
        return Promise.resolve(
          jsonResponse(paginatedResponse(url)),
        )
      }
      return Promise.resolve(jsonResponse({}, 404))
    })
    renderAppAt("/components")
    await screen.findByText("curl")

    await user.selectOptions(
      screen.getByLabelText("Dictionary status filter"),
      "OFFICIAL_ACTIVE",
    )

    expect(
      await screen.findByText("Unable to load components"),
    ).toBeInTheDocument()
  })

  it("debounces server search, updates the URL, and resets page", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/components?page=3")
    await screen.findByText("curl")

    await user.type(
      screen.getByLabelText("Search components"),
      " openssl ",
    )

    const request = await waitForComponentRequest(
      (url) => url.searchParams.get("search") === "openssl",
    )
    expect(request.searchParams.get("page")).toBe("1")
    await waitFor(() => {
      expect(screen.getByTestId("route-location")).toHaveTextContent(
        "/components?search=openssl",
      )
    })
  })

  it("applies supported server sorting and resets page", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/components?page=3")
    await screen.findByText("curl")

    await user.click(
      screen.getByRole("button", { name: "Sort by Component" }),
    )
    const nameRequest = await waitForComponentRequest(
      (url) => url.searchParams.get("ordering") === "-name",
    )
    expect(nameRequest.searchParams.get("page")).toBe("1")

    await user.click(
      screen.getByRole("button", { name: "Sort by Image" }),
    )
    await waitForComponentRequest(
      (url) => url.searchParams.get("ordering") === "repository",
    )
    expect(
      screen.queryByRole("button", {
        name: "Sort by Primary CPE",
      }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole("button", { name: "Sort by Part" }),
    ).not.toBeInTheDocument()
  })

  it("updates page size on the server and resets page", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/components?page=3")
    await screen.findByText("curl")

    await user.selectOptions(
      screen.getByLabelText("Components per page"),
      "100",
    )
    const request = await waitForComponentRequest(
      (url) => url.searchParams.get("page_size") === "100",
    )
    expect(request.searchParams.get("page")).toBe("1")
    expect(screen.getByTestId("route-location")).toHaveTextContent(
      "page_size=100",
    )
  })

  it("supports First, Previous, Next, and Last pagination", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch({ componentCount: 160 })
    renderAppAt("/components?page=2&page_size=50")
    await screen.findByText("Page 2 of 4")

    await user.click(
      screen.getByRole("button", { name: "Next page" }),
    )
    await screen.findByText("Page 3 of 4")

    await user.click(
      screen.getByRole("button", { name: "Last page" }),
    )
    await screen.findByText("Page 4 of 4")
    expect(
      screen.getByRole("button", { name: "Next page" }),
    ).toBeDisabled()

    await user.click(
      screen.getByRole("button", { name: "Previous page" }),
    )
    await screen.findByText("Page 3 of 4")

    await user.click(
      screen.getByRole("button", { name: "First page" }),
    )
    await screen.findByText("Page 1 of 4")
    expect(
      screen.getByRole("button", { name: "Previous page" }),
    ).toBeDisabled()
  })

  it("restores filters, ordering, page, and page size from the URL", async () => {
    installSuccessfulFetch({ componentCount: 60 })
    renderAppAt(
      "/components?search=curl&ordering=-version&page=2&page_size=25&dictionary_status=NOT_IN_DICTIONARY",
    )
    await screen.findByText("Page 2 of 3")

    expect(screen.getByLabelText("Search components")).toHaveValue(
      "curl",
    )
    expect(screen.getByLabelText("Sort components")).toHaveValue(
      "-version",
    )
    expect(
      screen.getByLabelText("Components per page"),
    ).toHaveValue("25")
    expect(
      screen.getByLabelText("Dictionary status filter"),
    ).toHaveValue("NOT_IN_DICTIONARY")
    await waitForComponentRequest(
      (url) =>
        url.searchParams.get("search") === "curl" &&
        url.searchParams.get("ordering") === "-version" &&
        url.searchParams.get("page") === "2" &&
        url.searchParams.get("page_size") === "25" &&
        url.searchParams.get("dictionary_status")
          === "NOT_IN_DICTIONARY",
    )
  })

  it("shows a safe Components error and succeeds on Retry", async () => {
    const user = userEvent.setup()
    let componentAttempts = 0
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/components/") {
        componentAttempts += 1
        if (componentAttempts === 1) {
          return Promise.resolve(
            jsonResponse(
              { detail: "<html>SECRET_TRACEBACK</html>" },
              500,
            ),
          )
        }
        return Promise.resolve(
          jsonResponse(paginatedResponse(url)),
        )
      }
      return Promise.resolve(jsonResponse({}, 404))
    })

    renderAppAt("/components")
    expect(
      await screen.findByText("Unable to load components"),
    ).toBeInTheDocument()
    expect(
      screen.queryByText(/SECRET_TRACEBACK/),
    ).not.toBeInTheDocument()

    await user.click(
      screen.getByRole("button", { name: "Retry" }),
    )
    expect(await screen.findByText("curl")).toBeInTheDocument()
    expect(componentAttempts).toBe(2)
  })

  it("keeps Components visible when only image detail fails", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/images/1/") {
        return Promise.resolve(jsonResponse({}, 500))
      }
      if (url.pathname === "/api/components/") {
        return Promise.resolve(
          jsonResponse(paginatedResponse(url)),
        )
      }
      return Promise.resolve(jsonResponse({}, 404))
    })

    renderAppAt("/components?image_id=1")
    expect(
      await screen.findByText("Unable to load image details"),
    ).toBeInTheDocument()
    expect(await screen.findByText("curl")).toBeInTheDocument()
  })

  it("shows a not-found image scope without hiding the queue", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/images/1/") {
        return Promise.resolve(jsonResponse({}, 404))
      }
      if (url.pathname === "/api/components/") {
        return Promise.resolve(
          jsonResponse(paginatedResponse(url)),
        )
      }
      return Promise.resolve(jsonResponse({}, 404))
    })

    renderAppAt("/components?image_id=1")
    expect(
      await screen.findByText("Docker image not found"),
    ).toBeInTheDocument()
    expect(await screen.findByText("curl")).toBeInTheDocument()
  })

  it("clears a selected image filter and resets the page", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/components?image_id=1&page=3")
    await screen.findByText("alpine:3.24.1")

    await user.click(
      screen.getByRole("button", {
        name: "Clear image filter",
      }),
    )
    await waitForComponentRequest(
      (url) =>
        !url.searchParams.has("image_id") &&
        url.searchParams.get("page") === "1",
    )
    expect(screen.getByTestId("route-location")).toHaveTextContent(
      "/components",
    )
    expect(
      await screen.findByText("All Docker Images"),
    ).toBeInTheDocument()
  })

  it("distinguishes empty scope and empty search results", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch({
      componentResults: [],
      componentCount: 0,
    })
    const emptyScope = renderAppAt("/components")
    expect(
      await screen.findByText(
        "No primary CPE components available",
      ),
    ).toBeInTheDocument()
    emptyScope.unmount()

    renderAppAt("/components?search=missing")
    expect(
      await screen.findByText("No matching components"),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("button", { name: "Clear search" }),
    ).toBeInTheDocument()
    await user.click(
      screen.getByRole("button", { name: "Clear search" }),
    )
    expect(screen.getByLabelText("Search components")).toHaveValue("")
    expect(screen.getByTestId("route-location")).toHaveTextContent(
      "/components",
    )
  })

  it("rejects an invalid image_id before any data request", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/components?image_id=not-a-number")

    expect(
      screen.getByText("Invalid image filter"),
    ).toBeInTheDocument()
    expect(componentRequestUrls()).toHaveLength(0)
    expect(
      vi
        .mocked(fetch)
        .mock.calls.some(([input]) =>
          String(input).includes("/api/images/not-a-number/"),
        ),
    ).toBe(false)

    await user.click(
      screen.getByRole("button", {
        name: "View all components",
      }),
    )
    expect(await screen.findByText("curl")).toBeInTheDocument()
    expect(screen.getByTestId("route-location")).toHaveTextContent(
      "/components",
    )
  })

  it("shows initial loading skeletons before data arrives", async () => {
    let resolveComponents:
      | ((response: Response) => void)
      | undefined
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/components/") {
        return new Promise<Response>((resolve) => {
          resolveComponents = resolve
        })
      }
      return Promise.resolve(jsonResponse({}, 404))
    })

    renderAppAt("/components")
    expect(
      screen.getByLabelText(
        "Loading Primary CPE Component table",
      ),
    ).toBeInTheDocument()
    const loadingTable = screen.getByRole("table")
    expect(
      within(loadingTable)
        .getAllByRole("columnheader")
        .map((header) => header.textContent?.trim()),
    ).toEqual(expectedComponentTableHeaders)

    await act(async () => {
      resolveComponents?.(
        jsonResponse(
          paginatedResponse(
            new URL(
              "/api/components/?page=1&page_size=50",
              "http://frontend.test",
            ),
          ),
        ),
      )
    })
    expect(await screen.findByText("curl")).toBeInTheDocument()
    expect(
      screen.queryByLabelText(
        "Loading Primary CPE Component table",
      ),
    ).not.toBeInTheDocument()
  })
})
