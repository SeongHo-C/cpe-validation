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
  CpeDictionaryDetail,
  CpeDictionarySearchResponse,
} from "@/features/cpe-dictionary/cpe-dictionary-types"
import type { ComponentDetail } from "@/features/components/components-types"
import {
  renderAppAt,
  renderAppWithHistory,
} from "@/test/render-app"

const cpeName =
  "cpe:2.3:a:haxx:curl:8.14.1:*:*:*:*:*:*:*"
const cpeNameId = "11111111-1111-4111-8111-111111111111"

const searchResponse: CpeDictionarySearchResponse = {
  snapshot: {
    snapshot_id: "20260725T035002Z",
    manifest_sha256: "d".repeat(64),
    status: "COMPLETE",
  },
  query: {
    q: "curl",
    part: "",
    vendor: "",
    product: "",
    version: "",
    cpe_name: "",
    deprecated: "active",
  },
  count: 26,
  page: 1,
  page_size: 25,
  results: [
    {
      id: 1,
      cpe_name_id: cpeNameId,
      cpe_name: cpeName,
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
      deprecated: false,
      title: "curl command line tool",
      snapshot_id: "20260725T035002Z",
    },
    {
      id: 2,
      cpe_name_id: "22222222-2222-4222-8222-222222222222",
      cpe_name:
        "cpe:2.3:a:oldvendor:curl:7.0:*:*:*:*:*:*:*",
      part: "a",
      vendor: "oldvendor",
      product: "curl",
      version: "7.0",
      update: "*",
      edition: "*",
      language: "*",
      sw_edition: "*",
      target_sw: "*",
      target_hw: "*",
      other: "*",
      deprecated: true,
      title: "Old curl",
      snapshot_id: "20260725T035002Z",
    },
  ],
}

const detailResponse: CpeDictionaryDetail = {
  id: 1,
  cpe_name_id: cpeNameId,
  cpe_name: cpeName,
  snapshot_id: "20260725T035002Z",
  snapshot_manifest_sha256: "d".repeat(64),
  deprecated: false,
  deprecated_by: [],
  deprecates: [],
  created_at_nvd: "2020-01-01T00:00:00Z",
  last_modified_at_nvd: "2026-01-01T00:00:00Z",
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
  titles: [
    { lang: "en", title: "curl command line tool" },
    { lang: "fr", title: "curl français" },
  ],
  references: [
    { url: "https://curl.se/", type: "Vendor" },
  ],
}

const componentResponse: ComponentDetail = {
  id: 101,
  image: {
    id: 1,
    repository: "docker.io/library/alpine",
    tag: "3.24.1",
  },
  sbom_document_id: 11,
  component_type: "library",
  group: "alpine",
  name: "curl",
  version: "8.14.1-r1",
  publisher: "Daniel Stenberg",
  purl: "pkg:apk/alpine/curl@8.14.1-r1",
  cpe: cpeName,
  structural_status: "STRUCTURALLY_VALID",
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
  dictionary_status: "OFFICIAL_ACTIVE",
  bom_ref: "pkg:apk/alpine/curl@8.14.1-r1",
  properties: [
    {
      name: "syft:package:foundBy",
      value: "apk-db-cataloger",
    },
    { name: "syft:location:0:path", value: "/lib/apk/db" },
  ],
  sbom_document: {
    id: 11,
    source_path: "pilot/results/sboms/alpine-3.24.1.cdx.json",
    spec_version: "1.7",
    generator_name: "syft",
    generator_version: "1.49.0",
    source_type: "registry",
    scope: "squashed",
  },
  structural_error_message: null,
  dictionary_match: {
    snapshot_id: "20260725T035002Z",
    cpe_name_id: cpeNameId,
    matched_cpe_name: cpeName,
    deprecated: false,
  },
}

function jsonResponse<T>(body: T, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function installFetch(
  options: {
    empty?: boolean
    searchError?: boolean
  } = {},
) {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = new URL(String(input), "http://frontend.test")
    if (url.pathname === "/api/health/") {
      return Promise.resolve(
        jsonResponse({ status: "ok", database: "ok" }),
      )
    }
    if (url.pathname === "/api/components/101/") {
      return Promise.resolve(jsonResponse(componentResponse))
    }
    if (url.pathname === "/api/cpe-dictionary/snapshot/") {
      return Promise.resolve(jsonResponse(searchResponse.snapshot))
    }
    if (url.pathname === "/api/cpe-dictionary/") {
      if (options.searchError) {
        return Promise.resolve(
          jsonResponse(
            {
              code: "invalid_search_query",
              detail: "q must contain at least two characters.",
            },
            400,
          ),
        )
      }
      const page = Number(url.searchParams.get("page") ?? 1)
      const pageSize = Number(
        url.searchParams.get("page_size") ?? 25,
      ) as 25 | 50 | 100
      return Promise.resolve(
        jsonResponse({
          ...searchResponse,
          count: options.empty ? 0 : searchResponse.count,
          results: options.empty ? [] : searchResponse.results,
          page,
          page_size: pageSize,
        }),
      )
    }
    if (
      url.pathname ===
      `/api/cpe-dictionary/${cpeNameId}/`
    ) {
      return Promise.resolve(jsonResponse(detailResponse))
    }
    return Promise.resolve(jsonResponse({}, 404))
  })
}

function dictionaryRequests(): URL[] {
  return vi
    .mocked(fetch)
    .mock.calls.map(
      ([input]) => new URL(String(input), "http://frontend.test"),
    )
    .filter((url) => url.pathname === "/api/cpe-dictionary/")
}

function currentParameters(): URLSearchParams {
  const location =
    screen.getByTestId("route-location").textContent ?? ""
  return new URL(location, "http://frontend.test").searchParams
}

describe("CPE Dictionary Workbench", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn())
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("renders the route and sidebar without an initial search", async () => {
    installFetch()
    renderAppAt("/cpe-dictionary")

    expect(
      screen.getByRole("heading", { name: "CPE Dictionary" }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("link", { name: "CPE Dictionary" }),
    ).toHaveAttribute("href", "/cpe-dictionary")
    expect(
      screen.getByText("Search the selected Dictionary snapshot"),
    ).toBeInTheDocument()
    expect(
      await screen.findByText("20260725T035002Z"),
    ).toBeInTheDocument()
    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        "/api/health/",
        expect.anything(),
      ),
    )
    expect(dictionaryRequests()).toHaveLength(0)
  })

  it("submits keyword only on Search and syncs the URL", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/cpe-dictionary")

    await user.type(screen.getByLabelText("Keyword"), "curl")
    expect(dictionaryRequests()).toHaveLength(0)
    await user.click(screen.getByRole("button", { name: "Search" }))

    expect(
      await screen.findByText("26 results"),
    ).toBeInTheDocument()
    expect(dictionaryRequests()).toHaveLength(1)
    expect(dictionaryRequests()[0].searchParams.get("q")).toBe(
      "curl",
    )
    expect(currentParameters().get("q")).toBe("curl")
    expect(currentParameters().get("deprecated")).toBe("active")
  })

  it("supports Enter and structured filters without normalization", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/cpe-dictionary")

    await user.selectOptions(screen.getByLabelText("Part"), "a")
    await user.type(screen.getByLabelText("Vendor"), "HAXX")
    await user.type(screen.getByLabelText("Product"), "curl")
    await user.type(screen.getByLabelText("Version"), "8.14.1-r1")
    await user.selectOptions(
      screen.getByLabelText("Status"),
      "all",
    )
    screen.getByLabelText("Version").focus()
    await user.keyboard("{Enter}")

    await screen.findByText("26 results")
    const request = dictionaryRequests()[0]
    expect(request.searchParams.get("part")).toBe("a")
    expect(request.searchParams.get("vendor")).toBe("HAXX")
    expect(request.searchParams.get("product")).toBe("curl")
    expect(request.searchParams.get("version")).toBe("8.14.1-r1")
    expect(request.searchParams.get("deprecated")).toBe("all")
  })

  it("resets the URL, form, and results", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/cpe-dictionary?q=curl&deprecated=all")
    await screen.findByText("26 results")

    await user.click(screen.getByRole("button", { name: "Reset" }))

    expect(screen.getByLabelText("Keyword")).toHaveValue("")
    expect(currentParameters().get("q")).toBeNull()
    expect(
      screen.getByText("Search the selected Dictionary snapshot"),
    ).toBeInTheDocument()
  })

  it("shows a loading state, API errors, and empty results", async () => {
    let resolveSearch:
      | ((response: Response) => void)
      | undefined
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/cpe-dictionary/snapshot/") {
        return Promise.resolve(jsonResponse(searchResponse.snapshot))
      }
      return new Promise<Response>((resolve) => {
        resolveSearch = resolve
      })
    })
    renderAppAt("/cpe-dictionary?q=curl")
    expect(
      await screen.findByText(
        "Searching the selected Dictionary snapshot…",
      ),
    ).toBeInTheDocument()
    await act(async () => {
      resolveSearch?.(jsonResponse({ ...searchResponse, results: [] }))
    })
    expect(
      await screen.findByText(
        "No CPE Dictionary records match these exact search conditions.",
      ),
    ).toBeInTheDocument()

    vi.mocked(fetch).mockReset()
    installFetch({ searchError: true })
    renderAppAt("/cpe-dictionary?q=x")
    expect(
      await screen.findByText("Dictionary search failed"),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/invalid_search_query/),
    ).toBeInTheDocument()
  })

  it("renders statuses, protects long CPE overflow, and copies a row", async () => {
    const user = userEvent.setup()
    const copySpy = vi.spyOn(navigator.clipboard, "writeText")
    installFetch()
    renderAppAt("/cpe-dictionary?q=curl&deprecated=all")
    await screen.findByText("26 results")

    expect(screen.getAllByText("Active")).not.toHaveLength(0)
    expect(screen.getAllByText("Deprecated")).not.toHaveLength(0)
    const rawCpe = screen.getByTitle(cpeName)
    expect(rawCpe).toHaveClass("truncate")
    await user.click(
      screen.getByRole("button", {
        name: `Copy CPE ${cpeName}`,
      }),
    )
    expect(copySpy).toHaveBeenCalledWith(
      cpeName,
    )
  })

  it("changes page and page size through server-side URL state", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/cpe-dictionary?q=curl")
    await screen.findByText("26 results")

    expect(
      screen.getByText("Rows per page").closest("label"),
    ).toHaveClass(
      "flex",
      "shrink-0",
      "items-center",
      "gap-2",
      "whitespace-nowrap",
    )
    await user.click(
      screen.getByRole("button", { name: "Next page" }),
    )
    await waitFor(() =>
      expect(currentParameters().get("page")).toBe("2"),
    )
    await user.selectOptions(
      screen.getByLabelText("Rows per page"),
      "100",
    )
    await waitFor(() =>
      expect(currentParameters().get("page_size")).toBe("100"),
    )
    expect(currentParameters().get("page")).toBe("1")
    expect(dictionaryRequests().at(-1)?.searchParams.get("page_size"))
      .toBe("100")
  })

  it("restores URL state on refresh and browser history navigation", async () => {
    installFetch()
    const { router } = renderAppWithHistory([
      "/cpe-dictionary?q=openssl&deprecated=all",
      "/cpe-dictionary?q=curl&deprecated=active",
    ])
    await screen.findByText("26 results")
    expect(screen.getByLabelText("Keyword")).toHaveValue("curl")

    await act(async () => {
      await router.navigate(-1)
    })
    await waitFor(() =>
      expect(screen.getByLabelText("Keyword")).toHaveValue(
        "openssl",
      ),
    )
    expect(currentParameters().get("deprecated")).toBe("all")
  })

  it("opens read-only details with titles, references, and copy actions", async () => {
    const user = userEvent.setup()
    const copySpy = vi.spyOn(navigator.clipboard, "writeText")
    installFetch()
    renderAppAt("/cpe-dictionary?q=curl")
    await screen.findByText("26 results")

    await user.click(
      screen.getAllByRole("button", {
        name: "View details",
      })[0],
    )
    const dialog = await screen.findByRole("dialog")
    expect(
      within(dialog).getByText("curl français"),
    ).toBeInTheDocument()
    const reference = within(dialog).getByRole("link", {
      name: /https:\/\/curl\.se\//,
    })
    expect(reference).toHaveAttribute("target", "_blank")
    expect(reference).toHaveAttribute(
      "rel",
      "noopener noreferrer",
    )
    await user.click(
      within(dialog).getByRole("button", {
        name: "Copy raw CPE",
      }),
    )
    await user.click(
      within(dialog).getByRole("button", {
        name: "Copy CPE UUID",
      }),
    )
    expect(copySpy).toHaveBeenCalledWith(
      cpeName,
    )
    expect(copySpy).toHaveBeenCalledWith(
      cpeNameId,
    )
    for (const prohibited of [
      "Select",
      "Confirm",
      "Replace",
      "Save",
    ]) {
      expect(
        within(dialog).queryByRole("button", {
          name: prohibited,
        }),
      ).not.toBeInTheDocument()
    }
  })

  it("loads Component context and fills convenience searches without submitting", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/cpe-dictionary?component_id=101")

    expect(
      await screen.findByText("Component context"),
    ).toBeInTheDocument()
    expect(screen.getByText("Daniel Stenberg")).toBeInTheDocument()
    expect(screen.getByText("alpine")).toBeInTheDocument()
    expect(
      screen.getByText("apk-db-cataloger"),
    ).toBeInTheDocument()
    expect(dictionaryRequests()).toHaveLength(0)

    await user.click(
      screen.getByRole("button", {
        name: "Use existing CPE product",
      }),
    )
    expect(screen.getByLabelText("Product")).toHaveValue("curl")
    expect(dictionaryRequests()).toHaveLength(0)
    await user.click(
      screen.getByRole("button", {
        name: "Use publisher",
      }),
    )
    expect(screen.getByLabelText("Keyword")).toHaveValue(
      "Daniel Stenberg",
    )
  })
})
