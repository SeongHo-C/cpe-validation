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
  ],
}

const detailResponse: CpeDictionaryDetail = {
  ...searchResponse.results[0],
  snapshot_manifest_sha256: "d".repeat(64),
  deprecated_by: [],
  deprecates: [],
  created_at_nvd: "2020-01-01T00:00:00Z",
  last_modified_at_nvd: "2026-01-01T00:00:00Z",
  titles: [{ lang: "en", title: "curl command line tool" }],
  references: [{ url: "https://curl.se/", type: "Vendor" }],
}

function jsonResponse<T>(body: T, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function installFetch() {
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
    if (url.pathname === "/api/cpe-dictionary/") {
      const page = Number(url.searchParams.get("page") ?? 1)
      const pageSize = Number(
        url.searchParams.get("page_size") ?? 25,
      ) as 25 | 50 | 100
      return Promise.resolve(
        jsonResponse({
          ...searchResponse,
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

describe("read-only CPE Dictionary", () => {
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

  it("renders the generic route without Ground Truth UI", async () => {
    installFetch()
    renderAppAt("/cpe-dictionary?component_id=101")

    expect(
      screen.getByRole("heading", { name: "CPE Dictionary" }),
    ).toBeInTheDocument()
    expect(
      screen.queryByText("예상 Ground Truth"),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText("Component context"),
    ).not.toBeInTheDocument()
    expect(
      await screen.findByText("20260725T035002Z"),
    ).toBeInTheDocument()
  })

  it("submits keyword and structured filters into URL state", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/cpe-dictionary")

    await user.type(screen.getByLabelText("Keyword"), "curl")
    await user.selectOptions(screen.getByLabelText("Part"), "a")
    await user.type(screen.getByLabelText("Vendor"), "HAXX")
    await user.click(screen.getByRole("button", { name: "Search" }))

    expect(await screen.findByText("26 results")).toBeInTheDocument()
    expect(currentParameters().get("q")).toBe("curl")
    expect(currentParameters().get("part")).toBe("a")
    expect(currentParameters().get("vendor")).toBe("HAXX")
  })

  it("restores URL search state through history navigation", async () => {
    installFetch()
    const { router } = renderAppWithHistory([
      "/cpe-dictionary?q=openssl",
      "/cpe-dictionary?q=curl",
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
  })

  it("opens read-only detail and copy controls", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/cpe-dictionary?q=curl")
    await screen.findByText("26 results")

    await user.click(
      screen.getByRole("button", { name: "View details" }),
    )
    const dialog = await screen.findByRole("dialog")
    expect(
      within(dialog).getByText("https://curl.se/"),
    ).toBeInTheDocument()
    expect(
      within(dialog).queryByRole("button", {
        name: "Ground Truth로 선택",
      }),
    ).not.toBeInTheDocument()
  })

  it("keeps results and disables pagination while fetching", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/cpe-dictionary?q=curl")
    await screen.findByText("26 results")
    const original = vi.mocked(fetch).getMockImplementation()
    let resolveNext: ((response: Response) => void) | undefined
    vi.mocked(fetch).mockImplementation((input, init) => {
      const url = new URL(String(input), "http://frontend.test")
      if (
        url.pathname === "/api/cpe-dictionary/" &&
        url.searchParams.get("page") === "2"
      ) {
        return new Promise<Response>((resolve) => {
          resolveNext = resolve
        })
      }
      return original!(input, init)
    })

    await user.click(
      screen.getByRole("button", { name: "Next page" }),
    )

    expect(await screen.findByText("불러오는 중..."))
      .toBeInTheDocument()
    expect(screen.getByTitle(cpeName)).toBeInTheDocument()
    expect(
      screen.getByRole("button", { name: "Next page" }),
    ).toBeDisabled()
    expect(
      dictionaryRequests().filter(
        (url) => url.searchParams.get("page") === "2",
      ),
    ).toHaveLength(1)

    await act(async () => {
      resolveNext?.(
        jsonResponse({
          ...searchResponse,
          page: 2,
          results: [
            {
              ...searchResponse.results[0],
              id: 2,
              cpe_name_id:
                "22222222-2222-4222-8222-222222222222",
              cpe_name:
                "cpe:2.3:a:haxx:curl:8.15.0:*:*:*:*:*:*:*",
              version: "8.15.0",
            },
          ],
        }),
      )
    })
    expect(
      await screen.findByTitle(
        "cpe:2.3:a:haxx:curl:8.15.0:*:*:*:*:*:*:*",
      ),
    ).toBeInTheDocument()
  })

  it("keeps prior results when pagination fails", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/cpe-dictionary?q=curl")
    await screen.findByText("26 results")
    const original = vi.mocked(fetch).getMockImplementation()
    vi.mocked(fetch).mockImplementation((input, init) => {
      const url = new URL(String(input), "http://frontend.test")
      if (
        url.pathname === "/api/cpe-dictionary/" &&
        url.searchParams.get("page") === "2"
      ) {
        return Promise.resolve(
          jsonResponse({ detail: "Temporary failure" }, 503),
        )
      }
      return original!(input, init)
    })

    await user.click(
      screen.getByRole("button", { name: "Next page" }),
    )

    expect(
      await screen.findByText("Dictionary search failed"),
    ).toBeInTheDocument()
    expect(screen.getByText("Temporary failure")).toBeInTheDocument()
    expect(screen.getByTitle(cpeName)).toBeInTheDocument()
  })
})
