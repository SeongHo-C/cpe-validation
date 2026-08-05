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

import type { ComponentSummary } from "@/features/components/components-types"
import type {
  SbomDocumentSummary,
  SbomPage,
} from "@/features/sboms/sboms-types"
import { formatDateTime } from "@/lib/format"
import { renderAppAt } from "@/test/render-app"

const uploadedAt = "2026-08-05T03:04:05Z"
const sbomFixture: SbomDocumentSummary = {
  id: 1,
  manufacturer: "NETGEAR",
  product_name: "R7000",
  product_version: "1.0.11.136",
  original_filename: "r7000.cdx.json",
  format: "CYCLONEDX_JSON",
  spec_version: "1.7",
  generator_name: "syft",
  generator_version: "1.49.0",
  component_count: 125,
  uploaded_at: uploadedAt,
}

const dockerlessComponent: ComponentSummary = {
  id: 101,
  image: null,
  sbom: {
    id: 1,
    manufacturer: "NETGEAR",
    product_name: "R7000",
    product_version: "1.0.11.136",
    original_filename: "r7000.cdx.json",
  },
  sbom_document_id: 1,
  component_type: "firmware",
  group: "",
  name: "R7000 firmware",
  version: "1.0.11.136",
  publisher: "NETGEAR",
  purl: "",
  cpe: "cpe:2.3:o:netgear:r7000_firmware:1.0.11.136:*:*:*:*:*:*:*",
  structural_status: "STRUCTURALLY_VALID",
  dictionary_status: "NOT_IN_DICTIONARY",
  cpe_fields: {
    part: "o",
    vendor: "netgear",
    product: "r7000_firmware",
    version: "1.0.11.136",
    update: "*",
    edition: "*",
    language: "*",
    sw_edition: "*",
    target_sw: "*",
    target_hw: "*",
    other: "*",
  },
}

function jsonResponse<T>(body: T, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function sbomResponse(
  url: URL,
  results: SbomDocumentSummary[] = [sbomFixture],
  count = results.length,
): SbomPage {
  const page = Number(url.searchParams.get("page") ?? "1")
  const pageSize = Number(
    url.searchParams.get("page_size") ?? "50",
  )
  const totalPages = Math.max(Math.ceil(count / pageSize), 1)
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

function installSuccessfulFetch(
  results: SbomDocumentSummary[] = [sbomFixture],
  count = results.length,
) {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = new URL(String(input), "http://frontend.test")
    if (url.pathname === "/api/health/") {
      return Promise.resolve(
        jsonResponse({ status: "ok", database: "ok" }),
      )
    }
    if (url.pathname === "/api/sboms/") {
      return Promise.resolve(
        jsonResponse(sbomResponse(url, results, count)),
      )
    }
    if (url.pathname === "/api/components/") {
      return Promise.resolve(
        jsonResponse({
          count: 1,
          page: 1,
          page_size: 50,
          total_pages: 1,
          next: null,
          previous: null,
          results: [dockerlessComponent],
        }),
      )
    }
    return Promise.resolve(jsonResponse({}, 404))
  })
}

function sbomRequestUrls(): URL[] {
  return vi
    .mocked(fetch)
    .mock.calls.map(([input]) =>
      new URL(String(input), "http://frontend.test"),
    )
    .filter((url) => url.pathname === "/api/sboms/")
}

describe("SBOM inventory", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("renders SBOM metadata using the Backend contract", async () => {
    installSuccessfulFetch([sbomFixture], 125)
    renderAppAt("/sboms")

    expect(await screen.findByText("NETGEAR")).toBeInTheDocument()
    const table = screen.getByRole("table")
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent?.trim()),
    ).toEqual([
      "Manufacturer",
      "Product",
      "Version",
      "Format",
      "Components",
      "Uploaded",
    ])
    expect(within(table).getByText("R7000")).toBeInTheDocument()
    expect(
      within(table).getByText("1.0.11.136"),
    ).toBeInTheDocument()
    expect(
      within(table).getByText("CycloneDX 1.7"),
    ).toBeInTheDocument()
    expect(within(table).getByText("125")).toBeInTheDocument()
    expect(
      within(table).getByText(formatDateTime(uploadedAt)),
    ).toBeInTheDocument()
    expect(screen.getAllByText("125 SBOM documents")).toHaveLength(2)
    expect(screen.queryByText("syft")).not.toBeInTheDocument()

    const request = sbomRequestUrls()[0]
    expect(request.searchParams.get("page")).toBe("1")
    expect(request.searchParams.get("page_size")).toBe("50")
  })

  it.each([
    ["1.5", "CycloneDX 1.5"],
    ["", "CycloneDX"],
  ])(
    "renders CycloneDX with spec version %s as %s",
    async (specVersion, expectedLabel) => {
      installSuccessfulFetch([
        { ...sbomFixture, spec_version: specVersion },
      ])
      renderAppAt("/sboms")

      expect(
        await screen.findByText(expectedLabel),
      ).toBeInTheDocument()
    },
  )

  it("humanizes an unknown format without adding format mappings", async () => {
    installSuccessfulFetch([
      {
        ...sbomFixture,
        format: "SPDX_JSON",
        spec_version: "2.3",
      },
    ])
    renderAppAt("/sboms")

    expect(
      await screen.findByText("SPDX JSON 2.3"),
    ).toBeInTheDocument()
  })

  it("shows a normal empty state without upload or Docker UI", async () => {
    installSuccessfulFetch([], 0)
    renderAppAt("/sboms")

    expect(
      await screen.findByText("No SBOMs available"),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        "Uploaded SBOM documents will appear here.",
      ),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole("button", { name: /upload/i }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText(/Docker Images/i)).not.toBeInTheDocument()
    expect(
      screen.queryByText("Unable to load SBOMs"),
    ).not.toBeInTheDocument()
  })

  it("shows the existing loading and retry patterns", async () => {
    const user = userEvent.setup()
    let resolveSboms: ((response: Response) => void) | undefined
    let attempts = 0
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/sboms/") {
        attempts += 1
        if (attempts === 1) {
          return new Promise<Response>((resolve) => {
            resolveSboms = resolve
          })
        }
        return Promise.resolve(
          jsonResponse(sbomResponse(url, [sbomFixture])),
        )
      }
      return Promise.resolve(jsonResponse({}, 404))
    })

    renderAppAt("/sboms")
    expect(
      screen.getByLabelText("Loading SBOM table"),
    ).toBeInTheDocument()

    await act(async () => {
      resolveSboms?.(jsonResponse({}, 500))
    })
    expect(
      await screen.findByText("Unable to load SBOMs"),
    ).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Retry" }))
    expect(await screen.findByText("NETGEAR")).toBeInTheDocument()
    expect(attempts).toBe(2)
  })

  it("uses filename and untitled fallbacks for empty product data", async () => {
    installSuccessfulFetch([
      {
        ...sbomFixture,
        id: 2,
        manufacturer: "",
        product_name: "",
        product_version: "",
        original_filename: "router.cdx.json",
        generator_name: "",
        generator_version: "",
      },
      {
        ...sbomFixture,
        id: 3,
        manufacturer: "",
        product_name: "",
        product_version: "",
        original_filename: "",
        generator_name: "",
        generator_version: "",
      },
    ])
    renderAppAt("/sboms")

    expect(
      await screen.findByText("router.cdx.json"),
    ).toBeInTheDocument()
    expect(screen.getByText("Untitled SBOM")).toBeInTheDocument()
    expect(screen.getAllByText("—")).toHaveLength(4)
  })

  it("changes page and page size through API parameters", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch([sbomFixture], 125)
    renderAppAt("/sboms")
    await screen.findByText("NETGEAR")

    await user.click(
      screen.getByRole("button", { name: "Next page" }),
    )
    await waitFor(() => {
      expect(
        sbomRequestUrls().some(
          (url) => url.searchParams.get("page") === "2",
        ),
      ).toBe(true)
    })

    await user.selectOptions(
      screen.getByLabelText("SBOMs per page"),
      "25",
    )
    await waitFor(() => {
      expect(
        sbomRequestUrls().some(
          (url) =>
            url.searchParams.get("page") === "1" &&
            url.searchParams.get("page_size") === "25",
        ),
      ).toBe(true)
    })
  })

  it("opens the selected SBOM Component queue on click", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("link", {
        name: "View Components for R7000",
      }),
    )

    expect(screen.getByTestId("route-location")).toHaveTextContent(
      "/components?sbom_id=1",
    )
    await waitFor(() => {
      expect(
        vi.mocked(fetch).mock.calls.some(([input]) => {
          const url = new URL(
            String(input),
            "http://frontend.test",
          )
          return (
            url.pathname === "/api/components/" &&
            url.searchParams.get("sbom_id") === "1"
          )
        }),
      ).toBe(true)
    })
  })

  it.each(["{Enter}", " "])(
    "opens the SBOM Component queue with keyboard input %s",
    async (keyboardInput) => {
      const user = userEvent.setup()
      installSuccessfulFetch()
      renderAppAt("/sboms")
      const row = await screen.findByRole("link", {
        name: "View Components for R7000",
      })

      row.focus()
      await user.keyboard(keyboardInput)

      expect(screen.getByTestId("route-location")).toHaveTextContent(
        "/components?sbom_id=1",
      )
    },
  )

  it("redirects root and legacy images routes to SBOMs", async () => {
    installSuccessfulFetch()
    const root = renderAppAt("/")
    expect(
      await screen.findByRole("heading", { name: "SBOMs" }),
    ).toBeInTheDocument()
    expect(screen.getByTestId("route-location")).toHaveTextContent(
      "/sboms",
    )
    root.unmount()

    renderAppAt("/images")
    expect(
      await screen.findByRole("heading", { name: "SBOMs" }),
    ).toBeInTheDocument()
    expect(screen.getByTestId("route-location")).toHaveTextContent(
      "/sboms",
    )
  })
})
