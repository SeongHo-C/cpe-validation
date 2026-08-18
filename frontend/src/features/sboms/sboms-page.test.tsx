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
  SbomDocumentDetail,
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

const preservedSbomFixture: SbomDocumentSummary = {
  ...sbomFixture,
  id: 2,
  manufacturer: "Example Devices",
  product_name: "Preserved Router",
  product_version: "2.0",
  original_filename: "preserved.cdx.json",
  component_count: 42,
}

const uploadedSbomFixture: SbomDocumentDetail = {
  id: 11,
  manufacturer: "Teltonika",
  product_name: "RUTX",
  product_version: "00.07.23.7",
  original_filename: "sbom.cdx.json",
  format: "CYCLONEDX_JSON",
  spec_version: "1.5",
  generator_name: "EMBA binary analysis environment",
  generator_version: "2.0.3",
  component_count: 790,
  uploaded_at: "2026-08-08T05:06:07Z",
  file_sha256: "1".repeat(64),
  serial_number: "urn:uuid:emba-upload",
  document_version: 1,
  generated_at: "2026-08-08T04:05:06Z",
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

function installUploadFetch(
  uploadBody: unknown,
  uploadStatus: number,
  refreshedResults: SbomDocumentSummary[] = [
    uploadedSbomFixture,
    sbomFixture,
  ],
) {
  let uploadAttempted = false
  vi.mocked(fetch).mockImplementation((input, init) => {
    const url = new URL(String(input), "http://frontend.test")
    if (url.pathname === "/api/health/") {
      return Promise.resolve(
        jsonResponse({ status: "ok", database: "ok" }),
      )
    }
    if (
      url.pathname === "/api/sboms/upload/" &&
      init?.method === "POST"
    ) {
      uploadAttempted = true
      return Promise.resolve(jsonResponse(uploadBody, uploadStatus))
    }
    if (url.pathname === "/api/sboms/") {
      const results =
        uploadAttempted && uploadStatus === 201
          ? refreshedResults
          : [sbomFixture]
      return Promise.resolve(jsonResponse(sbomResponse(url, results)))
    }
    return Promise.resolve(jsonResponse({}, 404))
  })
}

function installDeleteFetch(
  deleteBody: unknown,
  deleteStatus: number,
  refreshedResults: SbomDocumentSummary[] = [preservedSbomFixture],
) {
  let deleteSucceeded = false
  vi.mocked(fetch).mockImplementation((input, init) => {
    const url = new URL(String(input), "http://frontend.test")
    if (url.pathname === "/api/health/") {
      return Promise.resolve(
        jsonResponse({ status: "ok", database: "ok" }),
      )
    }
    if (
      url.pathname === "/api/sboms/1/" &&
      init?.method === "DELETE"
    ) {
      deleteSucceeded = deleteStatus === 204
      return Promise.resolve(jsonResponse(deleteBody, deleteStatus))
    }
    if (url.pathname === "/api/sboms/") {
      const results = deleteSucceeded
        ? refreshedResults
        : [sbomFixture]
      return Promise.resolve(jsonResponse(sbomResponse(url, results)))
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

function uploadRequestCalls() {
  return vi.mocked(fetch).mock.calls.filter(([input, init]) => {
    const url = new URL(String(input), "http://frontend.test")
    return (
      url.pathname === "/api/sboms/upload/" &&
      init?.method === "POST"
    )
  })
}

function deleteRequestCalls() {
  return vi.mocked(fetch).mock.calls.filter(([input, init]) => {
    const url = new URL(String(input), "http://frontend.test")
    return url.pathname === "/api/sboms/1/" && init?.method === "DELETE"
  })
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
      "Actions",
    ])
    expect(within(table).getByText("R7000")).toBeInTheDocument()
    expect(
      within(table).getByText("1.0.11.136"),
    ).toBeInTheDocument()
    expect(
      within(table).getByText("CycloneDX 1.7"),
    ).toBeInTheDocument()
    expect(within(table).getByText("125")).toBeInTheDocument()
    const formattedUploadedAt = formatDateTime(uploadedAt)
    expect(formattedUploadedAt).toMatch(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/,
    )
    expect(formattedUploadedAt).not.toMatch(/AM|PM|오전|오후/i)
    expect(
      within(table).getByText(formattedUploadedAt),
    ).toBeInTheDocument()
    expect(screen.getByText("125 SBOMs")).toBeInTheDocument()
    expect(screen.queryByText("syft")).not.toBeInTheDocument()
    expect(table.querySelector(".lucide-chevron-right")).toBeNull()

    const request = sbomRequestUrls()[0]
    expect(request.searchParams.get("page")).toBe("1")
    expect(request.searchParams.get("page_size")).toBe("50")
  })

  it("keeps the Page description and removes the duplicate panel subtitle", async () => {
    installSuccessfulFetch()
    renderAppAt("/sboms")

    expect(
      await screen.findByText(
        "SBOM documents available for CPE validation",
      ),
    ).toBeInTheDocument()
    expect(
      screen.queryByText(
        "SBOM documents available for CPE validation.",
      ),
    ).not.toBeInTheDocument()
    const uploadButton = screen.getByRole("button", {
      name: "Upload SBOM",
    })
    const panelHeader = uploadButton.closest(
      '[data-slot="card-header"]',
    )
    expect(panelHeader).not.toBeNull()
    expect(
      within(panelHeader as HTMLElement).getByText("SBOM Inventory"),
    ).toBeInTheDocument()
  })

  it.each([
    [[sbomFixture], 1, "1 SBOM"],
    [[sbomFixture, preservedSbomFixture], 2, "2 SBOMs"],
  ])(
    "renders a natural inventory count for %s document(s)",
    async (results, count, expectedLabel) => {
      installSuccessfulFetch(results, count)
      renderAppAt("/sboms")

      expect(
        await screen.findByText(expectedLabel),
      ).toBeInTheDocument()
    },
  )

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

  it("shows a normal empty state with the upload action", async () => {
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
      screen.getByRole("button", { name: "Upload SBOM" }),
    ).toBeInTheDocument()
    expect(screen.queryByText(/Docker Images/i)).not.toBeInTheDocument()
    expect(
      screen.queryByText("Unable to load SBOMs"),
    ).not.toBeInTheDocument()
  })

  it("opens an accessible upload dialog with the required fields", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", { name: "Upload SBOM" }),
    )
    const dialog = screen.getByRole("dialog", { name: "Upload SBOM" })

    const fileInput = within(dialog).getByLabelText(/SBOM file/)
    expect(fileInput).toHaveAttribute(
      "accept",
      "application/json,.json",
    )
    expect(fileInput).toBeRequired()
    expect(fileInput).toHaveAttribute("tabindex", "-1")
    expect(fileInput.parentElement).toHaveClass("sr-only")
    expect(within(dialog).getByText("*")).toBeInTheDocument()
    expect(
      within(dialog).getByText("No file selected"),
    ).toBeInTheDocument()
    expect(
      within(dialog).queryByText("Choose a CycloneDX JSON document."),
    ).not.toBeInTheDocument()
    expect(
      within(dialog).queryByText(/\(optional\)/i),
    ).not.toBeInTheDocument()
    expect(
      within(dialog).queryByText(
        "Add an externally generated CycloneDX JSON SBOM.",
      ),
    ).not.toBeInTheDocument()

    const manufacturer = within(dialog).getByLabelText("Manufacturer")
    const productName = within(dialog).getByLabelText("Product name")
    const productVersion = within(dialog).getByLabelText("Product version")
    for (const input of [manufacturer, productName, productVersion]) {
      expect(input).toBeEnabled()
      expect(input).not.toBeRequired()
      expect(input).not.toHaveAttribute("placeholder")
    }

    const inputClick = vi.spyOn(fileInput, "click")
    await user.click(
      within(dialog).getByRole("button", { name: "Select file" }),
    )
    expect(inputClick).toHaveBeenCalledOnce()
    inputClick.mockRestore()
  })

  it("does not call the Upload API without a file", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", { name: "Upload SBOM" }),
    )
    const dialog = screen.getByRole("dialog", { name: "Upload SBOM" })
    await user.click(
      within(dialog).getByRole("button", { name: "Upload SBOM" }),
    )

    expect(
      await within(dialog).findByText(
        "Select a CycloneDX JSON SBOM file.",
      ),
    ).toBeInTheDocument()
    expect(uploadRequestCalls()).toHaveLength(0)
  })

  it("resets the file and metadata after cancelling", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", { name: "Upload SBOM" }),
    )
    const dialog = screen.getByRole("dialog", { name: "Upload SBOM" })
    await user.upload(
      within(dialog).getByLabelText(/SBOM file/),
      new File(["cancelled"], "cancelled.cdx.json", {
        type: "application/json",
      }),
    )
    await user.type(
      within(dialog).getByLabelText("Manufacturer"),
      "Example Devices",
    )
    await user.click(
      within(dialog).getByRole("button", { name: "Cancel" }),
    )

    await user.click(
      screen.getByRole("button", { name: "Upload SBOM" }),
    )
    const resetDialog = screen.getByRole("dialog", {
      name: "Upload SBOM",
    })
    expect(
      within(resetDialog).getByText("No file selected"),
    ).toBeInTheDocument()
    expect(within(resetDialog).getByLabelText(/SBOM file/)).toHaveValue("")
    expect(
      within(resetDialog).getByLabelText("Manufacturer"),
    ).toHaveValue("")
    expect(uploadRequestCalls()).toHaveLength(0)
  })

  it("uploads FormData, closes and resets, then refreshes the list", async () => {
    const user = userEvent.setup()
    installUploadFetch(uploadedSbomFixture, 201)
    renderAppAt("/sboms")
    await screen.findByText("NETGEAR")

    await user.click(
      screen.getByRole("button", { name: "Upload SBOM" }),
    )
    const dialog = screen.getByRole("dialog", { name: "Upload SBOM" })
    const file = new File(["{\"bomFormat\":\"CycloneDX\"}"], "sbom.cdx.json", {
      type: "application/json",
    })
    await user.upload(within(dialog).getByLabelText(/SBOM file/), file)
    await user.type(within(dialog).getByLabelText(/Manufacturer/), "Teltonika")
    await user.type(within(dialog).getByLabelText(/Product name/), "RUTX")
    await user.type(
      within(dialog).getByLabelText(/Product version/),
      "00.07.23.7",
    )
    expect(within(dialog).getByText("sbom.cdx.json")).toBeInTheDocument()
    expect(
      within(dialog).queryByText("No file selected"),
    ).not.toBeInTheDocument()

    await user.click(
      within(dialog).getByRole("button", { name: "Upload SBOM" }),
    )

    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Upload SBOM" }),
      ).not.toBeInTheDocument()
    })
    expect(await screen.findByText("Teltonika")).toBeInTheDocument()
    expect(screen.getByText("RUTX")).toBeInTheDocument()
    expect(screen.getByText("790")).toBeInTheDocument()
    expect(sbomRequestUrls().length).toBeGreaterThanOrEqual(2)

    const uploadCalls = uploadRequestCalls()
    expect(uploadCalls).toHaveLength(1)
    const request = uploadCalls[0]?.[1]
    expect(request?.body).toBeInstanceOf(FormData)
    const formData = request?.body as FormData
    expect(formData.get("file")).toBe(file)
    expect(formData.get("manufacturer")).toBe("Teltonika")
    expect(formData.get("product_name")).toBe("RUTX")
    expect(formData.get("product_version")).toBe("00.07.23.7")
    expect(new Headers(request?.headers).has("Content-Type")).toBe(false)

    await user.click(
      screen.getByRole("button", { name: "Upload SBOM" }),
    )
    const resetDialog = screen.getByRole("dialog", {
      name: "Upload SBOM",
    })
    expect(within(resetDialog).getByLabelText(/Manufacturer/)).toHaveValue("")
    expect(within(resetDialog).getByLabelText(/Product name/)).toHaveValue("")
    expect(within(resetDialog).getByLabelText(/Product version/)).toHaveValue("")
    expect(within(resetDialog).getByText("No file selected")).toBeInTheDocument()
    expect(within(resetDialog).getByLabelText(/SBOM file/)).toHaveValue("")
  })

  it("keeps the dialog open and explains duplicate uploads", async () => {
    const user = userEvent.setup()
    installUploadFetch(
      {
        code: "duplicate_sbom",
        detail: "An SBOM with the same SHA-256 is already registered.",
        existing_sbom_id: 1,
      },
      409,
    )
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", { name: "Upload SBOM" }),
    )
    const dialog = screen.getByRole("dialog", { name: "Upload SBOM" })
    await user.upload(
      within(dialog).getByLabelText(/SBOM file/),
      new File(["duplicate"], "duplicate.json", {
        type: "application/json",
      }),
    )
    await user.click(
      within(dialog).getByRole("button", { name: "Upload SBOM" }),
    )

    expect(
      await within(dialog).findByText(
        "This SBOM has already been uploaded.",
      ),
    ).toBeInTheDocument()
    expect(dialog).toBeInTheDocument()
    expect(uploadRequestCalls()).toHaveLength(1)
  })

  it("shows the Backend detail for an invalid SBOM", async () => {
    const user = userEvent.setup()
    installUploadFetch(
      {
        code: "invalid_sbom",
        detail: "uploaded SBOM: bomFormat must be 'CycloneDX'",
      },
      400,
    )
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", { name: "Upload SBOM" }),
    )
    const dialog = screen.getByRole("dialog", { name: "Upload SBOM" })
    await user.upload(
      within(dialog).getByLabelText(/SBOM file/),
      new File(["{}"], "invalid.json", { type: "application/json" }),
    )
    await user.click(
      within(dialog).getByRole("button", { name: "Upload SBOM" }),
    )

    expect(
      await within(dialog).findByText(
        "uploaded SBOM: bomFormat must be 'CycloneDX'",
      ),
    ).toBeInTheDocument()
    expect(dialog).toBeInTheDocument()
  })

  it("prevents duplicate submits while an upload is pending", async () => {
    const user = userEvent.setup()
    let resolveUpload: ((response: Response) => void) | undefined
    vi.mocked(fetch).mockImplementation((input, init) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (
        url.pathname === "/api/sboms/upload/" &&
        init?.method === "POST"
      ) {
        return new Promise<Response>((resolve) => {
          resolveUpload = resolve
        })
      }
      if (url.pathname === "/api/sboms/") {
        return Promise.resolve(
          jsonResponse(sbomResponse(url, [sbomFixture])),
        )
      }
      return Promise.resolve(jsonResponse({}, 404))
    })
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", { name: "Upload SBOM" }),
    )
    const dialog = screen.getByRole("dialog", { name: "Upload SBOM" })
    const fileInput = within(dialog).getByLabelText(/SBOM file/)
    await user.upload(
      fileInput,
      new File(["pending"], "pending.json", {
        type: "application/json",
      }),
    )
    await user.click(
      within(dialog).getByRole("button", { name: "Upload SBOM" }),
    )

    const uploadingButton = within(dialog).getByRole("button", {
      name: "Uploading…",
    })
    expect(uploadingButton).toBeDisabled()
    expect(fileInput).toBeDisabled()
    expect(
      within(dialog).getByRole("button", { name: "Select file" }),
    ).toBeDisabled()
    await user.click(uploadingButton)
    expect(uploadRequestCalls()).toHaveLength(1)

    await act(async () => {
      resolveUpload?.(jsonResponse(uploadedSbomFixture, 201))
    })
    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Upload SBOM" }),
      ).not.toBeInTheDocument()
    })
  })

  it("opens delete confirmation without following the SBOM row", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", {
        name: "Delete SBOM R7000",
      }),
    )
    const dialog = screen.getByRole("dialog", { name: "Delete SBOM?" })

    expect(screen.getByTestId("route-location")).toHaveTextContent("/sboms")
    expect(within(dialog).getByText("NETGEAR")).toBeInTheDocument()
    expect(within(dialog).getByText("R7000")).toBeInTheDocument()
    expect(within(dialog).getByText("1.0.11.136")).toBeInTheDocument()
    expect(within(dialog).getByText("r7000.cdx.json")).toBeInTheDocument()
    expect(
      within(dialog).getByText(/remove its imported components/i),
    ).toBeInTheDocument()
    expect(
      within(dialog).getByText(/Ground Truth records/i),
    ).toBeInTheDocument()
    expect(
      within(dialog).getByText(/Shared CPE Dictionary/i),
    ).toBeInTheDocument()
    expect(
      within(dialog).getByRole("button", { name: "Cancel" }),
    ).toBeEnabled()
    expect(
      within(dialog).getByRole("button", { name: "Delete SBOM" }),
    ).toBeEnabled()
    expect(deleteRequestCalls()).toHaveLength(0)
  })

  it("cancels deletion without a request or navigation", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", {
        name: "Delete SBOM R7000",
      }),
    )
    const dialog = screen.getByRole("dialog", { name: "Delete SBOM?" })
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }))

    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Delete SBOM?" }),
      ).not.toBeInTheDocument()
    })
    expect(deleteRequestCalls()).toHaveLength(0)
    expect(screen.getByText("R7000")).toBeInTheDocument()
    expect(screen.getByTestId("route-location")).toHaveTextContent("/sboms")
  })

  it("deletes the selected SBOM and refreshes the list", async () => {
    const user = userEvent.setup()
    installDeleteFetch(null, 204)
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", {
        name: "Delete SBOM R7000",
      }),
    )
    const dialog = screen.getByRole("dialog", { name: "Delete SBOM?" })
    await user.click(
      within(dialog).getByRole("button", { name: "Delete SBOM" }),
    )

    expect(await screen.findByText("Preserved Router")).toBeInTheDocument()
    expect(
      screen.queryByRole("dialog", { name: "Delete SBOM?" }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText("R7000")).not.toBeInTheDocument()
    expect(screen.getByTestId("route-location")).toHaveTextContent("/sboms")
    expect(sbomRequestUrls().length).toBeGreaterThanOrEqual(2)
    const calls = deleteRequestCalls()
    expect(calls).toHaveLength(1)
    expect(new Headers(calls[0]?.[1]?.headers).get("Accept")).toBe(
      "application/json",
    )
  })

  it.each([
    [404, { detail: "Not found." }, "This SBOM no longer exists."],
    [
      409,
      {
        code: "sbom_delete_conflict",
        detail: "Protected review data prevents this deletion.",
      },
      "Protected review data prevents this deletion.",
    ],
    [500, { detail: "Internal server error." }, "Unable to delete SBOM."],
  ])(
    "keeps the dialog open after a %s delete response",
    async (responseStatus, responseBody, expectedMessage) => {
      const user = userEvent.setup()
      installDeleteFetch(responseBody, responseStatus)
      renderAppAt("/sboms")

      await user.click(
        await screen.findByRole("button", {
          name: "Delete SBOM R7000",
        }),
      )
      const dialog = screen.getByRole("dialog", {
        name: "Delete SBOM?",
      })
      await user.click(
        within(dialog).getByRole("button", { name: "Delete SBOM" }),
      )

      expect(
        await within(dialog).findByText(expectedMessage),
      ).toBeInTheDocument()
      expect(dialog).toBeInTheDocument()
      expect(screen.getAllByText("R7000")).toHaveLength(2)
      expect(deleteRequestCalls()).toHaveLength(1)
    },
  )

  it("keeps the dialog open after a delete network error", async () => {
    const user = userEvent.setup()
    vi.mocked(fetch).mockImplementation((input, init) => {
      const url = new URL(String(input), "http://frontend.test")
      if (
        url.pathname === "/api/sboms/1/" &&
        init?.method === "DELETE"
      ) {
        return Promise.reject(new TypeError("network unavailable"))
      }
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/sboms/") {
        return Promise.resolve(
          jsonResponse(sbomResponse(url, [sbomFixture])),
        )
      }
      return Promise.resolve(jsonResponse({}, 404))
    })
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", { name: "Delete SBOM R7000" }),
    )
    const dialog = screen.getByRole("dialog", { name: "Delete SBOM?" })
    await user.click(
      within(dialog).getByRole("button", { name: "Delete SBOM" }),
    )

    expect(
      await within(dialog).findByText("Unable to delete SBOM."),
    ).toBeInTheDocument()
    expect(dialog).toBeInTheDocument()
  })

  it("prevents duplicate deletion while the request is pending", async () => {
    const user = userEvent.setup()
    let resolveDelete: ((response: Response) => void) | undefined
    vi.mocked(fetch).mockImplementation((input, init) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (
        url.pathname === "/api/sboms/1/" &&
        init?.method === "DELETE"
      ) {
        return new Promise<Response>((resolve) => {
          resolveDelete = resolve
        })
      }
      if (url.pathname === "/api/sboms/") {
        return Promise.resolve(
          jsonResponse(sbomResponse(url, [sbomFixture])),
        )
      }
      return Promise.resolve(jsonResponse({}, 404))
    })
    renderAppAt("/sboms")

    await user.click(
      await screen.findByRole("button", {
        name: "Delete SBOM R7000",
      }),
    )
    const dialog = screen.getByRole("dialog", { name: "Delete SBOM?" })
    await user.click(
      within(dialog).getByRole("button", { name: "Delete SBOM" }),
    )

    const deletingButton = within(dialog).getByRole("button", {
      name: "Deleting…",
    })
    expect(deletingButton).toBeDisabled()
    expect(
      within(dialog).getByRole("button", { name: "Cancel" }),
    ).toBeDisabled()
    await user.click(deletingButton)
    expect(deleteRequestCalls()).toHaveLength(1)

    await act(async () => {
      resolveDelete?.(jsonResponse(null, 204))
    })
    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Delete SBOM?" }),
      ).not.toBeInTheDocument()
    })
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
