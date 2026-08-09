import { screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { ComponentDetail } from "@/features/components/components-types"
import type {
  ComponentCpeGroundTruthRecord,
  ComponentCpeGroundTruthWrite,
  GroundTruthDecisionCode,
  GroundTruthDiscrepancyType,
} from "@/features/ground-truth/ground-truth-types"
import { renderAppAt } from "@/test/render-app"

const snapshotId = "20260725T035002Z"
const originalCpe =
  "cpe:2.3:a:syft:curl:8.14.1:*:*:*:*:*:*:*"
const mappedCpe =
  "cpe:2.3:a:haxx:curl:8.14.1:*:*:*:*:*:*:*"

const discrepancyTypes: GroundTruthDiscrepancyType[] = [
  {
    id: 35,
    code: "PART_MISMATCH",
    name: "Part mismatch",
    description: "The original part differs.",
    is_active: true,
    usage_count: 0,
  },
  {
    id: 32,
    code: "PRODUCT_MISMATCH",
    name: "Product mismatch",
    description: "The original product differs.",
    is_active: true,
    usage_count: 1,
  },
  {
    id: 31,
    code: "VENDOR_MISMATCH",
    name: "Vendor mismatch",
    description: "The original vendor differs.",
    is_active: true,
    usage_count: 2,
  },
  {
    id: 36,
    code: "VERSION_MISMATCH",
    name: "Version mismatch",
    description:
      "The original CPE version differs from the verified product or upstream version, and the difference cannot be explained solely by distribution or vendor package version normalization.",
    is_active: true,
    usage_count: 0,
  },
  {
    id: 33,
    code: "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED",
    name: "Distribution package version normalized",
    description: "The distribution package revision was removed.",
    is_active: true,
    usage_count: 1,
  },
  {
    id: 34,
    code: "VERSION_NOT_IN_DICTIONARY",
    name: "Version not in Dictionary",
    description: "The exact version is absent from the Dictionary.",
    is_active: true,
    usage_count: 0,
  },
]

const component: ComponentDetail = {
  id: 101,
  image: null,
  sbom: {
    id: 11,
    manufacturer: "Teltonika",
    product_name: "RUTX11 Firmware",
    product_version: "00.07.24.1",
    original_filename: "rutx.cdx.json",
  },
  sbom_document_id: 11,
  component_type: "library",
  group: "",
  name: "curl",
  version: "8.14.1-r1",
  publisher: "Daniel Stenberg",
  purl: "pkg:generic/curl@8.14.1-r1",
  cpe: originalCpe,
  structural_status: "STRUCTURALLY_VALID",
  cpe_fields: {
    part: "a",
    vendor: "syft",
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
  dictionary_status: "NOT_IN_DICTIONARY",
  bom_ref: "pkg:generic/curl@8.14.1-r1",
  properties: [],
  sbom_document: {
    id: 11,
    source_path: "uploaded-sboms/rutx.cdx.json",
    spec_version: "1.6",
    generator_name: "EMBA",
    generator_version: "1.4.3",
    source_type: "firmware_upload",
    scope: "firmware",
  },
  structural_error_message: null,
  dictionary_match: {
    snapshot_id: snapshotId,
    cpe_name_id: null,
    matched_cpe_name: null,
    deprecated: null,
  },
}

function jsonResponse<T>(body: T, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function decisionName(code: GroundTruthDecisionCode): string {
  return {
    CPE_CONFIRMED: "CPE Confirmed",
    OFFICIAL_CPE_MAPPED: "Official CPE mapped",
    DIRECT_OFFICIAL_CPE_NOT_CONFIRMED:
      "Direct official CPE not confirmed",
    UNRESOLVED: "Unresolved",
  }[code]
}

function recordFromPayload(
  payload: ComponentCpeGroundTruthWrite,
): ComponentCpeGroundTruthRecord {
  const source = payload.manual_cpe ? "MANUAL" : "NONE"
  return {
    id: 501,
    source,
    dictionary_cpe: null,
    manual_cpe: payload.manual_cpe,
    decision: {
      code: payload.decision,
      name: decisionName(payload.decision),
    },
    discrepancy_types: discrepancyTypes.filter((item) =>
      payload.discrepancy_type_ids.includes(item.id),
    ),
    resolution_outcome: {
      code:
        payload.decision === "UNRESOLVED"
          ? "UNRESOLVED"
          : source === "MANUAL"
            ? "MANUAL_FROM_OFFICIAL_FAMILY"
            : "DIRECT_OFFICIAL_NOT_CONFIRMED",
      label:
        payload.decision === "UNRESOLVED"
          ? "Unresolved"
          : source === "MANUAL"
            ? "Manual CPE from official family"
            : "Direct official CPE not confirmed",
    },
    correction_types: [],
    note: payload.note,
    created_at: "2026-08-09T00:00:00Z",
    updated_at: "2026-08-09T00:00:00Z",
  }
}

function restoredRecord(): ComponentCpeGroundTruthRecord {
  return recordFromPayload({
    decision: "OFFICIAL_CPE_MAPPED",
    dictionary_cpe_id: null,
    manual_cpe: mappedCpe,
    discrepancy_type_ids: [31, 33],
    note: "Reviewed from upstream evidence",
  })
}

function installFetch(options: { restore?: boolean } = {}) {
  vi.mocked(fetch).mockImplementation((input, init) => {
    const url = new URL(String(input), "http://frontend.test")
    if (url.pathname === "/api/health/") {
      return Promise.resolve(
        jsonResponse({ status: "ok", database: "ok" }),
      )
    }
    if (url.pathname === "/api/components/101/") {
      return Promise.resolve(jsonResponse(component))
    }
    if (
      url.pathname ===
      "/api/ground-truth/components/101/navigation/"
    ) {
      return Promise.resolve(
        jsonResponse({
          component_id: 101,
          previous_component_id: null,
          next_component_id: null,
        }),
      )
    }
    if (
      url.pathname === "/api/ground-truth-discrepancy-types/"
    ) {
      return Promise.resolve(jsonResponse(discrepancyTypes))
    }
    if (url.pathname === "/api/cpe-dictionary/snapshot/") {
      return Promise.resolve(
        jsonResponse({
          snapshot_id: snapshotId,
          manifest_sha256: "d".repeat(64),
          status: "COMPLETE",
        }),
      )
    }
    if (url.pathname === "/api/cpe-dictionary/") {
      return Promise.resolve(
        jsonResponse({
          snapshot: {
            snapshot_id: snapshotId,
            manifest_sha256: "d".repeat(64),
            status: "COMPLETE",
          },
          query: {},
          count: 0,
          page: 1,
          page_size: 25,
          results: [],
        }),
      )
    }
    if (
      url.pathname === "/api/components/101/cpe-ground-truth/"
    ) {
      if (init?.method === "PUT") {
        const payload = JSON.parse(
          String(init.body),
        ) as ComponentCpeGroundTruthWrite
        return Promise.resolve(
          jsonResponse({
            component_id: 101,
            snapshot_id: snapshotId,
            ground_truth: recordFromPayload(payload),
          }),
        )
      }
      return Promise.resolve(
        jsonResponse({
          component_id: 101,
          snapshot_id: snapshotId,
          ground_truth: options.restore ? restoredRecord() : null,
        }),
      )
    }
    if (url.pathname === "/api/sboms/") {
      return Promise.resolve(
        jsonResponse({
          count: 0,
          page: 1,
          page_size: 200,
          total_pages: 1,
          next: null,
          previous: null,
          results: [],
        }),
      )
    }
    if (url.pathname === "/api/ground-truth/components/") {
      return Promise.resolve(
        jsonResponse({
          count: 0,
          page: 1,
          page_size: 50,
          total_pages: 1,
          next: null,
          previous: null,
          results: [],
        }),
      )
    }
    return Promise.resolve(jsonResponse({}, 404))
  })
}

function editor(): HTMLElement {
  const title = screen.getByText("Expected Ground Truth CPE", {
    selector: "[data-slot='card-title']",
  })
  const card = title.closest("[data-slot='card']")
  if (!card) throw new Error("Ground Truth editor not found")
  return card as HTMLElement
}

function putPayload(): ComponentCpeGroundTruthWrite {
  const request = vi.mocked(fetch).mock.calls.find(([, init]) =>
    init?.method === "PUT",
  )
  if (!request) throw new Error("Ground Truth PUT was not sent")
  return JSON.parse(
    String(request[1]?.body),
  ) as ComponentCpeGroundTruthWrite
}

async function openDiscrepancyTypes(
  user: ReturnType<typeof userEvent.setup>,
): Promise<HTMLElement> {
  const trigger = within(editor()).getByRole("button", {
    name: /Discrepancy Types:/,
  })
  await user.click(trigger)
  await screen.findByLabelText("Discrepancy Type options")
  return trigger
}

describe("Ground Truth decision and discrepancy workflow", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn())
    vi.stubGlobal("confirm", vi.fn(() => true))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("renders one required Decision selector with the four values", async () => {
    installFetch()
    renderAppAt("/ground-truth/components/101")

    const decision = await within(editor()).findByRole("combobox", {
      name: "Ground Truth Decision",
    })
    expect(
      within(decision).getAllByRole("option").map((option) =>
        option.textContent,
      ),
    ).toEqual([
      "Select a decision",
      "CPE Confirmed",
      "Official CPE mapped",
      "Direct official CPE not confirmed",
      "Unresolved",
    ])
    expect(
      within(editor()).getByRole("button", {
        name: "Save Ground Truth",
      }),
    ).toBeDisabled()
  })

  it("restores an existing Decision and multiple Discrepancy Types", async () => {
    const user = userEvent.setup()
    installFetch({ restore: true })
    renderAppAt("/ground-truth/components/101")

    const review = editor()
    expect(
      await within(review).findByRole("combobox", {
        name: "Ground Truth Decision",
      }),
    ).toHaveValue("OFFICIAL_CPE_MAPPED")
    expect(
      within(review).getByRole("textbox", {
        name: "Manual CPE 2.3",
      }),
    ).toHaveValue(mappedCpe)
    expect(
      within(review).queryByRole("checkbox", {
        name: /Vendor mismatch/,
      }),
    ).not.toBeInTheDocument()
    expect(within(review).getByText("2 selected")).toBeInTheDocument()
    const trigger = await openDiscrepancyTypes(user)
    expect(trigger).toHaveAttribute("aria-expanded", "true")
    expect(
      screen.getByRole("checkbox", {
        name: /Vendor mismatch/,
      }),
    ).toBeChecked()
    expect(
      screen.getByRole("checkbox", {
        name: /Distribution package version normalized/,
      }),
    ).toBeChecked()
    await user.keyboard("{Escape}")
    await waitFor(() =>
      expect(trigger).toHaveAttribute("aria-expanded", "false"),
    )
  })

  it("saves multiple discrepancy IDs independently from Decision", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")

    const review = editor()
    const decision = await within(review).findByRole("combobox", {
      name: "Ground Truth Decision",
    })
    await user.selectOptions(decision, "OFFICIAL_CPE_MAPPED")
    await user.type(
      within(review).getByRole("textbox", {
        name: "Manual CPE 2.3",
      }),
      mappedCpe,
    )
    await openDiscrepancyTypes(user)
    await user.click(
      await screen.findByRole("checkbox", {
        name: /Vendor mismatch/,
      }),
    )
    await user.click(
      await screen.findByRole("checkbox", {
        name: /Distribution package version normalized/,
      }),
    )
    await within(review).findByText("2 selected")
    await user.click(screen.getByRole("button", { name: "Done" }))
    await user.click(
      within(review).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )

    await waitFor(() => {
      expect(putPayload()).toEqual({
        decision: "OFFICIAL_CPE_MAPPED",
        dictionary_cpe_id: null,
        manual_cpe: mappedCpe,
        discrepancy_type_ids: [31, 33],
        note: "",
      })
    })
    await within(review).findByText("Ground Truth saved.")
  })

  it("shows mapped-CPE discrepancy validation before sending a PUT", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")

    const review = editor()
    await user.selectOptions(
      await within(review).findByRole("combobox", {
        name: "Ground Truth Decision",
      }),
      "OFFICIAL_CPE_MAPPED",
    )
    await user.type(
      within(review).getByRole("textbox", {
        name: "Manual CPE 2.3",
      }),
      mappedCpe,
    )
    await user.click(
      within(review).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )

    expect(
      within(review).getAllByText(
        "Select at least one Discrepancy Type for Official CPE mapped.",
      ).length,
    ).toBeGreaterThan(0)
    expect(
      vi.mocked(fetch).mock.calls.some(([, init]) =>
        init?.method === "PUT",
      ),
    ).toBe(false)
  })

  it("clears CPE and preserves optional discrepancies for the direct decision", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")

    const review = editor()
    const decision = await within(review).findByRole("combobox", {
      name: "Ground Truth Decision",
    })
    await user.selectOptions(decision, "UNRESOLVED")
    const manual = within(review).getByRole("textbox", {
      name: "Manual CPE 2.3",
    })
    await user.type(manual, mappedCpe)
    await openDiscrepancyTypes(user)
    const vendor = await screen.findByRole("checkbox", {
      name: /Vendor mismatch/,
    })
    await user.click(vendor)
    await user.click(screen.getByRole("button", { name: "Done" }))
    await user.selectOptions(
      decision,
      "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
    )

    await waitFor(() => expect(manual).toHaveValue(""))
    expect(manual).toBeDisabled()
    expect(
      within(review).getByRole("button", {
        name: /Discrepancy Types: Vendor mismatch/,
      }),
    ).toBeInTheDocument()
  })

  it("uses canonical option order and a compact multi-select summary", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")

    const review = editor()
    await user.selectOptions(
      await within(review).findByRole("combobox", {
        name: "Ground Truth Decision",
      }),
      "UNRESOLVED",
    )
    expect(within(review).queryAllByRole("checkbox")).toHaveLength(0)
    const trigger = await openDiscrepancyTypes(user)
    const options = screen.getByLabelText("Discrepancy Type options")
    const checkboxes = within(options).getAllByRole("checkbox")
    expect(
      checkboxes.map((checkbox) => checkbox.dataset.code),
    ).toEqual([
      "PART_MISMATCH",
      "PRODUCT_MISMATCH",
      "VENDOR_MISMATCH",
      "VERSION_MISMATCH",
      "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED",
      "VERSION_NOT_IN_DICTIONARY",
    ])
    expect(
      within(options).getByText(
        /cannot be explained solely by distribution or vendor package version normalization/,
      ),
    ).toBeInTheDocument()

    for (const code of [
      "PART_MISMATCH",
      "PRODUCT_MISMATCH",
      "VENDOR_MISMATCH",
      "VERSION_MISMATCH",
    ]) {
      await user.click(
        within(options).getByRole("checkbox", {
          name: new RegExp(
            discrepancyTypes.find((item) => item.code === code)!
              .name,
          ),
        }),
      )
    }
    expect(trigger).toHaveAccessibleName(
      "Discrepancy Types: Part mismatch, Product mismatch, Vendor mismatch, Version mismatch",
    )
    expect(within(trigger).getByText("Part mismatch")).toBeInTheDocument()
    expect(
      within(trigger).getByText("Product mismatch"),
    ).toBeInTheDocument()
    expect(within(trigger).getByText("+2")).toBeInTheDocument()

    await user.click(
      within(options).getByRole("checkbox", {
        name: /Product mismatch/,
      }),
    )
    expect(trigger).toHaveAccessibleName(
      "Discrepancy Types: Part mismatch, Vendor mismatch, Version mismatch",
    )
    expect(within(trigger).getByText("+1")).toBeInTheDocument()
  })

  it("clears restored discrepancies when CPE Confirmed is selected", async () => {
    const user = userEvent.setup()
    installFetch({ restore: true })
    renderAppAt("/ground-truth/components/101")

    const review = editor()
    await within(review).findByText("2 selected")
    await user.selectOptions(
      within(review).getByRole("combobox", {
        name: "Ground Truth Decision",
      }),
      "CPE_CONFIRMED",
    )

    await waitFor(() =>
      expect(
        within(review).getByRole("button", {
          name: "Discrepancy Types: None selected",
        }),
      ).toBeDisabled(),
    )
    expect(
      within(review).getByText(
        "Discrepancy Types were cleared because the original CPE is confirmed.",
      ),
    ).toBeInTheDocument()
  })

  it("keeps CPE primary and save actions outside the scrolling details", async () => {
    installFetch()
    renderAppAt("/ground-truth/components/101")

    const review = editor()
    await within(review).findByRole("combobox", {
      name: "Ground Truth Decision",
    })
    const scrollRegion = within(review).getByTestId(
      "ground-truth-editor-scroll-region",
    )
    const cpe = within(review).getByTestId(
      "ground-truth-cpe-primary",
    )
    const classification = within(review).getByTestId(
      "ground-truth-classification",
    )
    const actions = within(review).getByTestId(
      "ground-truth-editor-actions",
    )

    expect(scrollRegion).toContainElement(cpe)
    expect(scrollRegion).toContainElement(classification)
    expect(cpe.compareDocumentPosition(classification)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    )
    expect(scrollRegion).not.toContainElement(actions)
    expect(actions).toHaveClass("sticky", "bottom-0")
  })

  it("uses Decision and Discrepancy filters in the review queue", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth")

    await screen.findByText("No components match the current filters.")
    expect(
      screen.getAllByRole("columnheader").map((header) =>
        header.textContent,
      ),
    ).toEqual([
      "Component",
      "Version",
      "Original CPE",
      "Ground Truth",
      "Ground Truth Decision",
      "Discrepancy Types",
      "Action",
    ])

    await user.selectOptions(
      screen.getByLabelText("Ground Truth Decision"),
      "OFFICIAL_CPE_MAPPED",
    )
    await user.selectOptions(
      screen.getByLabelText("Discrepancy Type"),
      "VENDOR_MISMATCH",
    )

    await waitFor(() => {
      const listCalls = vi.mocked(fetch).mock.calls.filter(([input]) =>
        String(input).includes("/api/ground-truth/components/?"),
      )
      const last = new URL(
        String(listCalls.at(-1)?.[0]),
        "http://frontend.test",
      )
      expect(last.searchParams.get("decision")).toBe(
        "OFFICIAL_CPE_MAPPED",
      )
      expect(last.searchParams.get("discrepancy_type")).toBe(
        "VENDOR_MISMATCH",
      )
    })
  })
})
