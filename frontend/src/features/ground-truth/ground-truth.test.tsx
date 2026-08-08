import {
  act,
  fireEvent,
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
  CpeDictionaryCandidate,
  CpeDictionaryDetail,
  CpeDictionarySearchResponse,
} from "@/features/cpe-dictionary/cpe-dictionary-types"
import type { ComponentDetail } from "@/features/components/components-types"
import type {
  ComponentCpeGroundTruthRecord,
  ComponentCpeGroundTruthResponse,
  GroundTruthComponentSummary,
  GroundTruthCorrectionType,
  GroundTruthResolutionOutcome,
  GroundTruthSource,
} from "@/features/ground-truth/ground-truth-types"
import type { SbomDocumentSummary } from "@/features/sboms/sboms-types"
import {
  renderAppAt,
  renderAppWithHistory,
} from "@/test/render-app"

const snapshotId = "20260725T035002Z"
const originalCpe =
  "cpe:2.3:a:syft:curl:8.14.1:*:*:*:*:*:*:*"
const correctedCpe =
  "cpe:2.3:a:haxx:curl:8.14.1:*:*:*:*:*:*:*"
const manualCpe =
  "cpe:2.3:a:haxx:curl:8.15.0:*:*:*:*:*:*:*"
const componentPurl =
  "pkg:apk/alpine/curl@8.14.1-r1?arch=x86_64&distro=alpine-3.24.1&upstream=curl%408.14.1"
const sbomFixture: SbomDocumentSummary = {
  id: 11,
  manufacturer: "Teltonika",
  product_name: "RUTX11 Firmware",
  product_version: "00.07.24.1",
  original_filename: "sbom.cdx.json",
  format: "CYCLONEDX_JSON",
  spec_version: "1.5",
  generator_name: "EMBA binary analysis environment",
  generator_version: "2.0.3",
  component_count: 790,
  uploaded_at: "2026-08-08T00:00:00Z",
}

const vendorCorrection: GroundTruthCorrectionType = {
  id: 21,
  code: "vendor_corrected",
  name: "Vendor corrected",
  description: "The vendor was changed to its canonical value.",
  is_active: true,
  usage_count: 2,
}
const productCorrection: GroundTruthCorrectionType = {
  id: 22,
  code: "product_corrected",
  name: "Product corrected",
  description: "The product was changed to its canonical value.",
  is_active: true,
  usage_count: 1,
}
const distributionCorrection: GroundTruthCorrectionType = {
  id: 23,
  code: "distribution_package_version_normalized",
  name: "Distribution package version normalized",
  description: "Distribution-specific version data was removed.",
  is_active: true,
  usage_count: 1,
}
const inactiveCorrection: GroundTruthCorrectionType = {
  id: 24,
  code: "archived_correction",
  name: "Archived correction",
  description: "Preserved inactive evidence.",
  is_active: false,
  usage_count: 1,
}

const originalCandidate: CpeDictionaryCandidate = {
  id: 1,
  cpe_name: originalCpe,
  cpe_uuid: "11111111-1111-4111-8111-111111111111",
  deprecated: false,
  part: "a",
  vendor: "syft",
  product: "curl",
  version: "8.14.1",
}
const correctedCandidate: CpeDictionaryCandidate = {
  id: 2,
  cpe_name: correctedCpe,
  cpe_uuid: "22222222-2222-4222-8222-222222222222",
  deprecated: false,
  part: "a",
  vendor: "haxx",
  product: "curl",
  version: "8.14.1",
}

const outcomeLabels = {
  ORIGINAL_OFFICIAL_CONFIRMED:
    "Original CPE confirmed",
  CORRECTED_TO_DICTIONARY:
    "Corrected to official CPE",
  MANUAL_FROM_OFFICIAL_FAMILY:
    "Manual CPE from official family",
  DIRECT_OFFICIAL_NOT_CONFIRMED:
    "Direct official CPE not confirmed",
} as const

function resolutionOutcome(
  code: keyof typeof outcomeLabels,
): GroundTruthResolutionOutcome {
  return { code, label: outcomeLabels[code] }
}

function componentDetail(
  id = 101,
  name = "curl",
): ComponentDetail {
  return {
    id,
    image: {
      id: 1,
      repository: "docker.io/library/alpine",
      tag: "3.24.1",
    },
    sbom: {
      id: 11,
      manufacturer: "",
      product_name: "alpine",
      product_version: "3.24.1",
      original_filename: "alpine-3.24.1.cdx.json",
    },
    sbom_document_id: 11,
    component_type: "library",
    group: "alpine",
    name,
    version: "8.14.1-r1",
    publisher: "Daniel Stenberg",
    purl: componentPurl,
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
    bom_ref: `pkg:apk/alpine/${name}@8.14.1-r1`,
    properties: [
      {
        name: "syft:package:foundBy",
        value: "apk-db-cataloger",
      },
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
      snapshot_id: snapshotId,
      cpe_name_id: null,
      matched_cpe_name: null,
      deprecated: null,
    },
  }
}

function groundTruthRecord(
  source: GroundTruthSource,
  corrections: GroundTruthCorrectionType[] = [],
): ComponentCpeGroundTruthRecord {
  const candidate =
    source === "DICTIONARY" ? correctedCandidate : null
  const outcome =
    source === "DICTIONARY"
      ? resolutionOutcome("CORRECTED_TO_DICTIONARY")
      : source === "MANUAL"
        ? resolutionOutcome("MANUAL_FROM_OFFICIAL_FAMILY")
        : resolutionOutcome("DIRECT_OFFICIAL_NOT_CONFIRMED")
  return {
    id: 501,
    source,
    dictionary_cpe: candidate,
    manual_cpe: source === "MANUAL" ? manualCpe : null,
    resolution_outcome: outcome,
    correction_types: corrections,
    note: source === "MANUAL" ? "Saved note" : "",
    created_at: "2026-07-28T00:00:00Z",
    updated_at: "2026-07-28T00:00:00Z",
  }
}

function listRow(
  id: number,
  source: GroundTruthSource | null,
): GroundTruthComponentSummary {
  const detail = componentDetail(
    id,
    id === 101 ? "curl" : id === 102 ? "openssl" : "dash",
  )
  const corrections =
    source === "MANUAL"
      ? [vendorCorrection, productCorrection]
      : []
  const groundTruth = source
    ? groundTruthRecord(source, corrections)
    : null
  return {
    ...detail,
    ground_truth_status: groundTruth
      ? "COMPLETED"
      : "UNREVIEWED",
    ground_truth: groundTruth,
    resolution_outcome:
      groundTruth?.resolution_outcome ?? null,
    correction_types:
      groundTruth?.correction_types ?? [],
  }
}

const dictionaryResponse: CpeDictionarySearchResponse = {
  snapshot: {
    snapshot_id: snapshotId,
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
  count: 2,
  page: 1,
  page_size: 25,
  results: [originalCandidate, correctedCandidate].map(
    (candidate) => ({
      id: candidate.id,
      cpe_name_id: candidate.cpe_uuid,
      cpe_name: candidate.cpe_name,
      part: candidate.part,
      vendor: candidate.vendor,
      product: candidate.product,
      version: candidate.version,
      update: "*",
      edition: "*",
      language: "*",
      sw_edition: "*",
      target_sw: "*",
      target_hw: "*",
      other: "*",
      deprecated: candidate.deprecated,
      title: candidate.product,
      snapshot_id: snapshotId,
    }),
  ),
}

function dictionaryDetail(
  candidate: CpeDictionaryCandidate,
): CpeDictionaryDetail {
  const result = dictionaryResponse.results.find(
    (item) => item.id === candidate.id,
  )
  if (!result) throw new Error("Dictionary fixture missing")
  return {
    ...result,
    snapshot_manifest_sha256: "d".repeat(64),
    deprecated_by: [],
    deprecates: [],
    created_at_nvd: "2020-01-01T00:00:00Z",
    last_modified_at_nvd: "2026-01-01T00:00:00Z",
    titles: [{ lang: "en", title: candidate.product }],
    references: [],
  }
}

function jsonResponse<T>(body: T, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

interface FetchOptions {
  restoredSource?: GroundTruthSource
  restoredCorrections?: GroundTruthCorrectionType[]
  invalidManual?: boolean
  saveError?: boolean
  delayedSave?: boolean
  missingPurl?: boolean
}

function installFetch(options: FetchOptions = {}) {
  let resolveSave: ((response: Response) => void) | undefined
  let correctionTypes = [
    vendorCorrection,
    productCorrection,
    distributionCorrection,
    inactiveCorrection,
  ]

  vi.mocked(fetch).mockImplementation((input, init) => {
    const url = new URL(String(input), "http://frontend.test")

    if (
      url.pathname ===
      "/api/ground-truth-correction-types/"
    ) {
      if (init?.method === "POST") {
        const payload = JSON.parse(String(init.body)) as {
          code: string
          name: string
          description: string
        }
        const created: GroundTruthCorrectionType = {
          id: 99,
          ...payload,
          is_active: true,
          usage_count: 0,
        }
        correctionTypes = [...correctionTypes, created]
        return Promise.resolve(jsonResponse(created, 201))
      }
      const includeAll =
        url.searchParams.get("is_active") === "all"
      return Promise.resolve(
        jsonResponse(
          correctionTypes.filter(
            (correctionType) =>
              includeAll || correctionType.is_active,
          ),
        ),
      )
    }

    const correctionTypeMatch = url.pathname.match(
      /^\/api\/ground-truth-correction-types\/(\d+)\/$/,
    )
    if (correctionTypeMatch && init?.method === "PATCH") {
      const id = Number(correctionTypeMatch[1])
      const payload = JSON.parse(String(init.body)) as {
        is_active?: boolean
      }
      const current = correctionTypes.find(
        (item) => item.id === id,
      )
      if (!current) {
        return Promise.resolve(jsonResponse({}, 404))
      }
      const updated = { ...current, ...payload }
      correctionTypes = correctionTypes.map((item) =>
        item.id === id ? updated : item,
      )
      return Promise.resolve(jsonResponse(updated))
    }

    if (url.pathname === "/api/health/") {
      return Promise.resolve(
        jsonResponse({ status: "ok", database: "ok" }),
      )
    }
    if (url.pathname === "/api/images/") {
      return Promise.resolve(
        jsonResponse([
          {
            id: 1,
            repository: "docker.io/library/alpine",
            tag: "3.24.1",
            platform: "linux/amd64",
            manifest_digest: `sha256:${"a".repeat(64)}`,
            pinned_reference: "alpine@sha256:test",
            sbom_count: 1,
            total_components: 3,
            components_with_primary_cpe: 3,
            components_without_primary_cpe: 0,
            primary_cpe_ratio: 1,
            unique_primary_cpes: 3,
          },
        ]),
      )
    }
    if (url.pathname === "/api/sboms/") {
      return Promise.resolve(
        jsonResponse({
          count: 1,
          page: 1,
          page_size: 200,
          total_pages: 1,
          next: null,
          previous: null,
          results: [sbomFixture],
        }),
      )
    }
    if (url.pathname === "/api/ground-truth/components/") {
      return Promise.resolve(
        jsonResponse({
          count: 3,
          page: Number(url.searchParams.get("page") ?? 1),
          page_size: Number(
            url.searchParams.get("page_size") ?? 50,
          ),
          total_pages: 1,
          next: null,
          previous: null,
          results: [
            listRow(101, null),
            listRow(102, "MANUAL"),
            listRow(103, "NONE"),
          ],
        }),
      )
    }

    const navigationMatch = url.pathname.match(
      /^\/api\/ground-truth\/components\/(\d+)\/navigation\/$/,
    )
    if (navigationMatch) {
      const id = Number(navigationMatch[1])
      return Promise.resolve(
        jsonResponse({
          component_id: id,
          previous_component_id: id === 102 ? 101 : null,
          next_component_id: id === 101 ? 102 : null,
        }),
      )
    }

    const groundTruthMatch = url.pathname.match(
      /^\/api\/components\/(\d+)\/cpe-ground-truth\/$/,
    )
    if (groundTruthMatch) {
      const id = Number(groundTruthMatch[1])
      if (init?.method === "PUT") {
        if (options.invalidManual || options.saveError) {
          return Promise.resolve(
            jsonResponse(
              {
                manual_cpe: [
                  options.invalidManual
                    ? "CPE must begin with cpe:2.3:"
                    : "Save rejected",
                ],
              },
              400,
            ),
          )
        }
        const payload = JSON.parse(String(init.body)) as {
          dictionary_cpe_id: number | null
          manual_cpe: string | null
          correction_type_ids: number[]
          note: string
        }
        const candidate =
          payload.dictionary_cpe_id === originalCandidate.id
            ? originalCandidate
            : payload.dictionary_cpe_id ===
                correctedCandidate.id
              ? correctedCandidate
              : null
        const source: GroundTruthSource = candidate
          ? "DICTIONARY"
          : payload.manual_cpe
            ? "MANUAL"
            : "NONE"
        const code = candidate
          ? candidate.cpe_name === originalCpe
            ? "ORIGINAL_OFFICIAL_CONFIRMED"
            : "CORRECTED_TO_DICTIONARY"
          : payload.manual_cpe
            ? "MANUAL_FROM_OFFICIAL_FAMILY"
            : "DIRECT_OFFICIAL_NOT_CONFIRMED"
        const selectedCorrections = correctionTypes.filter(
          (item) =>
            payload.correction_type_ids.includes(item.id),
        )
        const record: ComponentCpeGroundTruthRecord = {
          ...groundTruthRecord(source, selectedCorrections),
          dictionary_cpe: candidate,
          manual_cpe: payload.manual_cpe,
          resolution_outcome: resolutionOutcome(code),
          correction_types: selectedCorrections,
          note: payload.note,
        }
        const response = jsonResponse({
          component_id: id,
          snapshot_id: snapshotId,
          ground_truth: record,
        } satisfies ComponentCpeGroundTruthResponse)
        if (options.delayedSave) {
          return new Promise<Response>((resolve) => {
            resolveSave = resolve
          })
        }
        return Promise.resolve(response)
      }
      return Promise.resolve(
        jsonResponse({
          component_id: id,
          snapshot_id: snapshotId,
          ground_truth: options.restoredSource
            ? groundTruthRecord(
                options.restoredSource,
                options.restoredCorrections ?? [],
              )
            : null,
        } satisfies ComponentCpeGroundTruthResponse),
      )
    }

    const componentMatch = url.pathname.match(
      /^\/api\/components\/(\d+)\/$/,
    )
    if (componentMatch) {
      const id = Number(componentMatch[1])
      const detail = componentDetail(
        id,
        id === 101 ? "curl" : "openssl",
      )
      return Promise.resolve(
        jsonResponse(
          options.missingPurl
            ? { ...detail, purl: "" }
            : detail,
        ),
      )
    }

    if (url.pathname === "/api/cpe-dictionary/snapshot/") {
      return Promise.resolve(
        jsonResponse(dictionaryResponse.snapshot),
      )
    }
    if (url.pathname === "/api/cpe-dictionary/") {
      return Promise.resolve(jsonResponse(dictionaryResponse))
    }
    const detailMatch = url.pathname.match(
      /^\/api\/cpe-dictionary\/(.+)\/$/,
    )
    if (detailMatch) {
      const candidate =
        detailMatch[1] === originalCandidate.cpe_uuid
          ? originalCandidate
          : correctedCandidate
      return Promise.resolve(
        jsonResponse(dictionaryDetail(candidate)),
      )
    }
    return Promise.resolve(jsonResponse({}, 404))
  })

  return {
    resolveSave: () =>
      resolveSave?.(
        jsonResponse({
          component_id: 101,
          snapshot_id: snapshotId,
          ground_truth: groundTruthRecord("NONE"),
        }),
      ),
  }
}

function groundTruthEditor(): HTMLElement {
  const title = screen.getByText("Expected Ground Truth CPE", {
    selector: "[data-slot='card-title']",
  })
  const card = title.closest("[data-slot='card']")
  if (!card) throw new Error("Ground Truth editor not found")
  return card as HTMLElement
}

function componentContext(): HTMLElement {
  const title = screen.getByText("Component context", {
    selector: "[data-slot='card-title']",
  })
  const card = title.closest("[data-slot='card']")
  if (!card) throw new Error("Component context not found")
  return card as HTMLElement
}

function putRequests() {
  return vi.mocked(fetch).mock.calls.filter(([, init]) => {
    return init?.method === "PUT"
  })
}

function postRequests() {
  return vi.mocked(fetch).mock.calls.filter(([, init]) => {
    return init?.method === "POST"
  })
}

describe("Ground Truth outcome and correction workflow", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn())
    vi.stubGlobal("confirm", vi.fn(() => true))
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("renders separate outcome and correction columns and filters", async () => {
    installFetch()
    renderAppAt("/ground-truth")

    const table = await screen.findByRole("table", {
      name: "Ground Truth review components",
    })
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual([
      "Component",
      "Version",
      "Original CPE",
      "Ground Truth",
      "Resolution Outcome",
      "Correction Types",
      "Action",
    ])
    expect(
      within(table).queryByRole("columnheader", {
        name: "Ground Truth Status",
      }),
    ).not.toBeInTheDocument()
    expect(
      within(table).queryByRole("columnheader", {
        name: "Exact Match",
      }),
    ).not.toBeInTheDocument()
    expect(within(table).queryByText("Not in Dictionary"))
      .not.toBeInTheDocument()
    for (const row of within(table).getAllByRole("row").slice(1)) {
      expect(within(row).getAllByRole("cell")).toHaveLength(7)
    }
    expect(
      within(table).queryByRole("columnheader", {
        name: "Decision Type",
      }),
    ).not.toBeInTheDocument()
    expect(within(table).getByText("Manual CPE from official family"))
      .toBeInTheDocument()
    expect(within(table).getByText("Vendor corrected"))
      .toBeInTheDocument()
    expect(within(table).getByText("Product corrected"))
      .toBeInTheDocument()
    expect(within(table).getByText("No direct official CPE"))
      .toBeInTheDocument()
    expect(within(table).getByText("Not Assigned"))
      .toBeInTheDocument()
    expect(within(table).getByText(manualCpe)).toBeInTheDocument()
    expect(within(table).getAllByText("None")).not.toHaveLength(0)
    expect(within(table).queryByText("Not Reviewed"))
      .not.toBeInTheDocument()
    expect(within(table).queryByText("Completed"))
      .not.toBeInTheDocument()
    expect(within(table).getByRole("link", { name: "Review" }))
      .toBeInTheDocument()
    expect(within(table).getAllByRole("link", { name: "Edit" }))
      .toHaveLength(2)
    expect(
      screen.getByRole("heading", { name: "Ground Truth" }),
    ).toBeInTheDocument()
    expect(
      screen.getByText("Independent human-authored CPE answers"),
    ).toBeInTheDocument()
    expect(screen.queryByText("Review Components"))
      .not.toBeInTheDocument()
    expect(
      screen.queryByText(
        "Review components with a Primary CPE and assign an independent expected CPE.",
      ),
    ).not.toBeInTheDocument()
    expect(screen.getByLabelText("Component Keyword"))
      .not.toHaveAttribute("placeholder")
    expect(
      screen.getByRole("button", { name: "Search" }),
    ).toBeInTheDocument()
    expect(screen.getByLabelText("Resolution Outcome"))
      .toBeInTheDocument()
    expect(screen.getByLabelText("Ground Truth Status"))
      .toBeInTheDocument()
    expect(screen.getByLabelText("Correction Type"))
      .toBeInTheDocument()
    expect(screen.queryByLabelText("Image")).not.toBeInTheDocument()
    expect(screen.getByLabelText("SBOM")).toBeInTheDocument()
    expect(
      screen.getByRole("option", { name: "All SBOMs" }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("option", {
        name: "Teltonika RUTX11 Firmware 00.07.24.1",
      }),
    ).toBeInTheDocument()
    expect(screen.queryByLabelText("Exact Match"))
      .not.toBeInTheDocument()
    expect(screen.getByLabelText("Dictionary Status"))
      .toBeInTheDocument()
    expect(
      screen.getByRole("option", {
        name: "All Dictionary Statuses",
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("option", {
        name: "Primary CPE Not Present",
      }),
    ).toBeInTheDocument()
    expect(screen.getByLabelText("Sort")).toHaveValue("id")
    expect(
      screen.getByRole("option", {
        name: "Component ID Ascending",
      }),
    ).toBeInTheDocument()
  })

  it("keeps SBOM and review filters in URL/API state and resets them", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth")
    await screen.findByText("curl")

    await user.selectOptions(screen.getByLabelText("SBOM"), "11")
    await user.selectOptions(
      screen.getByLabelText("Resolution Outcome"),
      "MANUAL_FROM_OFFICIAL_FAMILY",
    )
    await user.selectOptions(
      screen.getByLabelText("Correction Type"),
      "vendor_corrected",
    )
    await user.selectOptions(
      screen.getByLabelText("Dictionary Status"),
      "NOT_IN_DICTIONARY",
    )

    await waitFor(() => {
      const location =
        screen.getByTestId("route-location").textContent ?? ""
      const query = new URL(
        location,
        "http://frontend.test",
      ).searchParams
      expect(query.get("resolution_outcome")).toBe(
        "MANUAL_FROM_OFFICIAL_FAMILY",
      )
      expect(query.get("sbom_id")).toBe("11")
      expect(query.has("image_id")).toBe(false)
      expect(query.get("correction_type")).toBe(
        "vendor_corrected",
      )
      expect(query.get("dictionary_status")).toBe(
        "NOT_IN_DICTIONARY",
      )
      const listRequests = vi
        .mocked(fetch)
        .mock.calls.map(([input]) =>
          new URL(String(input), "http://frontend.test"),
        )
        .filter(
          (url) =>
            url.pathname === "/api/ground-truth/components/",
        )
      expect(listRequests.at(-1)?.searchParams.get("sbom_id"))
        .toBe("11")
    })

    await user.selectOptions(screen.getByLabelText("SBOM"), "")
    await waitFor(() => {
      const location =
        screen.getByTestId("route-location").textContent ?? ""
      expect(
        new URL(location, "http://frontend.test").searchParams.has(
          "sbom_id",
        ),
      ).toBe(false)
    })
    await user.selectOptions(screen.getByLabelText("SBOM"), "11")

    await user.click(
      screen.getByRole("button", { name: "Reset" }),
    )
    await waitFor(() => {
      expect(
        screen.getByTestId("route-location").textContent,
      ).toBe("/ground-truth")
    })
    expect(screen.getByLabelText("Resolution Outcome"))
      .toHaveValue("")
    expect(screen.getByLabelText("Correction Type")).toHaveValue(
      "",
    )
    expect(screen.getByLabelText("Dictionary Status"))
      .toHaveValue("")
    expect(screen.getByLabelText("SBOM")).toHaveValue("")
    expect(screen.getByLabelText("Sort")).toHaveValue("id")
  })

  it("preserves outcome and correction filters in review navigation", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt(
      "/ground-truth?sbom_id=11&resolution_outcome=MANUAL_FROM_OFFICIAL_FAMILY&correction_type=vendor_corrected",
    )
    const editLinks = await screen.findAllByRole("link", {
      name: "Edit",
    })
    await user.click(editLinks[0])

    const location =
      screen.getByTestId("route-location").textContent ?? ""
    expect(location).toContain("/ground-truth/components/102")
    expect(decodeURIComponent(location)).toContain(
      "resolution_outcome=MANUAL_FROM_OFFICIAL_FAMILY",
    )
    expect(decodeURIComponent(location)).toContain(
      "correction_type=vendor_corrected",
    )
    expect(decodeURIComponent(location)).toContain("sbom_id=11")
  })

  it("shows Pending review until a new reviewer creates a preview", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()

    expect(
      await within(editor).findByText(
        "Pending review",
      ),
    ).toBeInTheDocument()
    expect(
      within(editor).getByText(
        "Select a Dictionary CPE, enter a Manual CPE, or save the reviewed result.",
      ),
    ).toBeInTheDocument()
    expect(
      within(editor).queryByRole("combobox", {
        name: "Decision Type",
      }),
    ).not.toBeInTheDocument()
    const corrections = within(editor).getByRole("combobox", {
      name: "Correction Types",
    })
    expect(corrections).toBeDisabled()

    const manual = within(editor).getByPlaceholderText(
      /cpe:2\.3:a:vendor/,
    )
    await user.type(manual, manualCpe)
    expect(
      within(editor).getByText(
        "Manual CPE from official family",
      ),
    ).toBeInTheDocument()
    expect(
      within(editor).getByText(
        "Preview calculated from the current Ground Truth result and confirmed by the server when saved.",
      ),
    ).toBeInTheDocument()
    expect(corrections).toBeEnabled()

    await user.clear(manual)
    expect(
      within(editor).getByText(
        "Pending review",
      ),
    ).toBeInTheDocument()
    expect(corrections).toBeDisabled()
  })

  it("shows a saved no-direct-CPE result as server-confirmed", async () => {
    installFetch({ restoredSource: "NONE" })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()

    expect(
      await within(editor).findByText(
        "Direct official CPE not confirmed",
      ),
    ).toBeInTheDocument()
    expect(
      within(editor).getByText(
        "Server-confirmed outcome from the saved Ground Truth.",
      ),
    ).toBeInTheDocument()
    expect(within(editor).queryByText("Pending review"))
      .not.toBeInTheDocument()
  })

  it("supports multi-select, badge removal, outside click, and Escape", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    const manual = await within(editor).findByPlaceholderText(
      /cpe:2\.3:a:vendor/,
    )
    await user.type(manual, manualCpe)
    const combobox = within(editor).getByRole("combobox", {
      name: "Correction Types",
    })

    await user.click(combobox)
    await user.click(
      await screen.findByRole("option", {
        name: "Vendor corrected",
      }),
    )
    await user.click(
      screen.getByRole("option", {
        name: "Product corrected",
      }),
    )
    expect(
      within(editor).getByRole("button", {
        name: "Remove correction type Vendor corrected",
      }),
    ).toBeInTheDocument()
    expect(
      within(editor).getByRole("button", {
        name: "Remove correction type Product corrected",
      }),
    ).toBeInTheDocument()

    await user.click(
      within(editor).getByRole("button", {
        name: "Remove correction type Vendor corrected",
      }),
    )
    expect(
      within(editor).queryByRole("button", {
        name: "Remove correction type Vendor corrected",
      }),
    ).not.toBeInTheDocument()

    expect(combobox).toHaveAttribute("aria-expanded", "false")
    await user.click(combobox)
    expect(combobox).toHaveAttribute("aria-expanded", "true")
    await user.click(
      within(editor).getByText("Expected Ground Truth CPE"),
    )
    expect(combobox).toHaveAttribute("aria-expanded", "false")
    await user.click(combobox)
    expect(combobox).toHaveAttribute("aria-expanded", "true")
    await user.keyboard("{Escape}")
    expect(combobox).toHaveAttribute("aria-expanded", "false")
  })

  it("restores an inactive correction but excludes it from new options", async () => {
    const user = userEvent.setup()
    installFetch({
      restoredSource: "MANUAL",
      restoredCorrections: [inactiveCorrection],
    })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()

    expect(
      await within(editor).findByText("Archived correction"),
    ).toBeInTheDocument()
    expect(within(editor).getByText("Inactive"))
      .toBeInTheDocument()
    const combobox = within(editor).getByRole("combobox", {
      name: "Correction Types",
    })
    await user.click(combobox)
    expect(
      screen.queryByRole("option", {
        name: "Archived correction",
      }),
    ).not.toBeInTheDocument()
  })

  it("clears corrections when an outcome stops allowing them", async () => {
    const user = userEvent.setup()
    installFetch({
      restoredSource: "MANUAL",
      restoredCorrections: [vendorCorrection],
    })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    const manual = await within(editor).findByDisplayValue(
      manualCpe,
    )
    expect(
      within(editor).getByRole("button", {
        name: "Remove correction type Vendor corrected",
      }),
    ).toBeInTheDocument()

    await user.clear(manual)
    expect(
      await within(editor).findByText(
        "Correction Types were cleared because this Resolution Outcome does not allow them.",
      ),
    ).toBeInTheDocument()
    expect(
      within(editor).queryByRole("button", {
        name: "Remove correction type Vendor corrected",
      }),
    ).not.toBeInTheDocument()
    expect(
      within(editor).getByRole("combobox", {
        name: "Correction Types",
      }),
    ).toBeDisabled()
  })

  it("derives corrected and original outcomes from selected raw CPEs", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101?q=curl")
    expect(await screen.findByText("2 results"))
      .toBeInTheDocument()
    const correctedRow = screen
      .getByText(correctedCpe)
      .closest("tr")
    const originalRow = screen
      .getAllByText(originalCpe)
      .find((element) => element.closest("tr"))
      ?.closest("tr")
    if (!correctedRow || !originalRow) {
      throw new Error("Dictionary result row missing")
    }
    await user.click(
      within(correctedRow).getByRole("button", {
        name: "Select as Ground Truth",
      }),
    )
    expect(
      within(groundTruthEditor()).getByText(
        "Corrected to official CPE",
      ),
    ).toBeInTheDocument()
    expect(
      within(groundTruthEditor()).getByRole("combobox", {
        name: "Correction Types",
      }),
    ).toBeEnabled()

    await user.click(
      within(originalRow).getByRole("button", {
        name: "Select as Ground Truth",
      }),
    )
    expect(
      within(groundTruthEditor()).getByText(
        "Original CPE confirmed",
      ),
    ).toBeInTheDocument()
    expect(
      within(groundTruthEditor()).getByRole("combobox", {
        name: "Correction Types",
      }),
    ).toBeDisabled()
  })

  it("keeps restored Dictionary and Manual CPE values mutually exclusive", async () => {
    const user = userEvent.setup()
    installFetch({ restoredSource: "DICTIONARY" })
    renderAppAt("/ground-truth/components/101?q=curl")
    const editor = groundTruthEditor()
    const manual = await within(editor).findByPlaceholderText(
      /cpe:2\.3:a:vendor/,
    )
    expect(within(editor).getByText(correctedCpe))
      .toBeInTheDocument()

    await user.type(manual, manualCpe)
    expect(within(editor).getByText("No Dictionary CPE selected"))
      .toBeInTheDocument()
    expect(manual).toHaveValue(manualCpe)

    const correctedRow = screen.getByText(correctedCpe).closest("tr")
    if (!correctedRow) throw new Error("Dictionary result row missing")
    await user.click(
      within(correctedRow).getByRole("button", {
        name: "Select as Ground Truth",
      }),
    )
    expect(manual).toHaveValue("")
    expect(within(editor).getByText(correctedCpe))
      .toBeInTheDocument()
  })

  it("creates and manages Correction Types without a delete action", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await user.type(
      await within(editor).findByPlaceholderText(
        /cpe:2\.3:a:vendor/,
      ),
      manualCpe,
    )
    const combobox = within(editor).getByRole("combobox", {
      name: "Correction Types",
    })
    await user.type(combobox, "Architecture corrected")
    await user.click(
      await screen.findByRole("option", {
        name: "Create “Architecture corrected”",
      }),
    )
    const createDialog = screen.getByRole("dialog", {
      name: "Add Correction Type",
    })
    expect(within(createDialog).getByLabelText("Code"))
      .toHaveValue("architecture_corrected")
    await user.type(
      within(createDialog).getByLabelText("Description"),
      "Architecture evidence changed.",
    )
    await user.click(
      within(createDialog).getByRole("button", {
        name: "Create",
      }),
    )
    expect(
      await within(editor).findByText(
        "Architecture corrected",
      ),
    ).toBeInTheDocument()
    expect(postRequests()).toHaveLength(1)

    await user.click(
      within(editor).getByRole("button", {
        name: "Manage Correction Types",
      }),
    )
    const manageDialog = await screen.findByRole("dialog", {
      name: "Manage Correction Types",
    })
    expect(within(manageDialog).queryByText("Delete"))
      .not.toBeInTheDocument()
    const vendorRow = within(manageDialog)
      .getByText("Vendor corrected")
      .closest(".rounded-lg.border")
    if (!vendorRow) throw new Error("Vendor row missing")
    await user.click(
      within(vendorRow as HTMLElement).getByRole("button", {
        name: "Deactivate",
      }),
    )
    const confirmation = screen.getByRole("dialog", {
      name: "Deactivate Correction Type?",
    })
    await user.click(
      within(confirmation).getByRole("button", {
        name: "Deactivate",
      }),
    )
    await waitFor(() => {
      const updatedRow = within(manageDialog)
        .getByText("Vendor corrected")
        .closest(".rounded-lg.border")
      expect(
        within(updatedRow as HTMLElement).getByRole("button", {
          name: "Reactivate",
        }),
      ).toBeInTheDocument()
    })
  })

  it("saves correction IDs without accepting a client outcome", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await user.type(
      await within(editor).findByPlaceholderText(
        /cpe:2\.3:a:vendor/,
      ),
      manualCpe,
    )
    const combobox = within(editor).getByRole("combobox", {
      name: "Correction Types",
    })
    await user.click(combobox)
    await user.click(
      await screen.findByRole("option", {
        name: "Vendor corrected",
      }),
    )
    await user.click(
      screen.getByRole("option", {
        name: "Product corrected",
      }),
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )

    expect(
      await within(editor).findByText("Ground Truth saved."),
    ).toBeInTheDocument()
    const payload = JSON.parse(
      String(putRequests()[0][1]?.body),
    ) as Record<string, unknown>
    expect(payload).toMatchObject({
      dictionary_cpe_id: null,
      manual_cpe: manualCpe,
      correction_type_ids: [22, 21],
    })
    expect(payload).not.toHaveProperty("resolution_outcome")
    expect(payload).not.toHaveProperty("decision_type_id")
  })

  it("saves a no-CPE result with no corrections", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "Pending review",
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )

    await waitFor(() => expect(putRequests()).toHaveLength(1))
    const payload = JSON.parse(
      String(putRequests()[0][1]?.body),
    ) as Record<string, unknown>
    expect(payload).toMatchObject({
      dictionary_cpe_id: null,
      manual_cpe: null,
      correction_type_ids: [],
    })
    expect(JSON.stringify(payload)).not.toContain("Pending review")
    expect(
      await within(editor).findByText(
        "Direct official CPE not confirmed",
      ),
    ).toBeInTheDocument()
    expect(within(editor).queryByText("Pending review"))
      .not.toBeInTheDocument()
    expect(
      within(editor).getByText(
        "Server-confirmed outcome from the saved Ground Truth.",
      ),
    ).toBeInTheDocument()
  })

  it("preserves invalid manual input after server validation", async () => {
    const user = userEvent.setup()
    installFetch({ invalidManual: true })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    const manual = await within(editor).findByPlaceholderText(
      /cpe:2\.3:a:vendor/,
    )
    await user.type(manual, "invalid")
    await user.click(
      within(editor).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )

    expect(
      await within(editor).findByText(
        /CPE must begin with cpe:2.3:/,
      ),
    ).toBeInTheDocument()
    expect(manual).toHaveValue("invalid")
  })

  it("prevents duplicate saves while a request is pending", async () => {
    const user = userEvent.setup()
    const controls = installFetch({ delayedSave: true })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "Pending review",
    )
    const save = within(editor).getByRole("button", {
      name: "Save Ground Truth",
    })
    await user.click(save)
    expect(save).toBeDisabled()
    await user.click(save)
    expect(putRequests()).toHaveLength(1)

    await act(async () => controls.resolveSave())
    expect(await within(editor).findByText("Saved"))
      .toBeInTheDocument()
  })

  it("saves and moves to the next filtered Component", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt(
      "/ground-truth/components/101?queue=resolution_outcome%3DMANUAL_FROM_OFFICIAL_FAMILY%26correction_type%3Dvendor_corrected",
    )
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "Pending review",
    )
    await user.type(screen.getByLabelText("Vendor"), "haxx")
    await user.type(screen.getByLabelText("Product"), "curl")
    await user.click(
      screen.getByRole("button", { name: "Search" }),
    )
    expect(await screen.findByText("2 results")).toBeInTheDocument()
    await user.click(
      within(editor).getByRole("button", {
        name: "Save and Next",
      }),
    )

    await waitFor(() => {
      expect(
        screen.getByTestId("route-location").textContent,
      ).toContain("/ground-truth/components/102")
    })
    expect(
      decodeURIComponent(
        screen.getByTestId("route-location").textContent ?? "",
      ),
    ).toContain("correction_type=vendor_corrected")
    expect(screen.getByLabelText("Vendor")).toHaveValue("")
    expect(screen.getByLabelText("Product")).toHaveValue("")
    expect(screen.getByLabelText("Part")).toHaveValue("")
    expect(screen.getByLabelText("Status")).toHaveValue("active")
    expect(screen.queryByText("2 results")).not.toBeInTheDocument()
  })

  it("preserves Component evidence and the existing review layout", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")

    expect(
      await screen.findByText("Component context"),
    ).toBeInTheDocument()
    expect(
      screen.queryByText("CPE Dictionary Snapshot"),
    ).not.toBeInTheDocument()
    expect(
      await screen.findByText(
        new RegExp(`Snapshot: ${snapshotId}`),
      ),
    ).toBeInTheDocument()
    expect(screen.getByText("Search Official CPE Names"))
      .toBeInTheDocument()
    const context = componentContext()
    expect(within(context).queryByText("Read only"))
      .not.toBeInTheDocument()
    expect(within(context).queryByText("Docker image"))
      .not.toBeInTheDocument()
    expect(within(context).queryByText("SBOM document"))
      .not.toBeInTheDocument()
    expect(within(context).queryByText("Exact Match"))
      .not.toBeInTheDocument()
    expect(within(context).getByText("Dictionary Status"))
      .toBeInTheDocument()
    expect(within(context).getByText("Not in Dictionary"))
      .toBeInTheDocument()
    expect(within(context).getByText("Name")).toBeInTheDocument()
    expect(within(context).getByText("Version"))
      .toBeInTheDocument()
    expect(within(context).getByText("Group")).toBeInTheDocument()
    expect(within(context).getByText("Publisher"))
      .toBeInTheDocument()
    expect(within(context).getByText("Type")).toBeInTheDocument()
    expect(within(context).getByText("Primary CPE"))
      .toBeInTheDocument()
    expect(within(context).getByText("PURL")).toBeInTheDocument()
    expect(within(context).getByText(componentPurl)).toHaveClass(
      "whitespace-normal",
      "break-all",
    )
    expect(within(context).getByText(originalCpe)).toHaveClass(
      "whitespace-normal",
      "break-all",
    )
    expect(within(context).getByText("Daniel Stenberg"))
      .toBeInTheDocument()
    const properties = within(context)
      .getByText(/Relevant package properties/)
      .closest("details")
    expect(properties).not.toHaveAttribute("open")
    await user.click(
      within(context).getByText(
        /Relevant package properties/,
      ),
    )
    expect(properties).toHaveAttribute("open")

    for (const field of [
      "Keyword",
      "Vendor",
      "Product",
      "Version",
    ]) {
      expect(screen.getByLabelText(field)).not.toHaveAttribute(
        "placeholder",
      )
    }
  })

  it("resets Dictionary search state and results across Review navigation", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt(
      "/ground-truth/components/101?queue=sbom_id%3D11%26page%3D2",
    )
    await within(groundTruthEditor()).findByText(
      "Pending review",
    )

    await user.type(screen.getByLabelText("Keyword"), "curl")
    await user.selectOptions(screen.getByLabelText("Part"), "a")
    await user.type(screen.getByLabelText("Vendor"), "haxx")
    await user.type(screen.getByLabelText("Product"), "curl")
    await user.type(screen.getByLabelText("Version"), "8.14.1")
    await user.selectOptions(screen.getByLabelText("Status"), "all")
    await user.click(screen.getByRole("button", { name: "Search" }))
    expect(await screen.findByText("2 results")).toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "Next" }))
    await waitFor(() => {
      expect(screen.getByTestId("route-location").textContent)
        .toContain("/ground-truth/components/102")
    })
    expect(screen.getByLabelText("Keyword")).toHaveValue("")
    expect(screen.getByLabelText("Part")).toHaveValue("")
    expect(screen.getByLabelText("Vendor")).toHaveValue("")
    expect(screen.getByLabelText("Product")).toHaveValue("")
    expect(screen.getByLabelText("Version")).toHaveValue("")
    expect(screen.getByLabelText("Status")).toHaveValue("active")
    expect(screen.queryByText("2 results")).not.toBeInTheDocument()
    expect(
      screen.getByText("Search the selected Dictionary snapshot"),
    ).toBeInTheDocument()
    const location = new URL(
      screen.getByTestId("route-location").textContent ?? "",
      "http://frontend.test",
    )
    expect([...location.searchParams.keys()]).toEqual(["queue"])
    expect(location.searchParams.get("queue")).toBe(
      "sbom_id=11&page=2",
    )

    await user.type(screen.getByLabelText("Vendor"), "openssl")
    await user.click(screen.getByRole("button", { name: "Search" }))
    expect(await screen.findByText("2 results")).toBeInTheDocument()
    await user.click(
      screen.getByRole("button", { name: "Previous" }),
    )
    await waitFor(() => {
      expect(screen.getByTestId("route-location").textContent)
        .toContain("/ground-truth/components/101")
    })
    expect(screen.getByLabelText("Vendor")).toHaveValue("")
    expect(screen.getByLabelText("Part")).toHaveValue("")
    expect(screen.getByLabelText("Status")).toHaveValue("active")
    expect(screen.queryByText("2 results")).not.toBeInTheDocument()

    await user.click(
      screen.getByRole("link", { name: "Back to Review Queue" }),
    )
    await waitFor(() => {
      expect(screen.getByTestId("route-location").textContent).toBe(
        "/ground-truth?sbom_id=11&page=2",
      )
    })
  })

  it("shows Not provided when the Component PURL is absent", async () => {
    installFetch({ missingPurl: true })
    renderAppAt("/ground-truth/components/101")
    await screen.findByText("Component context")
    const context = componentContext()
    const purlLabel = within(context).getByText("PURL", {
      selector: "dt",
    })
    expect(purlLabel.parentElement).toHaveTextContent(
      "Not provided",
    )
  })

  it("guards dirty navigation and reloads a new Component", async () => {
    const user = userEvent.setup()
    installFetch()
    const { router } = renderAppWithHistory([
      "/ground-truth/components/101",
    ])
    const editor = groundTruthEditor()
    const manual = await within(editor).findByPlaceholderText(
      /cpe:2\.3:a:vendor/,
    )
    await user.type(manual, manualCpe)
    vi.mocked(confirm).mockReturnValueOnce(false)
    await user.click(
      screen.getByRole("button", { name: "Next" }),
    )
    expect(
      screen.getByTestId("route-location").textContent,
    ).toContain("/101")

    await act(async () => {
      await router.navigate("/ground-truth/components/102")
    })
    expect(
      await within(groundTruthEditor()).findByText(
        "Pending review",
      ),
    ).toBeInTheDocument()
    expect(
      within(groundTruthEditor()).getByPlaceholderText(
        /cpe:2\.3:a:vendor/,
      ),
    ).toHaveValue("")
  })

  it("opens Correction Types with keyboard navigation", async () => {
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    fireEvent.change(
      await within(editor).findByPlaceholderText(
        /cpe:2\.3:a:vendor/,
      ),
      { target: { value: manualCpe } },
    )
    const combobox = within(editor).getByRole("combobox", {
      name: "Correction Types",
    })
    fireEvent.keyDown(combobox, { key: "ArrowDown" })
    expect(combobox).toHaveAttribute("aria-expanded", "true")
    fireEvent.keyDown(combobox, { key: "Enter" })
    expect(
      within(editor).getByRole("button", {
        name: "Remove correction type Distribution package version normalized",
      }),
    ).toBeInTheDocument()
  })
})
