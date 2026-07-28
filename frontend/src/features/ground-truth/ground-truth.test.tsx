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
import type {
  ComponentCpeGroundTruthRecord,
  ComponentCpeGroundTruthResponse,
  GroundTruthComponentSummary,
  GroundTruthDecisionType,
  GroundTruthSource,
} from "@/features/ground-truth/ground-truth-types"
import {
  renderAppAt,
  renderAppWithHistory,
} from "@/test/render-app"

const snapshotId = "20260725T035002Z"
const cpeName =
  "cpe:2.3:a:haxx:curl:8.14.1:*:*:*:*:*:*:*"
const cpeUuid = "11111111-1111-4111-8111-111111111111"
const manualCpe =
  "cpe:2.3:a:haxx:curl:8.15.0:*:*:*:*:*:*:*"
const componentPurl =
  "pkg:apk/alpine/curl@8.14.1-r1?arch=x86_64&distro=alpine-3.24.1&upstream=curl%408.14.1"
const initialDecisionTypes: GroundTruthDecisionType[] = [
  {
    id: 21,
    name: "Official CPE confirmed",
    description:
      "The exact active CPE Name is present in the selected CPE Dictionary snapshot.",
    is_active: true,
    usage_count: 0,
  },
  {
    id: 22,
    name:
      "Official CPE family confirmed; version not in Dictionary",
    description:
      "The canonical part, vendor, and product are confirmed, but the exact component version is absent from the selected CPE Dictionary snapshot.",
    is_active: true,
    usage_count: 0,
  },
  {
    id: 23,
    name: "Distribution package revision normalized",
    description:
      "A distribution-specific package revision was removed while preserving the confirmed upstream product version.",
    is_active: true,
    usage_count: 0,
  },
  {
    id: 24,
    name: "Deprecated CPE redirected to active CPE",
    description:
      "A deprecated CPE or alias was resolved to its active canonical CPE.",
    is_active: true,
    usage_count: 0,
  },
  {
    id: 25,
    name: "Mapped to parent product CPE",
    description:
      "The component is a subpackage or derived package represented by the parent product's CPE.",
    is_active: true,
    usage_count: 0,
  },
  {
    id: 26,
    name: "No independent CPE",
    description:
      "The component is a subpackage, data package, compatibility package, or internal unit without an independent CPE identity.",
    is_active: true,
    usage_count: 0,
  },
  {
    id: 27,
    name: "Direct official CPE not confirmed",
    description:
      "No directly corresponding official CPE family could be confirmed from the available evidence.",
    is_active: true,
    usage_count: 0,
  },
]
const activeDecisionType = initialDecisionTypes[0]
const inactiveDecisionType: GroundTruthDecisionType = {
  id: 28,
  name: "Archived English review",
  description: "Preserved inactive English value",
  is_active: false,
  usage_count: 1,
}

const candidate = {
  id: 1,
  cpe_name: cpeName,
  cpe_uuid: cpeUuid,
  deprecated: false,
  part: "a",
  vendor: "haxx",
  product: "curl",
  version: "8.14.1",
}

function componentDetail(
  id = 101,
  name = "curl",
): ComponentDetail {
  return {
    id,
    image: {
      id: id === 101 ? 1 : 2,
      repository: "docker.io/library/alpine",
      tag: "3.24.1",
    },
    sbom_document_id: 11,
    component_type: "library",
    group: "alpine",
    name,
    version: "8.14.1-r1",
    publisher: "Daniel Stenberg",
    purl: componentPurl,
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
      cpe_name_id: cpeUuid,
      matched_cpe_name: cpeName,
      deprecated: false,
    },
  }
}

function groundTruthRecord(
  source: GroundTruthSource,
): ComponentCpeGroundTruthRecord {
  return {
    id: 501,
    source,
    dictionary_cpe: source === "DICTIONARY" ? candidate : null,
    ground_truth_cpe:
      source === "DICTIONARY" ? candidate : null,
    manual_cpe: source === "MANUAL" ? manualCpe : null,
    decision_type:
      source === "NONE"
        ? inactiveDecisionType
        : activeDecisionType,
    note: source === "MANUAL" ? "Saved note" : "",
    created_at: "2026-07-28T00:00:00Z",
    updated_at: "2026-07-28T00:00:00Z",
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
  count: 1,
  page: 1,
  page_size: 25,
  results: [
    {
      id: 1,
      cpe_name_id: cpeUuid,
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
      title: "curl",
      snapshot_id: snapshotId,
    },
  ],
}

const dictionaryDetail: CpeDictionaryDetail = {
  ...dictionaryResponse.results[0],
  snapshot_manifest_sha256: "d".repeat(64),
  deprecated_by: [],
  deprecates: [],
  created_at_nvd: "2020-01-01T00:00:00Z",
  last_modified_at_nvd: "2026-01-01T00:00:00Z",
  titles: [{ lang: "en", title: "curl" }],
  references: [],
}

function listRow(
  id: number,
  source: GroundTruthSource | null,
): GroundTruthComponentSummary {
  const detail = componentDetail(
    id,
    id === 101 ? "curl" : "openssl",
  )
  const groundTruth = source
    ? {
        ...groundTruthRecord(source),
        ...(source === "MANUAL"
          ? { decision_type: initialDecisionTypes[1] }
          : {}),
      }
    : null
  return {
    ...detail,
    ground_truth_status: source ? "COMPLETED" : "UNREVIEWED",
    ground_truth: groundTruth,
    decision_type: groundTruth?.decision_type ?? null,
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
  missingPurl?: boolean
  saveError?: boolean
  invalidManual?: boolean
  delayedSave?: boolean
  delayedList?: boolean
  emptyList?: boolean
  listError?: boolean
  createDecisionTypeError?: boolean
}

function installFetch(options: FetchOptions = {}) {
  let resolveSave: ((response: Response) => void) | undefined
  let decisionTypes = [
    ...initialDecisionTypes,
    inactiveDecisionType,
  ]
  vi.mocked(fetch).mockImplementation((input, init) => {
    const url = new URL(String(input), "http://frontend.test")
    if (
      url.pathname === "/api/ground-truth-decision-types/"
    ) {
      if (init?.method === "POST") {
        if (options.createDecisionTypeError) {
          return Promise.resolve(
            jsonResponse(
              { name: ["A Decision Type already exists."] },
              400,
            ),
          )
        }
        const payload = JSON.parse(String(init.body)) as {
          name: string
          description: string
        }
        const created: GroundTruthDecisionType = {
          id: 29,
          name: payload.name.trim(),
          description: payload.description.trim(),
          is_active: true,
          usage_count: 0,
        }
        decisionTypes = [...decisionTypes, created]
        return Promise.resolve(jsonResponse(created, 201))
      }
      const includeAll =
        url.searchParams.get("is_active") === "all"
      return Promise.resolve(
        jsonResponse(
          decisionTypes.filter(
            (decisionType) =>
              includeAll || decisionType.is_active,
          ),
        ),
      )
    }
    const decisionTypeMatch = url.pathname.match(
      /^\/api\/ground-truth-decision-types\/(\d+)\/$/,
    )
    if (decisionTypeMatch && init?.method === "PATCH") {
      const id = Number(decisionTypeMatch[1])
      const payload = JSON.parse(String(init.body)) as {
        is_active?: boolean
      }
      const existing = decisionTypes.find((item) => item.id === id)
      if (!existing) return Promise.resolve(jsonResponse({}, 404))
      const updated = { ...existing, ...payload }
      decisionTypes = decisionTypes.map((item) =>
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
            total_components: 2,
            components_with_primary_cpe: 2,
            components_without_primary_cpe: 0,
            primary_cpe_ratio: 1,
            unique_primary_cpes: 2,
          },
        ]),
      )
    }
    if (url.pathname === "/api/ground-truth/components/") {
      if (options.delayedList) {
        return new Promise<Response>(() => undefined)
      }
      if (options.listError) {
        return Promise.resolve(
          jsonResponse({ detail: "List unavailable" }, 500),
        )
      }
      return Promise.resolve(
        jsonResponse({
          count: options.emptyList ? 0 : 3,
          page: Number(url.searchParams.get("page") ?? 1),
          page_size: Number(
            url.searchParams.get("page_size") ?? 50,
          ),
          total_pages: 1,
          next: null,
          previous: null,
          results: options.emptyList
            ? []
            : [
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
        if (options.saveError || options.invalidManual) {
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
          decision_type_id: number
          note: string
        }
        const source: GroundTruthSource =
          payload.dictionary_cpe_id !== null
            ? "DICTIONARY"
            : payload.manual_cpe
              ? "MANUAL"
              : "NONE"
        const response = jsonResponse({
          component_id: id,
          snapshot_id: snapshotId,
          ground_truth: {
            ...groundTruthRecord(source),
            manual_cpe: payload.manual_cpe,
            decision_type:
              decisionTypes.find(
                (item) => item.id === payload.decision_type_id,
              ) ?? activeDecisionType,
            note: payload.note,
          },
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
            ? groundTruthRecord(options.restoredSource)
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
      return Promise.resolve(jsonResponse(dictionaryResponse.snapshot))
    }
    if (url.pathname === "/api/cpe-dictionary/") {
      return Promise.resolve(jsonResponse(dictionaryResponse))
    }
    if (
      url.pathname === `/api/cpe-dictionary/${cpeUuid}/`
    ) {
      return Promise.resolve(jsonResponse(dictionaryDetail))
    }
    return Promise.resolve(jsonResponse({}, 404))
  })
  return {
    resolveSave: () =>
      resolveSave?.(
        jsonResponse({
          component_id: 101,
          snapshot_id: snapshotId,
          ground_truth: {
            ...groundTruthRecord("NONE"),
            decision_type: activeDecisionType,
          },
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

async function selectDecisionType(
  user: ReturnType<typeof userEvent.setup>,
  name = activeDecisionType.name,
): Promise<void> {
  const combobox = screen.getByPlaceholderText(
    "Search or select a decision type...",
  )
  await user.click(combobox)
  await user.click(
    await screen.findByRole("option", { name }),
  )
}

describe("Ground Truth workflow", () => {
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

  it("adds the Ground Truth menu and renders the review list", async () => {
    installFetch()
    renderAppAt("/ground-truth")

    expect(
      screen.getByRole("link", { name: "Ground Truth" }),
    ).toHaveAttribute("href", "/ground-truth")
    expect(
      screen.getByRole("heading", { name: "Ground Truth" }),
    ).toBeInTheDocument()
    expect(
      screen.getByText("Independent human-authored CPE answers"),
    ).toBeInTheDocument()
    expect(screen.getByText("Review Components"))
      .toBeInTheDocument()
    expect(
      screen.getByText(
        "Review components with a Primary CPE and assign an independent expected CPE.",
      ),
    ).toBeInTheDocument()
    expect(
      await screen.findAllByText("Not Reviewed"),
    ).not.toHaveLength(0)
    expect(screen.getAllByText("Completed")).not.toHaveLength(0)
    expect(screen.getAllByText("Inactive")).not.toHaveLength(0)
    expect(
      screen.getByRole("columnheader", {
        name: "Ground Truth Status",
      }),
    ).toBeInTheDocument()
    const table = screen.getByRole("table", {
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
      "Exact Match",
      "Ground Truth Status",
      "Ground Truth",
      "Decision Type",
      "Action",
    ])
    expect(
      within(table).queryByRole("columnheader", {
        name: "Image",
      }),
    ).not.toBeInTheDocument()
    expect(
      within(table).queryByText(
        "docker.io/library/alpine:3.24.1",
      ),
    ).not.toBeInTheDocument()
    expect(screen.getByLabelText("Image")).toBeInTheDocument()
    expect(within(table).getByText("Not Assigned"))
      .toBeInTheDocument()
    expect(within(table).getByText("No CPE Assigned"))
      .toBeInTheDocument()
    expect(
      screen.getByRole("link", { name: "Review" }),
    ).toBeInTheDocument()
    expect(
      screen.getAllByRole("link", { name: "Edit" }),
    ).not.toHaveLength(0)
    expect(within(table).getByTitle(manualCpe))
      .toHaveTextContent(manualCpe)
    expect(
      within(table).getByTitle(initialDecisionTypes[1].name),
    ).toHaveTextContent(initialDecisionTypes[1].name)
  })

  it("renders list loading, empty, and error states in English", async () => {
    installFetch({ delayedList: true })
    const loadingView = renderAppAt("/ground-truth")
    expect(
      await screen.findByText("Loading review components…"),
    ).toBeInTheDocument()
    loadingView.unmount()

    installFetch({ emptyList: true })
    const emptyView = renderAppAt("/ground-truth")
    expect(
      await screen.findByText(
        "No components match the current filters.",
      ),
    ).toBeInTheDocument()
    emptyView.unmount()

    installFetch({ listError: true })
    renderAppAt("/ground-truth")
    expect(
      await screen.findByText(
        "Unable to load review components",
      ),
    ).toBeInTheDocument()
    expect(screen.getByText("List unavailable"))
      .toBeInTheDocument()
  })

  it("renders the search, filter, sort, and reset controls in English", async () => {
    installFetch()
    renderAppAt("/ground-truth")

    const keyword = await screen.findByLabelText(
      "Component Keyword",
    )
    const form = keyword.closest("form")
    if (!form) throw new Error("Ground Truth search form not found")

    expect(
      screen.getByText("Review Components"),
    ).toBeInTheDocument()
    expect(
      screen
        .getByText("Review Components")
        .closest('[data-slot="card-header"]'),
    ).not.toBeNull()
    expect(keyword).toHaveAttribute(
      "placeholder",
      "Search by name, version, publisher, PURL, or CPE",
    )
    expect(
      within(form).getByRole("button", { name: "Search" }),
    ).toBeInTheDocument()
    expect(within(form).getByLabelText("Image"))
      .toBeInTheDocument()
    expect(within(form).getByLabelText("Ground Truth Status"))
      .toBeInTheDocument()
    expect(within(form).getByLabelText("Exact Match"))
      .toBeInTheDocument()
    expect(within(form).getByLabelText("Sort"))
      .toBeInTheDocument()
    expect(
      within(form).getByRole("button", { name: "Reset" }),
    ).toBeDisabled()
    expect(
      within(form).getByRole("option", { name: "All Images" }),
    ).toBeInTheDocument()
    expect(
      within(form).getByRole("option", {
        name: "All Statuses",
      }),
    ).toBeInTheDocument()
    expect(
      within(form).getByRole("option", {
        name: "All Exact Match Results",
      }),
    ).toBeInTheDocument()
    expect(within(form).queryByText("검색")).not.toBeInTheDocument()
  })

  it("keeps list filters and pagination in URL state", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth")
    await screen.findAllByText("Not Reviewed")

    await user.selectOptions(
      screen.getByLabelText("Ground Truth Status"),
      "UNREVIEWED",
    )
    await user.selectOptions(
      screen.getByLabelText("Exact Match"),
      "NOT_IN_DICTIONARY",
    )
    await user.selectOptions(screen.getByLabelText("Image"), "1")
    await user.selectOptions(screen.getByLabelText("Sort"), "-id")
    await user.type(
      screen.getByLabelText("Component Keyword"),
      "curl",
    )
    const search = screen.getByRole("button", { name: "Search" })
    await waitFor(() => expect(search).toBeEnabled())
    await user.click(search)

    await waitFor(() => {
      const location =
        screen.getByTestId("route-location").textContent ?? ""
      const parameters = new URL(
        location,
        "http://frontend.test",
      ).searchParams
      expect(parameters.get("ground_truth_status")).toBe(
        "UNREVIEWED",
      )
      expect(parameters.get("dictionary_status")).toBe(
        "NOT_IN_DICTIONARY",
      )
      expect(parameters.get("image_id")).toBe("1")
      expect(parameters.get("search")).toBe("curl")
      expect(parameters.get("ordering")).toBe("-id")
      expect(parameters.get("page")).toBeNull()
    })
  })

  it("resets keyword, filters, sorting, pagination, and URL state", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt(
      "/ground-truth?image_id=1&ground_truth_status=COMPLETED&dictionary_status=OFFICIAL_ACTIVE&search=curl&ordering=-id&page=2&page_size=100",
    )

    expect(
      await screen.findByLabelText("Component Keyword"),
    ).toHaveValue("curl")
    expect(screen.getByLabelText("Image")).toHaveValue("1")
    expect(screen.getByLabelText("Ground Truth Status"))
      .toHaveValue("COMPLETED")
    expect(screen.getByLabelText("Exact Match"))
      .toHaveValue("OFFICIAL_ACTIVE")
    expect(screen.getByLabelText("Sort")).toHaveValue("-id")
    expect(screen.getByLabelText("Rows per page")).toHaveValue(
      "100",
    )

    const reset = screen.getByRole("button", { name: "Reset" })
    await waitFor(() => expect(reset).toBeEnabled())
    await user.click(reset)

    await waitFor(() => {
      expect(
        screen.getByTestId("route-location").textContent,
      ).toBe("/ground-truth")
    })
    expect(screen.getByLabelText("Component Keyword")).toHaveValue(
      "",
    )
    expect(screen.getByLabelText("Image")).toHaveValue("")
    expect(screen.getByLabelText("Ground Truth Status")).toHaveValue(
      "",
    )
    expect(screen.getByLabelText("Exact Match")).toHaveValue("")
    expect(screen.getByLabelText("Sort")).toHaveValue("id")
    expect(screen.getByLabelText("Rows per page")).toHaveValue(
      "50",
    )
    await waitFor(() => expect(reset).toBeDisabled())
  })

  it("does not request the list again when Reset is disabled", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth")
    await screen.findByText("curl")

    const listRequestCount = () =>
      vi.mocked(fetch).mock.calls.filter(([input]) => {
        const url = new URL(
          String(input),
          "http://frontend.test",
        )
        return url.pathname === "/api/ground-truth/components/"
      }).length
    const beforeReset = listRequestCount()
    const reset = screen.getByRole("button", { name: "Reset" })
    expect(reset).toBeDisabled()
    await user.click(reset)
    expect(listRequestCount()).toBe(beforeReset)
  })

  it("restores list query state and carries it into the editor", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt(
      "/ground-truth?ground_truth_status=COMPLETED&search=curl",
    )

    expect(
      await screen.findByLabelText("Ground Truth Status"),
    ).toHaveValue("COMPLETED")
    expect(screen.getByLabelText("Component Keyword")).toHaveValue(
      "curl",
    )
    await user.click(
      screen.getAllByRole("link", {
        name: "Review",
      })[0],
    )

    expect(
      await screen.findByRole("heading", {
        name: "Ground Truth Review",
      }),
    ).toBeInTheDocument()
    const location =
      screen.getByTestId("route-location").textContent ?? ""
    expect(location).toContain("/ground-truth/components/101")
    expect(decodeURIComponent(location)).toContain(
      "ground_truth_status=COMPLETED",
    )
  })

  it("shows Component evidence without ranking or score output", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")

    expect(
      await screen.findByText("Component context"),
    ).toBeInTheDocument()
    expect(screen.getByText("Daniel Stenberg")).toBeInTheDocument()
    expect(screen.getByText("apk-db-cataloger"))
      .toBeInTheDocument()
    expect(screen.getByText("Exact Match")).toBeInTheDocument()
    expect(
      screen.queryByText("CPE Dictionary Snapshot"),
    ).not.toBeInTheDocument()
    expect(screen.queryByText(/Manifest SHA-256:/))
      .not.toBeInTheDocument()
    expect(
      await screen.findByText(new RegExp(`Snapshot: ${snapshotId}`)),
    ).toBeInTheDocument()
    expect(
      screen.getByText("Search Official CPE Names"),
    ).toBeInTheDocument()
    const context = componentContext()
    const metadataGrid = within(context).getByTestId(
      "component-context-metadata-grid",
    )
    expect(
      Array.from(metadataGrid.querySelectorAll("dt")).map(
        (label) => label.textContent,
      ),
    ).toEqual([
      "Name",
      "Version",
      "Group",
      "Publisher",
      "Type",
      "Docker image",
      "SBOM document",
      "Exact Match",
      "Primary CPE",
      "PURL",
    ])
    const purl = within(context).getByText(componentPurl)
    expect(purl).toHaveClass(
      "min-w-0",
      "max-w-full",
      "whitespace-normal",
      "break-all",
    )
    expect(purl).not.toHaveClass(
      "truncate",
      "whitespace-nowrap",
    )
    expect(
      within(context).queryByRole("button", {
        name: "Copy PURL",
      }),
    ).not.toBeInTheDocument()
    const primaryCpe = within(metadataGrid).getByText(cpeName)
    expect(primaryCpe).toHaveClass(
      "min-w-0",
      "max-w-full",
      "whitespace-normal",
      "break-all",
    )
    expect(primaryCpe).not.toHaveClass(
      "truncate",
      "whitespace-nowrap",
    )
    for (const metadata of [
      "curl",
      "8.14.1-r1",
      "alpine",
      "Daniel Stenberg",
      "docker.io/library/alpine:3.24.1",
      "11 · pilot/results/sboms/alpine-3.24.1.cdx.json",
    ]) {
      expect(within(context).getByText(metadata))
        .toBeInTheDocument()
    }
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
    expect(
      screen.getByRole("link", {
        name: "Back to Review Queue",
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("button", { name: "Previous" }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("button", { name: "Next" }),
    ).toBeInTheDocument()
    expect(screen.queryByText(/BM25|BM25F|fuzzy|rerank/i))
      .not.toBeInTheDocument()
  })

  it("shows Not provided when Component PURL is absent", async () => {
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

  for (const source of [
    "DICTIONARY",
    "MANUAL",
    "NONE",
  ] as const) {
    it(`restores ${source} Ground Truth without translating stored values`, async () => {
      installFetch({ restoredSource: source })
      renderAppAt("/ground-truth/components/101")
      const editor = groundTruthEditor()

      await within(editor).findByText(
        source === "NONE"
          ? "Archived English review"
          : "Official CPE confirmed",
      )
      if (source === "NONE") {
        expect(within(editor).getByText("Inactive"))
          .toBeInTheDocument()
      }
      if (source === "DICTIONARY") {
        expect(within(editor).getByText(`UUID: ${cpeUuid}`))
          .toBeInTheDocument()
      } else if (source === "MANUAL") {
        expect(
          within(editor).getByDisplayValue(manualCpe),
        ).toBeInTheDocument()
        expect(
          within(editor).getByText("Add Note · Saved note", {
            selector: "summary",
          }),
        ).toBeInTheDocument()
      } else {
        expect(
          within(editor).getByText(
            "No Dictionary CPE selected",
          ),
        ).toBeInTheDocument()
      }
    })
  }

  it("selects, clears, and copies a Dictionary CPE to manual input", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101?q=curl")
    await screen.findByText("1 result")
    await screen.findByText("No Dictionary CPE selected")

    await user.click(
      screen.getByRole("button", {
        name: "Select as Ground Truth",
      }),
    )
    let editor = groundTruthEditor()
    expect(within(editor).getByText(`UUID: ${cpeUuid}`))
      .toBeInTheDocument()
    expect(putRequests()).toHaveLength(0)

    await user.click(
      within(editor).getByRole("button", {
        name: "Copy to Manual CPE",
      }),
    )
    expect(
      within(editor).getByDisplayValue(cpeName),
    ).toBeInTheDocument()
    expect(
      within(editor).getByText("No Dictionary CPE selected"),
    ).toBeInTheDocument()

    await user.clear(within(editor).getByDisplayValue(cpeName))
    await user.click(
      screen.getByRole("button", {
        name: "Select as Ground Truth",
      }),
    )
    editor = groundTruthEditor()
    await user.click(
      within(editor).getByRole("button", {
        name: "Remove Selection",
      }),
    )
    expect(
      within(editor).getByText("No Dictionary CPE selected"),
    ).toBeInTheDocument()
  })

  it("keeps all Raw CPE detail actions inside a wrapping group", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101?q=curl")
    await screen.findByText("1 result")
    await user.click(
      screen.getByRole("button", { name: "View details" }),
    )
    const dialog = await screen.findByRole("dialog", {
      name: "CPE Dictionary record",
    })
    const actions = within(dialog).getByTestId("raw-cpe-actions")

    expect(actions).toHaveClass("flex-wrap")
    expect(actions).toHaveClass("max-w-full")
    for (const name of [
      "Select as Ground Truth",
      "Copy to Manual CPE",
      "Copy raw CPE",
      "Copy CPE UUID",
    ]) {
      expect(
        within(dialog).getByRole("button", { name }),
      ).toBeInTheDocument()
    }
    const rawCpe = within(dialog).getByText(cpeName)
    expect(rawCpe).toHaveClass("break-all")
    expect(rawCpe).toHaveClass("max-w-full")

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
    await user.click(
      within(dialog).getByRole("button", {
        name: "Copy to Manual CPE",
      }),
    )
    expect(
      within(groundTruthEditor()).getByDisplayValue(cpeName),
    ).toBeInTheDocument()
    await user.click(
      within(dialog).getByRole("button", {
        name: "Select as Ground Truth",
      }),
    )
    expect(
      within(groundTruthEditor()).getByText(`UUID: ${cpeUuid}`),
    ).toBeInTheDocument()
  })

  it("searches and replaces a single Decision Type selection", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    const combobox = within(editor).getByRole("combobox", {
      name: "Decision Type",
    })

    await user.click(combobox)
    await screen.findByRole("option", {
      name: "Official CPE confirmed",
    })
    const initialOptionNames = within(
      screen.getByRole("listbox"),
    )
      .getAllByRole("option")
      .map((option) => option.textContent?.trim() ?? "")
    expect(initialOptionNames).toHaveLength(7)
    expect(initialOptionNames).toEqual(
      expect.arrayContaining(
        initialDecisionTypes.map(
          (decisionType) => decisionType.name,
        ),
      ),
    )
    expect(
      initialOptionNames.some((name) =>
        /[\u1100-\u11ff\u3130-\u318f\ua960-\ua97f\uac00-\ud7ff\uffa0-\uffdc]/u.test(
          name,
        ),
      ),
    ).toBe(false)
    await user.keyboard("{Escape}")

    await user.type(combobox, "Official CPE confirmed")
    await user.keyboard("{Enter}")
    expect(within(editor).getByText("Official CPE confirmed"))
      .toBeInTheDocument()

    await user.click(combobox)
    await user.clear(combobox)
    await user.type(combobox, "version not")
    await user.keyboard("{Enter}")
    expect(
      within(editor).getByText(
        "Official CPE family confirmed; version not in Dictionary",
      ),
    ).toBeInTheDocument()
    expect(
      within(editor).queryByText("Official CPE confirmed"),
    ).not.toBeInTheDocument()

    await user.click(
      within(editor).getByRole("button", {
        name: "Clear Decision Type",
      }),
    )
    expect(
      within(editor).queryByText(
        "Official CPE family confirmed; version not in Dictionary",
      ),
    ).not.toBeInTheDocument()
    await user.click(combobox)
    expect(
      screen.queryByRole("option", {
        name: "Archived English review",
      }),
    ).not.toBeInTheDocument()
    await user.keyboard("{Escape}")
  })

  it("closes the Decision Type dropdown without changing the form state", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    const manual = within(editor).getByPlaceholderText(
      /cpe:2\.3:a:vendor/,
    )
    const combobox = within(editor).getByRole("combobox", {
      name: "Decision Type",
    })
    await user.type(manual, manualCpe)

    await user.click(combobox)
    expect(combobox).toHaveAttribute("aria-expanded", "true")
    expect(screen.getByRole("listbox")).toBeInTheDocument()
    await user.click(
      within(editor).getByText("Expected Ground Truth CPE"),
    )
    expect(combobox).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument()
    expect(manual).toHaveValue(manualCpe)

    await user.click(combobox)
    expect(combobox).toHaveAttribute("aria-expanded", "true")
    await user.click(combobox)
    expect(combobox).toHaveAttribute("aria-expanded", "false")

    await user.click(combobox)
    await user.click(
      await screen.findByRole("option", {
        name: "Official CPE confirmed",
      }),
    )
    expect(combobox).toHaveAttribute("aria-expanded", "false")
    expect(within(editor).getByText("Official CPE confirmed"))
      .toBeInTheDocument()

    await user.click(combobox)
    await user.keyboard("{Escape}")
    expect(combobox).toHaveAttribute("aria-expanded", "false")
    expect(within(editor).getByText("Official CPE confirmed"))
      .toBeInTheDocument()
    expect(manual).toHaveValue(manualCpe)

    await user.type(combobox, "New outside-click type")
    await user.click(
      await screen.findByRole("option", {
        name: "Create “New outside-click type”",
      }),
    )
    expect(combobox).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument()
    const dialog = screen.getByRole("dialog", {
      name: "Add Decision Type",
    })
    await user.click(
      within(dialog).getByRole("button", { name: "Cancel" }),
    )
    expect(within(editor).getByText("Official CPE confirmed"))
      .toBeInTheDocument()
    expect(manual).toHaveValue(manualCpe)

    await user.click(
      within(editor).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )
    expect(
      await within(editor).findByText("Ground Truth saved."),
    ).toBeInTheDocument()
    expect(putRequests()).toHaveLength(1)
  })

  it("creates a Decision Type and selects it without saving Ground Truth", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    const combobox = await within(editor).findByRole(
      "combobox",
      { name: "Decision Type" },
    )

    await user.type(combobox, "New evidence type")
    await user.click(
      await screen.findByRole("option", {
        name: "Create “New evidence type”",
      }),
    )
    const dialog = screen.getByRole("dialog", {
      name: "Add Decision Type",
    })
    const nameInput = within(dialog).getByLabelText("Name")
    expect(nameInput).toHaveValue(
      "New evidence type",
    )
    await user.clear(nameInput)
    await user.click(
      within(dialog).getByRole("button", { name: "Create" }),
    )
    expect(
      within(dialog).getByText("Name is required."),
    ).toBeInTheDocument()
    await user.type(nameInput, "New evidence type")
    await user.type(
      within(dialog).getByLabelText("Description"),
      "Evidence description",
    )
    await user.click(
      within(dialog).getByRole("button", { name: "Create" }),
    )

    expect(
      await within(editor).findByText("New evidence type"),
    ).toBeInTheDocument()
    expect(putRequests()).toHaveLength(0)
  })

  it("preserves Decision Type create input after a duplicate error", async () => {
    const user = userEvent.setup()
    installFetch({ createDecisionTypeError: true })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    const combobox = await within(editor).findByRole(
      "combobox",
      { name: "Decision Type" },
    )

    await user.type(combobox, "Duplicate evidence")
    await user.click(
      await screen.findByRole("option", {
        name: "Create “Duplicate evidence”",
      }),
    )
    const dialog = screen.getByRole("dialog", {
      name: "Add Decision Type",
    })
    await user.click(
      within(dialog).getByRole("button", { name: "Create" }),
    )

    expect(
      await within(dialog).findByText(
        /Decision Type already exists/,
      ),
    ).toBeInTheDocument()
    expect(within(dialog).getByLabelText("Name")).toHaveValue(
      "Duplicate evidence",
    )
  })

  it("rejects Hangul in Decision Type names and descriptions before requesting", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    const combobox = await within(editor).findByRole(
      "combobox",
      { name: "Decision Type" },
    )

    await user.type(combobox, "New English type")
    await user.click(
      await screen.findByRole("option", {
        name: "Create “New English type”",
      }),
    )
    const dialog = screen.getByRole("dialog", {
      name: "Add Decision Type",
    })
    const name = within(dialog).getByLabelText("Name")
    const description =
      within(dialog).getByLabelText("Description")
    await user.clear(name)
    await user.type(name, "한국어 유형")
    await user.click(
      within(dialog).getByRole("button", { name: "Create" }),
    )
    expect(
      within(dialog).getByText(
        "Decision Type names must be written in English.",
      ),
    ).toBeInTheDocument()

    await user.clear(name)
    await user.type(name, "New English type")
    await user.type(description, "한국어 설명")
    await user.click(
      within(dialog).getByRole("button", { name: "Create" }),
    )
    expect(
      within(dialog).getByText(
        "Decision Type descriptions must be written in English.",
      ),
    ).toBeInTheDocument()
    expect(postRequests()).toHaveLength(0)
  })

  it("deactivates and reactivates Decision Types without delete actions", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByRole("combobox", {
      name: "Decision Type",
    })
    await selectDecisionType(user)
    await user.click(
      within(editor).getByRole("button", {
        name: "Manage Decision Types",
      }),
    )
    const manageDialog = await screen.findByRole("dialog", {
      name: "Manage Decision Types",
    })
    expect(within(manageDialog).getByText("Active"))
      .toBeInTheDocument()
    expect(within(manageDialog).getByText("Inactive"))
      .toBeInTheDocument()
    expect(within(manageDialog).queryByText("Delete"))
      .not.toBeInTheDocument()
    expect(manageDialog.textContent).not.toMatch(
      /[\u1100-\u11ff\u3130-\u318f\ua960-\ua97f\uac00-\ud7ff\uffa0-\uffdc]/u,
    )
    const activeRow = within(manageDialog)
      .getByText("Official CPE confirmed")
      .closest(".rounded-lg.border")
    if (!activeRow) throw new Error("Active Decision Type row missing")
    await user.click(
      within(activeRow as HTMLElement).getByRole("button", {
        name: "Deactivate",
      }),
    )
    const confirmation = screen.getByRole("dialog", {
      name: "Deactivate Decision Type?",
    })
    await user.click(
      within(confirmation).getByRole("button", {
        name: "Deactivate",
      }),
    )

    const selectedValue = within(editor)
      .getByRole("button", { name: "Clear Decision Type" })
      .closest(".rounded-lg.border")
    if (!selectedValue) {
      throw new Error("Selected Decision Type container missing")
    }
    expect(within(selectedValue as HTMLElement).getByText("Inactive"))
      .toBeInTheDocument()
    const inactiveRow = within(manageDialog)
      .getByText("Official CPE confirmed")
      .closest(".rounded-lg.border")
    if (!inactiveRow) {
      throw new Error("Inactive Decision Type row missing")
    }
    await user.click(
      within(inactiveRow as HTMLElement).getByRole("button", {
        name: "Reactivate",
      }),
    )
    await waitFor(() =>
      expect(
        within(manageDialog).getAllByRole("button", {
          name: "Deactivate",
        }).length,
      ).toBeGreaterThan(0),
    )
  })

  it("shows server validation for invalid manual CPE and preserves input", async () => {
    const user = userEvent.setup()
    installFetch({ invalidManual: true })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    const manual = within(editor).getByPlaceholderText(
      /cpe:2\.3:a:vendor/,
    )
    await user.type(manual, "invalid")
    await selectDecisionType(user)
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

  it("requires decision type and keeps note collapsed by default", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    const noteSummary = within(editor).getByText("Add Note")
    expect(noteSummary.closest("details")).not.toHaveAttribute(
      "open",
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )
    expect(
      within(editor).getByText("Decision Type is required."),
    ).toBeInTheDocument()
    expect(putRequests()).toHaveLength(0)
  })

  it("saves no-CPE, manual, and Dictionary payloads explicitly", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt("/ground-truth/components/101?q=curl")
    await screen.findByText("1 result")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    expect(
      within(editor).queryByPlaceholderText(
        "Enter a free-form decision type",
      ),
    ).not.toBeInTheDocument()
    await selectDecisionType(user)
    await user.click(
      within(editor).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )
    expect(
      await within(editor).findByText(
        "Ground Truth saved.",
      ),
    ).toBeInTheDocument()
    expect(
      JSON.parse(String(putRequests()[0][1]?.body)),
    ).toMatchObject({
      dictionary_cpe_id: null,
      manual_cpe: null,
      decision_type_id: activeDecisionType.id,
    })

    await user.type(
      within(editor).getByPlaceholderText(/cpe:2\.3:a:vendor/),
      manualCpe,
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )
    await waitFor(() => expect(putRequests()).toHaveLength(2))
    expect(
      JSON.parse(String(putRequests()[1][1]?.body)),
    ).toMatchObject({
      dictionary_cpe_id: null,
      manual_cpe: manualCpe,
    })

    await user.clear(
      within(editor).getByDisplayValue(manualCpe),
    )
    await user.click(
      screen.getByRole("button", {
        name: "Select as Ground Truth",
      }),
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )
    await waitFor(() => expect(putRequests()).toHaveLength(3))
    expect(
      JSON.parse(String(putRequests()[2][1]?.body)),
    ).toMatchObject({
      dictionary_cpe_id: 1,
      manual_cpe: null,
    })
  })

  it("prevents duplicate save clicks while a request is pending", async () => {
    const user = userEvent.setup()
    const controls = installFetch({ delayedSave: true })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    await selectDecisionType(user)
    const save = within(editor).getByRole("button", {
      name: "Save Ground Truth",
    })
    await user.click(save)
    expect(save).toBeDisabled()
    await user.click(save)
    expect(putRequests()).toHaveLength(1)

    await act(async () => controls.resolveSave())
    expect(
      await within(editor).findByText("Saved"),
    ).toBeInTheDocument()
  })

  it("preserves inputs after a failed save", async () => {
    const user = userEvent.setup()
    installFetch({ saveError: true })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    await selectDecisionType(user)
    await user.click(
      within(editor).getByRole("button", {
        name: "Save Ground Truth",
      }),
    )

    expect(
      await within(editor).findByText(/Save rejected/),
    ).toBeInTheDocument()
    expect(within(editor).getByText("Official CPE confirmed"))
      .toBeInTheDocument()
  })

  it("saves and moves to the next filtered Component", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt(
      "/ground-truth/components/101?queue=ground_truth_status%3DUNREVIEWED",
    )
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    await selectDecisionType(user)
    await user.click(
      within(editor).getByRole("button", {
        name: "Save and Next",
      }),
    )

    await waitFor(() =>
      expect(
        screen.getByTestId("route-location").textContent,
      ).toContain("/ground-truth/components/102"),
    )
    expect(
      screen.getByTestId("route-location").textContent,
    ).toContain("queue=ground_truth_status%3DUNREVIEWED")
  })

  it("guards unsaved navigation and reloads state for a new Component", async () => {
    const user = userEvent.setup()
    installFetch()
    const { router } = renderAppWithHistory([
      "/ground-truth/components/101",
    ])
    let editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    await selectDecisionType(user, "No independent CPE")
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
    editor = groundTruthEditor()
    await within(editor).findByText(
      "No Dictionary CPE selected",
    )
    expect(
      within(editor).queryByText("No independent CPE"),
    ).not.toBeInTheDocument()
  })
})
