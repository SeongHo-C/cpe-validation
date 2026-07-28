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
    purl: `pkg:apk/alpine/${name}@8.14.1-r1`,
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
      source === "NONE" ? "직접 대응 CPE 없음" : "Version review",
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
  return {
    ...detail,
    ground_truth_status: source ? "COMPLETED" : "UNREVIEWED",
    ground_truth: source ? groundTruthRecord(source) : null,
    decision_type: source
      ? groundTruthRecord(source).decision_type
      : null,
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
  saveError?: boolean
  invalidManual?: boolean
  delayedSave?: boolean
}

function installFetch(options: FetchOptions = {}) {
  let resolveSave: ((response: Response) => void) | undefined
  vi.mocked(fetch).mockImplementation((input, init) => {
    const url = new URL(String(input), "http://frontend.test")
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
      return Promise.resolve(
        jsonResponse({
          count: 2,
          page: Number(url.searchParams.get("page") ?? 1),
          page_size: Number(
            url.searchParams.get("page_size") ?? 50,
          ),
          total_pages: 1,
          next: null,
          previous: null,
          results: [listRow(101, null), listRow(102, "MANUAL")],
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
          decision_type: string
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
            decision_type: payload.decision_type.trim(),
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
      return Promise.resolve(
        jsonResponse(
          componentDetail(id, id === 101 ? "curl" : "openssl"),
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
          ground_truth: groundTruthRecord("NONE"),
        }),
      ),
  }
}

function groundTruthEditor(): HTMLElement {
  const title = screen.getByText("예상 Ground Truth", {
    selector: "[data-slot='card-title']",
  })
  const card = title.closest("[data-slot='card']")
  if (!card) throw new Error("Ground Truth editor not found")
  return card as HTMLElement
}

function putRequests() {
  return vi.mocked(fetch).mock.calls.filter(([, init]) => {
    return init?.method === "PUT"
  })
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
    expect(await screen.findAllByText("미작성")).not.toHaveLength(0)
    expect(screen.getAllByText("작성 완료")).not.toHaveLength(0)
    expect(screen.getByTitle(manualCpe)).toBeInTheDocument()
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
    await screen.findAllByText("미작성")

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
        name: "Ground Truth 작성",
      })[0],
    )

    expect(
      await screen.findByRole("heading", {
        name: "Ground Truth 작성",
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
    installFetch()
    renderAppAt("/ground-truth/components/101")

    expect(
      await screen.findByText("Component context"),
    ).toBeInTheDocument()
    expect(screen.getByText("Daniel Stenberg")).toBeInTheDocument()
    expect(screen.getByText("apk-db-cataloger"))
      .toBeInTheDocument()
    expect(screen.getByText("Exact Match")).toBeInTheDocument()
    expect(screen.queryByText(/BM25|ranking|score/i))
      .not.toBeInTheDocument()
  })

  for (const source of [
    "DICTIONARY",
    "MANUAL",
    "NONE",
  ] as const) {
    it(`restores ${source} Ground Truth`, async () => {
      installFetch({ restoredSource: source })
      renderAppAt("/ground-truth/components/101")
      const editor = groundTruthEditor()

      await within(editor).findByDisplayValue(
        source === "NONE"
          ? "직접 대응 CPE 없음"
          : "Version review",
      )
      if (source === "DICTIONARY") {
        expect(within(editor).getByText(`UUID: ${cpeUuid}`))
          .toBeInTheDocument()
      } else if (source === "MANUAL") {
        expect(
          within(editor).getByDisplayValue(manualCpe),
        ).toBeInTheDocument()
        expect(
          within(editor).getByText(/저장된 메모 있음/),
        ).toBeInTheDocument()
      } else {
        expect(
          within(editor).getByText(
            "선택된 Dictionary CPE 없음",
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
    await screen.findByText("선택된 Dictionary CPE 없음")

    await user.click(
      screen.getByRole("button", {
        name: "Ground Truth로 선택",
      }),
    )
    let editor = groundTruthEditor()
    expect(within(editor).getByText(`UUID: ${cpeUuid}`))
      .toBeInTheDocument()
    expect(putRequests()).toHaveLength(0)

    await user.click(
      within(editor).getByRole("button", {
        name: "수동 CPE로 복사",
      }),
    )
    expect(
      within(editor).getByDisplayValue(cpeName),
    ).toBeInTheDocument()
    expect(
      within(editor).getByText("선택된 Dictionary CPE 없음"),
    ).toBeInTheDocument()

    await user.clear(within(editor).getByDisplayValue(cpeName))
    await user.click(
      screen.getByRole("button", {
        name: "Ground Truth로 선택",
      }),
    )
    editor = groundTruthEditor()
    await user.click(
      within(editor).getByRole("button", {
        name: "CPE 선택 해제",
      }),
    )
    expect(
      within(editor).getByText("선택된 Dictionary CPE 없음"),
    ).toBeInTheDocument()
  })

  it("shows server validation for invalid manual CPE and preserves input", async () => {
    const user = userEvent.setup()
    installFetch({ invalidManual: true })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "선택된 Dictionary CPE 없음",
    )
    const manual = within(editor).getByPlaceholderText(
      /cpe:2\.3:a:vendor/,
    )
    await user.type(manual, "invalid")
    await user.type(
      within(editor).getByPlaceholderText(
        "판정 유형을 자유롭게 입력",
      ),
      "Manual review",
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "검토 결과 저장",
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
      "선택된 Dictionary CPE 없음",
    )
    const noteSummary = within(editor).getByText("메모 추가")
    expect(noteSummary.closest("details")).not.toHaveAttribute(
      "open",
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "검토 결과 저장",
      }),
    )
    expect(
      within(editor).getByText("판정 유형은 필수 입력입니다."),
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
      "선택된 Dictionary CPE 없음",
    )
    const decision = within(editor).getByPlaceholderText(
      "판정 유형을 자유롭게 입력",
    )
    await user.type(decision, "No CPE")
    await user.click(
      within(editor).getByRole("button", {
        name: "검토 결과 저장",
      }),
    )
    expect(
      await within(editor).findByText(
        "검토 결과가 저장되었습니다.",
      ),
    ).toBeInTheDocument()
    expect(
      JSON.parse(String(putRequests()[0][1]?.body)),
    ).toMatchObject({
      dictionary_cpe_id: null,
      manual_cpe: null,
    })

    await user.type(
      within(editor).getByPlaceholderText(/cpe:2\.3:a:vendor/),
      manualCpe,
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "검토 결과 저장",
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
        name: "Ground Truth로 선택",
      }),
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "검토 결과 저장",
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
      "선택된 Dictionary CPE 없음",
    )
    await user.type(
      within(editor).getByPlaceholderText(
        "판정 유형을 자유롭게 입력",
      ),
      "Pending save",
    )
    const save = within(editor).getByRole("button", {
      name: "검토 결과 저장",
    })
    await user.click(save)
    expect(save).toBeDisabled()
    await user.click(save)
    expect(putRequests()).toHaveLength(1)

    await act(async () => controls.resolveSave())
    expect(
      await within(editor).findByText("저장 완료"),
    ).toBeInTheDocument()
  })

  it("preserves inputs after a failed save", async () => {
    const user = userEvent.setup()
    installFetch({ saveError: true })
    renderAppAt("/ground-truth/components/101")
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "선택된 Dictionary CPE 없음",
    )
    const decision = within(editor).getByPlaceholderText(
      "판정 유형을 자유롭게 입력",
    )
    await user.type(decision, "Keep this value")
    await user.click(
      within(editor).getByRole("button", {
        name: "검토 결과 저장",
      }),
    )

    expect(
      await within(editor).findByText(/Save rejected/),
    ).toBeInTheDocument()
    expect(decision).toHaveValue("Keep this value")
  })

  it("saves and moves to the next filtered Component", async () => {
    const user = userEvent.setup()
    installFetch()
    renderAppAt(
      "/ground-truth/components/101?queue=ground_truth_status%3DUNREVIEWED",
    )
    const editor = groundTruthEditor()
    await within(editor).findByText(
      "선택된 Dictionary CPE 없음",
    )
    await user.type(
      within(editor).getByPlaceholderText(
        "판정 유형을 자유롭게 입력",
      ),
      "Complete and continue",
    )
    await user.click(
      within(editor).getByRole("button", {
        name: "저장 후 다음",
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
      "선택된 Dictionary CPE 없음",
    )
    await user.type(
      within(editor).getByPlaceholderText(
        "판정 유형을 자유롭게 입력",
      ),
      "Unsaved",
    )
    vi.mocked(confirm).mockReturnValueOnce(false)
    await user.click(
      screen.getByRole("button", { name: "다음" }),
    )
    expect(
      screen.getByTestId("route-location").textContent,
    ).toContain("/101")

    await act(async () => {
      await router.navigate("/ground-truth/components/102")
    })
    editor = groundTruthEditor()
    await within(editor).findByText(
      "선택된 Dictionary CPE 없음",
    )
    expect(
      within(editor).getByPlaceholderText(
        "판정 유형을 자유롭게 입력",
      ),
    ).toHaveValue("")
  })
})
