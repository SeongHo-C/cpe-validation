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
  ComponentDetail,
  ComponentSummary,
  DockerImageDetail,
  PaginatedResponse,
} from "@/features/components/components-types"
import { renderAppAt } from "@/test/render-app"

const componentSummary: ComponentSummary = {
  id: 101,
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

const componentDetail: ComponentDetail = {
  ...componentSummary,
  image: null,
  bom_ref: "pkg:apk/alpine/curl@8.14.1-r1?package-id=abc",
  properties: [
    {
      name: "syft:cpe23",
      value: componentSummary.cpe,
    },
    {
      name: "syft:package:foundBy",
      value: "apk-db-cataloger",
    },
    {
      name: "syft:cpe23",
      value: "cpe:2.3:a:curl:curl:8.14.1:*:*:*:*:*:*:*",
    },
    {
      name: "syft:location:0:path",
      value: "/lib/apk/db/installed",
    },
    {
      name: "EMBA:sbom:source_location:1:source_path",
      value: "/firmware/rootfs/usr/bin/curl",
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
  dictionary_status: "OFFICIAL_ACTIVE",
  dictionary_match: {
    snapshot_id: "20260725T035002Z",
    cpe_name_id: "11111111-1111-4111-8111-111111111111",
    matched_cpe_name: componentSummary.cpe,
    deprecated: false,
  },
}

const imageDetail: DockerImageDetail = {
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

function jsonResponse<T>(body: T, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function paginatedResponse(
  url: URL,
): PaginatedResponse<ComponentSummary> {
  const page = Number(url.searchParams.get("page") ?? "1")
  const pageSize = Number(
    url.searchParams.get("page_size") ?? "50",
  )
  return {
    count: 60,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(60 / pageSize),
    next: page < Math.ceil(60 / pageSize) ? "next" : null,
    previous: page > 1 ? "previous" : null,
    results: [componentSummary],
  }
}

function installSuccessfulFetch(
  detail: ComponentDetail = componentDetail,
) {
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
        jsonResponse(paginatedResponse(url)),
      )
    }
    if (url.pathname === "/api/components/101/") {
      return Promise.resolve(jsonResponse(detail))
    }
    if (url.pathname === "/api/components/102/") {
      return Promise.resolve(jsonResponse(detail))
    }
    return Promise.resolve(jsonResponse({}, 404))
  })
}

function listRequestCount(): number {
  return vi
    .mocked(fetch)
    .mock.calls.filter(([input]) => {
      const url = new URL(
        String(input),
        "http://frontend.test",
      )
      return url.pathname === "/api/components/"
    }).length
}

function detailRequestCount(): number {
  return vi
    .mocked(fetch)
    .mock.calls.filter(([input]) => {
      const url = new URL(
        String(input),
        "http://frontend.test",
      )
      return /^\/api\/components\/\d+\/$/.test(url.pathname)
    }).length
}

function selectedRow(): HTMLElement {
  return screen.getByRole("button", {
    name: "Inspect component curl 8.14.1-r1",
  })
}

async function waitForDetail() {
  return screen.findByRole("heading", { name: "curl" })
}

function currentParameters(): URLSearchParams {
  const location =
    screen.getByTestId("route-location").textContent ?? ""
  return new URL(location, "http://frontend.test").searchParams
}

describe("Component Detail panel", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("uses a desktop shell without mobile navigation UI", async () => {
    installSuccessfulFetch()
    renderAppAt("/components")
    await screen.findByText("curl")

    const sidebar = screen.getByRole("complementary", {
      name: "",
    })
    expect(sidebar).not.toHaveClass("hidden")
    expect(
      screen.queryByRole("button", {
        name: "Open navigation menu",
      }),
    ).not.toBeInTheDocument()
    expect(
      document.querySelector('[data-slot="sheet"]'),
    ).not.toBeInTheDocument()
  })

  it("shows an instructional panel when no Component is selected", async () => {
    installSuccessfulFetch()
    renderAppAt("/components")

    expect(
      await screen.findByText("Select a component"),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        "Choose a row to inspect its metadata and CPE evidence.",
      ),
    ).toBeInTheDocument()
  })

  it("preserves every list query when a row is clicked", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt(
      "/components?image_id=1&search=curl&ordering=-version&page=2&page_size=25",
    )
    await screen.findByText("Page 2 of 3")

    await user.click(selectedRow())
    await waitForDetail()

    const parameters = currentParameters()
    expect(parameters.get("image_id")).toBe("1")
    expect(parameters.get("search")).toBe("curl")
    expect(parameters.get("ordering")).toBe("-version")
    expect(parameters.get("page")).toBe("2")
    expect(parameters.get("page_size")).toBe("25")
    expect(parameters.get("component_id")).toBe("101")
    expect(selectedRow()).toHaveAttribute("aria-pressed", "true")
  })

  it.each([
    ["Enter", "{Enter}"],
    ["Space", " "],
  ])("selects a Component with %s", async (_name, key) => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/components")
    await screen.findByText("curl")

    selectedRow().focus()
    await user.keyboard(key)

    await waitForDetail()
    expect(currentParameters().get("component_id")).toBe("101")
  })

  it("requests the trailing-slash Detail API independently", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/components")
    await screen.findByText("curl")
    const initialListRequests = listRequestCount()

    await user.click(selectedRow())
    await waitForDetail()

    expect(
      vi
        .mocked(fetch)
        .mock.calls.some(
          ([input]) => String(input) === "/api/components/101/",
        ),
    ).toBe(true)
    expect(listRequestCount()).toBe(initialListRequests)
  })

  it("renders component evidence while hiding SBOM provenance", async () => {
    installSuccessfulFetch()
    renderAppAt("/components?component_id=101")
    await waitForDetail()

    const panel = screen.getByRole("complementary", {
      name: "Component details",
    })
    expect(within(panel).queryByText("Read only")).not.toBeInTheDocument()
    expect(
      within(panel).queryByText("No Docker image"),
    ).not.toBeInTheDocument()
    expect(
      within(panel).getAllByText(componentDetail.version),
    ).toHaveLength(1)
    expect(within(panel).getAllByText("library")).toHaveLength(1)
    expect(
      within(panel).getByText("Official Active"),
    ).toBeInTheDocument()
    const headerContent = within(panel)
      .getByRole("heading", { name: componentDetail.name })
      .parentElement
    expect(headerContent).not.toBeNull()
    expect(
      within(headerContent!).getByText("Structurally Valid"),
    ).toBeInTheDocument()
    expect(
      within(headerContent!)
        .getAllByText(
          /^(library|Official Active|Structurally Valid)$/,
        )
        .map((element) => element.textContent),
    ).toEqual(["library", "Official Active", "Structurally Valid"])
    expect(
      within(panel).queryByRole("heading", {
        name: "Status Summary",
      }),
    ).not.toBeInTheDocument()
    expect(
      within(panel).queryByText("Structural Status"),
    ).not.toBeInTheDocument()
    expect(
      within(panel).queryByText("STRUCTURALLY_VALID"),
    ).not.toBeInTheDocument()

    const metadataSection = within(panel)
      .getByRole("heading", { name: "Component Metadata" })
      .closest("section")
    expect(metadataSection).not.toBeNull()
    for (const fieldName of [
      "Version",
      "Publisher",
      "PURL",
    ]) {
      expect(
        within(metadataSection!).getByText(fieldName),
      ).toBeInTheDocument()
    }
    for (const removedField of [
      "Name",
      "Type",
      "bom-ref",
      "Docker repository",
      "Docker tag",
      "SBOM document id",
    ]) {
      expect(
        within(metadataSection!).queryByText(removedField),
      ).not.toBeInTheDocument()
    }
    expect(
      within(panel).queryByText(componentDetail.bom_ref),
    ).not.toBeInTheDocument()
    expect(componentDetail.bom_ref).toBe(
      "pkg:apk/alpine/curl@8.14.1-r1?package-id=abc",
    )
    expect(
      within(panel).getByText(componentDetail.purl),
    ).toBeInTheDocument()

    const primaryCpeSection = within(panel)
      .getByRole("heading", { name: "Primary CPE" })
      .closest("section")
    expect(primaryCpeSection).not.toBeNull()
    expect(
      within(primaryCpeSection!).getByText(componentDetail.cpe),
    ).toBeInTheDocument()
    expect(
      within(panel).queryByRole("heading", {
        name: "Structural Validation",
      }),
    ).not.toBeInTheDocument()
    expect(componentDetail.dictionary_match).toEqual({
      snapshot_id: "20260725T035002Z",
      cpe_name_id: "11111111-1111-4111-8111-111111111111",
      matched_cpe_name: componentSummary.cpe,
      deprecated: false,
    })
    expect(
      within(panel).queryByRole("heading", {
        name: "Exact Match",
      }),
    ).not.toBeInTheDocument()
    expect(within(panel).queryByText("Snapshot ID")).not.toBeInTheDocument()
    expect(
      within(panel).queryByText("20260725T035002Z"),
    ).not.toBeInTheDocument()
    expect(
      within(panel).queryByText(
        "11111111-1111-4111-8111-111111111111",
      ),
    ).not.toBeInTheDocument()
    expect(
      within(panel).queryByText(
        "No structural issues detected by the formatted-string parser.",
      ),
    ).not.toBeInTheDocument()
    expect(componentDetail.sbom_document).toEqual({
      id: 11,
      source_path: "pilot/results/sboms/alpine-3.24.1.cdx.json",
      spec_version: "1.7",
      generator_name: "syft",
      generator_version: "1.49.0",
      source_type: "registry",
      scope: "squashed",
    })
    expect(
      within(panel).queryByRole("heading", { name: "SBOM Source" }),
    ).not.toBeInTheDocument()
    for (const provenanceLabel of [
      "Source path",
      "Spec version",
      "Generator name",
      "Generator version",
      "Source type",
      "Scope",
      "Document id",
    ]) {
      expect(
        within(panel).queryByText(provenanceLabel),
      ).not.toBeInTheDocument()
    }
    for (const provenanceValue of [
      componentDetail.sbom_document.source_path,
      componentDetail.sbom_document.spec_version,
      componentDetail.sbom_document.generator_name,
      componentDetail.sbom_document.generator_version,
      componentDetail.sbom_document.source_type,
      componentDetail.sbom_document.scope,
    ]) {
      expect(
        within(panel).queryByText(provenanceValue),
      ).not.toBeInTheDocument()
    }

    expect(componentDetail.cpe_fields).toEqual(
      componentSummary.cpe_fields,
    )
    expect(
      within(panel).queryByRole("heading", {
        name: "CPE 2.3 Fields",
      }),
    ).not.toBeInTheDocument()
    for (const fieldName of [
      "part",
      "vendor",
      "product",
      "update",
      "edition",
      "language",
      "sw_edition",
      "target_sw",
      "target_hw",
      "other",
    ]) {
      expect(
        within(panel).queryByText(fieldName),
      ).not.toBeInTheDocument()
    }
  })

  it("keeps Additional SBOM Evidence collapsed and toggles raw properties", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/components?component_id=101")
    await waitForDetail()

    const syftCandidates = componentDetail.properties.filter(
      (property) => property.name === "syft:cpe23",
    )
    expect(syftCandidates).toHaveLength(2)
    expect(syftCandidates[0].value).toBe(componentSummary.cpe)
    expect(syftCandidates[1].value).toBe(
      "cpe:2.3:a:curl:curl:8.14.1:*:*:*:*:*:*:*",
    )
    expect(
      screen.queryByRole("heading", {
        name: "Syft CPE Candidates",
      }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText("2 candidates")).not.toBeInTheDocument()
    expect(screen.queryByText("Same as primary")).not.toBeInTheDocument()
    expect(
      screen.queryByText(
        "cpe:2.3:a:curl:curl:8.14.1:*:*:*:*:*:*:*",
      ),
    ).not.toBeInTheDocument()

    expect(
      screen.queryByRole("heading", {
        name: "Other SBOM Properties",
      }),
    ).not.toBeInTheDocument()
    const trigger = screen.getByText("Additional SBOM Evidence")
    const disclosure = trigger.closest("details")
    const summary = trigger.closest("summary")
    expect(disclosure).not.toBeNull()
    expect(summary).not.toBeNull()
    expect(disclosure).not.toHaveAttribute("open")
    expect(
      within(summary!).getByText("3 properties"),
    ).toBeInTheDocument()

    const firstProperty = screen.getByText("syft:package:foundBy")
    const secondProperty = screen.getByText("syft:location:0:path")
    const embaSourceProperty = screen.getByText(
      "EMBA:sbom:source_location:1:source_path",
    )
    const embaSourceValue = screen.getByText(
      "/firmware/rootfs/usr/bin/curl",
    )
    expect(firstProperty).not.toBeVisible()
    expect(secondProperty).not.toBeVisible()
    expect(embaSourceProperty).not.toBeVisible()
    expect(embaSourceValue).not.toBeVisible()

    await user.click(trigger)
    expect(disclosure).toHaveAttribute("open")
    expect(firstProperty).toBeVisible()
    expect(secondProperty).toBeVisible()
    expect(embaSourceProperty).toBeVisible()
    expect(embaSourceValue).toBeVisible()
    expect(firstProperty.closest("li")).toHaveTextContent(
      "syft:package:foundBy",
    )
    expect(secondProperty.closest("li")).toHaveTextContent(
      "syft:location:0:path",
    )

    await user.click(trigger)
    expect(disclosure).not.toHaveAttribute("open")
    expect(firstProperty).not.toBeVisible()
    expect(secondProperty).not.toBeVisible()
    expect(embaSourceProperty).not.toBeVisible()
    expect(embaSourceValue).not.toBeVisible()
  })

  it("uses singular wording for one additional SBOM property", async () => {
    installSuccessfulFetch({
      ...componentDetail,
      properties: [
        {
          name: "EMBA:sbom:minimal_identifier",
          value: "curl",
        },
      ],
    })
    renderAppAt("/components?component_id=101")
    await waitForDetail()

    const trigger = screen.getByText("Additional SBOM Evidence")
    const summary = trigger.closest("summary")
    expect(summary).not.toBeNull()
    expect(
      within(summary!).getByText("1 property"),
    ).toBeInTheDocument()
  })

  it("closes only component_id without reloading the list", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt(
      "/components?image_id=1&search=curl&page=2&component_id=101",
    )
    await waitForDetail()
    const initialListRequests = listRequestCount()

    await user.click(
      screen.getByRole("button", {
        name: "Close component details",
      }),
    )

    await screen.findByText("Select a component")
    const parameters = currentParameters()
    expect(parameters.has("component_id")).toBe(false)
    expect(parameters.get("image_id")).toBe("1")
    expect(parameters.get("search")).toBe("curl")
    expect(parameters.get("page")).toBe("2")
    expect(listRequestCount()).toBe(initialListRequests)
  })

  it("restores a direct component_id URL", async () => {
    installSuccessfulFetch()
    renderAppAt("/components?component_id=101")

    await waitForDetail()
    expect(detailRequestCount()).toBe(1)
    expect(selectedRow()).toHaveAttribute("aria-pressed", "true")
  })

  it("rejects an invalid component_id without a Detail request", async () => {
    installSuccessfulFetch()
    renderAppAt("/components?component_id=not-a-number")

    expect(
      await screen.findByText("Invalid component selection"),
    ).toBeInTheDocument()
    expect(await screen.findByText("curl")).toBeInTheDocument()
    expect(detailRequestCount()).toBe(0)
  })

  it("keeps the list visible for a Detail 404", async () => {
    installSuccessfulFetch()
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/components/") {
        return Promise.resolve(
          jsonResponse(paginatedResponse(url)),
        )
      }
      if (url.pathname === "/api/components/101/") {
        return Promise.resolve(jsonResponse({}, 404))
      }
      return Promise.resolve(jsonResponse({}, 404))
    })

    renderAppAt("/components?component_id=101")
    expect(
      await screen.findByText("Component not found"),
    ).toBeInTheDocument()
    expect(screen.getByText("curl")).toBeInTheDocument()
  })

  it("retries only a failed Detail request", async () => {
    const user = userEvent.setup()
    let detailAttempts = 0
    installSuccessfulFetch()
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/components/") {
        return Promise.resolve(
          jsonResponse(paginatedResponse(url)),
        )
      }
      if (url.pathname === "/api/components/101/") {
        detailAttempts += 1
        return Promise.resolve(
          detailAttempts === 1
            ? jsonResponse(
                { detail: "<html>SECRET_TRACEBACK</html>" },
                500,
              )
            : jsonResponse(componentDetail),
        )
      }
      return Promise.resolve(jsonResponse({}, 404))
    })

    renderAppAt("/components?component_id=101")
    expect(
      await screen.findByText(
        "Unable to load component details",
      ),
    ).toBeInTheDocument()
    const initialListRequests = listRequestCount()
    expect(
      screen.queryByText(/SECRET_TRACEBACK/),
    ).not.toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "Retry" }))
    await waitForDetail()
    expect(detailAttempts).toBe(2)
    expect(listRequestCount()).toBe(initialListRequests)
  })

  it("shows a Detail Skeleton before the request completes", async () => {
    let resolveDetail:
      | ((response: Response) => void)
      | undefined
    installSuccessfulFetch()
    vi.mocked(fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://frontend.test")
      if (url.pathname === "/api/health/") {
        return Promise.resolve(
          jsonResponse({ status: "ok", database: "ok" }),
        )
      }
      if (url.pathname === "/api/components/") {
        return Promise.resolve(
          jsonResponse(paginatedResponse(url)),
        )
      }
      if (url.pathname === "/api/components/101/") {
        return new Promise<Response>((resolve) => {
          resolveDetail = resolve
        })
      }
      return Promise.resolve(jsonResponse({}, 404))
    })

    renderAppAt("/components?component_id=101")
    expect(
      screen.getByLabelText("Loading component details"),
    ).toBeInTheDocument()
    expect(await screen.findByText("curl")).toBeInTheDocument()

    await act(async () => {
      resolveDetail?.(jsonResponse(componentDetail))
    })
    await waitForDetail()
    expect(
      screen.queryByLabelText("Loading component details"),
    ).not.toBeInTheDocument()
  })

  it("handles a Component without a Primary CPE", async () => {
    const noCpeDetail: ComponentDetail = {
      ...componentDetail,
      id: 102,
      cpe: "",
      cpe_fields: null,
      structural_status: "NOT_PRESENT",
      structural_error_message: null,
      properties: [],
      dictionary_status: "NOT_PRESENT",
      dictionary_match: {
        snapshot_id: "20260725T035002Z",
        cpe_name_id: null,
        matched_cpe_name: null,
        deprecated: null,
      },
    }
    installSuccessfulFetch(noCpeDetail)
    renderAppAt("/components?component_id=102")

    expect(
      await screen.findByText("No primary CPE"),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole("heading", {
        name: "CPE 2.3 Fields",
      }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText("CPE fields are not available."),
    ).not.toBeInTheDocument()
    expect(
      within(
        screen.getByRole("complementary", {
          name: "Component details",
        }),
      ).getAllByText("Primary CPE Not Present"),
    ).toHaveLength(1)
    expect(
      screen.queryByRole("heading", {
        name: "Syft CPE Candidates",
      }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText(
        "No `syft:cpe23` candidate properties were found.",
      ),
    ).not.toBeInTheDocument()
    expect(
      screen.getByText("Not Present"),
    ).toBeInTheDocument()
    expect(screen.getAllByText("NOT_PRESENT")).toHaveLength(1)
    expect(screen.getByText("0 properties")).toBeInTheDocument()
  })

  it("keeps Structural Validation and the header Dictionary status", async () => {
    const structuralErrorDetail: ComponentDetail = {
      ...componentDetail,
      structural_status: "INVALID_ESCAPE",
      structural_error_message:
        "Invalid escape sequence at character 18.",
    }
    installSuccessfulFetch(structuralErrorDetail)
    renderAppAt("/components?component_id=101")

    expect(
      await screen.findByText(
        "Invalid escape sequence at character 18.",
      ),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("heading", {
        name: "Structural Validation",
      }),
    ).toBeInTheDocument()
    const panel = screen.getByRole("complementary", {
      name: "Component details",
    })
    expect(
      within(panel).getByText("Official Active"),
    ).toBeInTheDocument()
    expect(
      within(panel).getByText("Invalid Escape"),
    ).toBeInTheDocument()
    expect(
      within(panel).queryByRole("heading", {
        name: "Status Summary",
      }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole("heading", { name: "Exact Match" }),
    ).not.toBeInTheDocument()
    expect(
      screen.getByText(
        "Checks the CPE 2.3 formatted-string structure only.",
      ),
    ).toBeInTheDocument()
  })

  it.each([
    {
      status: "OFFICIAL_ACTIVE" as const,
      headerLabel: "Official Active",
      cpeNameId: "11111111-1111-4111-8111-111111111111",
      deprecated: false,
    },
    {
      status: "OFFICIAL_DEPRECATED" as const,
      headerLabel: "Official Deprecated",
      cpeNameId: "22222222-2222-4222-8222-222222222222",
      deprecated: true,
    },
    {
      status: "NOT_IN_DICTIONARY" as const,
      headerLabel: "Not in Dictionary",
      cpeNameId: null,
      deprecated: null,
    },
    {
      status: "NOT_PRESENT" as const,
      headerLabel: "Primary CPE Not Present",
      cpeNameId: null,
      deprecated: null,
    },
  ])(
    "keeps $status data while hiding Exact Match details",
    async ({
      status,
      headerLabel,
      cpeNameId,
      deprecated,
    }) => {
      const dictionaryMatch = {
        snapshot_id: "20260725T035002Z",
        cpe_name_id: cpeNameId,
        matched_cpe_name: cpeNameId
          ? componentSummary.cpe
          : null,
        deprecated,
      }
      installSuccessfulFetch({
        ...componentDetail,
        dictionary_status: status,
        dictionary_match: dictionaryMatch,
      })
      renderAppAt("/components?component_id=101")
      await waitForDetail()

      const panel = screen.getByRole("complementary", {
        name: "Component details",
      })
      expect(dictionaryMatch.snapshot_id).toBe(
        "20260725T035002Z",
      )
      expect(
        within(panel).getByText(headerLabel),
      ).toBeInTheDocument()
      expect(
        screen.queryByRole("heading", { name: "Exact Match" }),
      ).not.toBeInTheDocument()
      expect(
        screen.queryByText("Snapshot ID"),
      ).not.toBeInTheDocument()
      expect(
        screen.queryByText("20260725T035002Z"),
      ).not.toBeInTheDocument()
      expect(
        screen.queryByText(
          "Dictionary exact match is automated evidence and does not establish semantic correctness for this component.",
        ),
      ).not.toBeInTheDocument()
      if (cpeNameId) {
        expect(
          screen.queryByText(cpeNameId),
        ).not.toBeInTheDocument()
      }
    },
  )

  it("closes Detail when the list search changes", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt("/components?component_id=101")
    await waitForDetail()

    await user.type(
      screen.getByLabelText("Search components"),
      "openssl",
    )
    await waitFor(() => {
      expect(currentParameters().get("search")).toBe("openssl")
      expect(currentParameters().has("component_id")).toBe(false)
    })
    expect(
      await screen.findByText("Select a component"),
    ).toBeInTheDocument()
  })

  it("keeps the remaining Detail flow without hidden evidence or provenance sections", async () => {
    installSuccessfulFetch()
    renderAppAt("/components?component_id=101")
    await waitForDetail()

    expect(
      screen.queryByRole("link", {
        name: "Search CPE Dictionary",
      }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText("Expected Ground Truth CPE"),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole("heading", { name: "Exact Match" }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole("heading", {
        name: "Syft CPE Candidates",
      }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText("SBOM Source")).not.toBeInTheDocument()
  })

  it("closes Detail when sorting, page size, or page changes", async () => {
    const user = userEvent.setup()
    installSuccessfulFetch()
    renderAppAt(
      "/components?page_size=25&component_id=101",
    )
    await waitForDetail()

    await user.click(
      screen.getByRole("button", {
        name: "Sort by Component",
      }),
    )
    await screen.findByText("Select a component")
    expect(currentParameters().get("ordering")).toBe("-name")
    expect(currentParameters().has("component_id")).toBe(false)

    await user.click(selectedRow())
    await waitForDetail()
    await user.selectOptions(
      screen.getByLabelText("Components per page"),
      "50",
    )
    await screen.findByText("Select a component")
    expect(currentParameters().has("page_size")).toBe(false)
    expect(currentParameters().has("component_id")).toBe(false)

    await user.click(selectedRow())
    await waitForDetail()
    await user.click(
      screen.getByRole("button", { name: "Next page" }),
    )
    await screen.findByText("Select a component")
    expect(currentParameters().get("page")).toBe("2")
    expect(currentParameters().has("component_id")).toBe(false)
  })

  it("does not render review or decision controls", async () => {
    installSuccessfulFetch()
    renderAppAt("/components?component_id=101")
    await waitForDetail()

    for (const label of [
      "Confirm",
      "Replace",
      "Save",
      "Approve",
      "Reject",
      "Mark correct",
    ]) {
      expect(
        screen.queryByRole("button", { name: label }),
      ).not.toBeInTheDocument()
    }
  })
})
