import { screen, waitFor, within } from "@testing-library/react"
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest"

import { renderAppAt } from "@/test/render-app"

function jsonResponse<T>(body: T, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function installFetch(summaryStatus = 200) {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = new URL(String(input), "http://frontend.test")
    if (url.pathname === "/api/health/") {
      return Promise.resolve(
        jsonResponse({ status: "ok", database: "ok" }),
      )
    }
    if (url.pathname === "/api/cpe-analysis/summary/") {
      return Promise.resolve(
        jsonResponse(
          summaryStatus === 200
            ? {
                positive_gt_components_at_validation: 158,
                searchable_candidate_families: 181_484,
                method_count: 4,
                completed_method_count: 4,
                algorithms: [
                  {
                    algorithm_id: "length_normalized_levenshtein",
                    status: "COMPLETED",
                    query_count: 158,
                    candidate_family_count: 181_484,
                    metrics: {
                      top1_accuracy: 0.3987341772151899,
                      recall_at_5: 0.7848101265822784,
                      recall_at_10: 0.8037974683544303,
                      mrr: 0.5565417164607827,
                    },
                  },
                  {
                    algorithm_id: "jaro_winkler",
                    status: "COMPLETED",
                    query_count: 158,
                    candidate_family_count: 181_484,
                    metrics: {
                      top1_accuracy: 0.43670886075949367,
                      recall_at_5: 0.8481012658227848,
                      recall_at_10: 0.8860759493670886,
                      mrr: 0.6082612255091588,
                    },
                  },
                  {
                    algorithm_id: "character_trigram_dice",
                    status: "COMPLETED",
                    query_count: 158,
                    candidate_family_count: 181_484,
                    metrics: {
                      top1_accuracy: 0.5,
                      recall_at_5: 0.8607594936708861,
                      recall_at_10: 0.8987341772151899,
                      mrr: 0.6523244057752082,
                    },
                  },
                  {
                    algorithm_id: "ratcliff_obershelp",
                    status: "COMPLETED",
                    query_count: 158,
                    candidate_family_count: 181_484,
                    metrics: {
                      top1_accuracy: 0.45569620253164556,
                      recall_at_5: 0.8227848101265823,
                      recall_at_10: 0.8354430379746836,
                      mrr: 0.6058037627846183,
                    },
                  },
                ],
              }
            : {
                code: "cpe_analysis_manifest_unavailable",
                detail: "CPE analysis metadata is unavailable.",
              },
          summaryStatus,
        ),
      )
    }
    return Promise.resolve(jsonResponse({}, 404))
  })
}

function analysisRequestCount(): number {
  return vi
    .mocked(fetch)
    .mock.calls.filter(([input]) => {
      const url = new URL(String(input), "http://frontend.test")
      return url.pathname === "/api/cpe-analysis/summary/"
    }).length
}

describe("CPE Analysis dashboard", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("renders the completed final four-method dashboard", async () => {
    installFetch()
    renderAppAt("/cpe-analysis")

    expect(
      screen.getByRole("heading", { name: "CPE Analysis" }),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        "Compare CPE product-family matching performance across algorithms.",
      ),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("link", { name: "CPE Analysis" }),
    ).toHaveAttribute("aria-current", "page")

    const summary = await screen.findByRole("region", {
      name: "Experiment Summary",
    })
    expect(within(summary).getByText("158"))
      .toBeInTheDocument()
    expect(within(summary).getByText("181,484"))
      .toBeInTheDocument()
    expect(within(summary).getByText("50.00%"))
      .toBeInTheDocument()
    expect(within(summary).getByText("89.87%"))
      .toBeInTheDocument()
    for (const label of [
      "Evaluation Set",
      "Candidate Families",
      "Best Top-1",
      "Best Recall@10",
    ]) {
      expect(within(summary).getByText(label)).toBeInTheDocument()
    }
    for (const removed of [
      "Methods",
      "Benchmark",
      "Character-level similarity methods",
      "Methods evaluated",
    ]) {
      expect(within(summary).queryByText(removed))
        .not.toBeInTheDocument()
    }
    expect(within(summary).queryByRole("progressbar"))
      .not.toBeInTheDocument()
    expect(screen.queryByRole("region", { name: "Algorithms" }))
      .not.toBeInTheDocument()
    expect(screen.queryByText("API Connected"))
      .not.toBeInTheDocument()

    const table = screen.getByRole("table", {
      name: "Product-family retrieval performance leaderboard",
    })
    expect(table.parentElement).toHaveClass("overflow-x-auto")
    expect(within(table).getAllByRole("rowgroup")[0])
      .toHaveClass("bg-slate-50")
    expect(within(table).getAllByRole("row")).toHaveLength(5)
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual([
      "Algorithm",
      "Top-1 Accuracy",
      "Recall@5",
      "Recall@10",
      "MRR",
    ])
    const levenshteinRow = within(table).getByRole("row", {
      name: /Levenshtein/,
    })
    for (const metric of ["39.87%", "78.48%", "80.38%", "0.5565"]) {
      expect(within(levenshteinRow).getByText(metric))
        .toBeInTheDocument()
    }
    const characterRow = within(table).getByRole("row", {
      name: /Character n-gram/,
    })
    expect(characterRow).toHaveClass("hover:bg-slate-50")
    expect(characterRow).not.toHaveClass("bg-cyan-50/45")
    expect(within(characterRow).getAllByRole("cell")[0])
      .toHaveClass("border-l-2", "border-l-cyan-600")
    const bestBadge = within(characterRow).getByText("Best")
    expect(bestBadge).toHaveClass(
      "h-4",
      "border-cyan-600/20",
      "bg-transparent",
      "text-[10px]",
      "text-cyan-700",
    )
    for (const metric of ["50.00%", "86.08%", "89.87%", "0.6523"]) {
      const metricValue = within(characterRow).getByText(metric)
      expect(metricValue).toHaveClass("font-semibold", "text-foreground")
      expect(metricValue).not.toHaveClass("text-cyan-800")
    }
    const ratcliffRow = within(table).getByRole("row", {
      name: /Ratcliff–Obershelp/,
    })
    for (const metric of ["45.57%", "82.28%", "83.54%", "0.6058"]) {
      expect(within(ratcliffRow).getByText(metric))
        .toBeInTheDocument()
    }
    for (const [name, descriptor] of [
      ["Levenshtein", "Edit distance"],
      ["Jaro-Winkler", "Character position"],
      ["Character n-gram", "Character fragments"],
      ["Ratcliff–Obershelp", "Common substring"],
    ]) {
      const row = within(table).getByRole("row", {
        name: new RegExp(name),
      })
      expect(within(row).getByText(descriptor)).toBeInTheDocument()
    }
    expect(within(table).queryByText("Completed"))
      .not.toBeInTheDocument()
    expect(within(table).queryByText("Status"))
      .not.toBeInTheDocument()

    await waitFor(() => {
      expect(analysisRequestCount()).toBe(1)
    })
    for (const [, options] of vi.mocked(fetch).mock.calls) {
      expect(options?.method ?? "GET").toBe("GET")
    }
  })

  it("keeps static dashboard sections available on metadata failure", async () => {
    installFetch(503)
    renderAppAt("/cpe-analysis")

    expect(
      await screen.findByText("Unable to load experiment summary"),
    ).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Retry" }))
      .toBeInTheDocument()
    expect(screen.queryByRole("region", { name: "Algorithms" }))
      .not.toBeInTheDocument()
    expect(screen.getByRole("region", { name: "Performance" }))
      .toBeInTheDocument()
    expect(screen.queryByText("Selected Algorithm"))
      .not.toBeInTheDocument()
    expect(screen.queryByText("181,484"))
      .not.toBeInTheDocument()
  })

})
