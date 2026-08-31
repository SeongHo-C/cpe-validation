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
                method_count: 6,
                completed_method_count: 1,
                algorithms: [
                  {
                    algorithm_id: "exact_match",
                    status: "NOT_RUN",
                    query_count: null,
                    candidate_family_count: null,
                    metrics: null,
                  },
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
                  ...[
                    "jaro_winkler",
                    "character_ngram",
                    "token_jaccard",
                    "tfidf_cosine",
                  ].map((algorithmId) => ({
                    algorithm_id: algorithmId,
                    status: "NOT_RUN",
                    query_count: null,
                    candidate_family_count: null,
                    metrics: null,
                  })),
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

  it("renders four KPIs and a six-method leaderboard", async () => {
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
    expect(within(summary).getByText("6")).toBeInTheDocument()
    expect(within(summary).getByText("1 / 6"))
      .toBeInTheDocument()
    expect(within(summary).getByText("Methods evaluated"))
      .toBeInTheDocument()
    for (const label of [
      "Evaluation Set",
      "Candidate Families",
      "Methods",
      "Benchmark",
    ]) {
      expect(within(summary).getByText(label)).toBeInTheDocument()
    }

    const algorithmCards = screen.getByRole("region", {
      name: "Algorithms",
    })
    expect(within(algorithmCards).getAllByRole("listitem"))
      .toHaveLength(6)
    expect(within(algorithmCards).queryByRole("button"))
      .not.toBeInTheDocument()
    for (const name of [
      "Exact Match",
      "Levenshtein",
      "Jaro-Winkler",
      "Character n-gram",
      "Token Jaccard",
      "TF-IDF + Cosine",
    ]) {
      expect(within(algorithmCards).getByRole("heading", { name }))
        .toBeInTheDocument()
    }
    expect(within(algorithmCards).getByText("Baseline"))
      .toBeInTheDocument()
    const levenshteinCard = within(algorithmCards)
      .getByRole("heading", { name: "Levenshtein" })
      .closest("li")
    expect(levenshteinCard).not.toBeNull()
    expect(within(levenshteinCard!).getByText("Completed"))
      .toBeInTheDocument()
    expect(within(algorithmCards).getAllByText("Not Run"))
      .toHaveLength(5)
    expect(screen.queryByText("Selected Algorithm"))
      .not.toBeInTheDocument()
    expect(screen.queryByText("Selected"))
      .not.toBeInTheDocument()

    const table = screen.getByRole("table", {
      name: "Product-family retrieval performance leaderboard",
    })
    expect(within(table).getAllByRole("row")).toHaveLength(7)
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual([
      "Algorithm",
      "Status",
      "Top-1 Accuracy",
      "Recall@5",
      "Recall@10",
      "MRR",
    ])
    const levenshteinRow = within(table).getByRole("row", {
      name: /Levenshtein/,
    })
    expect(within(levenshteinRow).getByText("Completed"))
      .toBeInTheDocument()
    for (const metric of ["39.87%", "78.48%", "80.38%", "0.5565"]) {
      expect(within(levenshteinRow).getByText(metric))
        .toBeInTheDocument()
    }
    expect(within(table).getAllByText("-")).toHaveLength(20)
    expect(within(table).getAllByText("Not Run")).toHaveLength(5)

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
    expect(
      screen.getByRole("region", { name: "Algorithms" }),
    ).toBeInTheDocument()
    expect(screen.getByRole("region", { name: "Performance" }))
      .toBeInTheDocument()
    expect(screen.queryByText("Selected Algorithm"))
      .not.toBeInTheDocument()
    expect(screen.queryByText("181,484"))
      .not.toBeInTheDocument()
  })
})
