export interface GetJsonOptions {
  signal?: AbortSignal
}

export class ApiError extends Error {
  readonly status: number
  readonly code?: string
  readonly detail?: string

  constructor(
    status: number,
    options: { code?: string; detail?: string } = {},
  ) {
    super(
      options.detail ?? `Request failed with status ${status}`,
    )
    this.name = "ApiError"
    this.status = status
    this.code = options.code
    this.detail = options.detail
  }
}

export function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError"
}

/**
 * Fetch JSON from a relative GET endpoint.
 */
export async function getJson<T>(
  url: string,
  options: GetJsonOptions = {},
): Promise<T> {
  const response = await fetch(url, {
    method: "GET",
    signal: options.signal,
    headers: {
      Accept: "application/json",
    },
  })

  if (!response.ok) {
    let errorBody: unknown
    try {
      errorBody = await response.json()
    } catch {
      errorBody = null
    }
    const body =
      typeof errorBody === "object" && errorBody !== null
        ? (errorBody as Record<string, unknown>)
        : null
    throw new ApiError(response.status, {
      code:
        typeof body?.code === "string"
          ? body.code
          : undefined,
      detail:
        typeof body?.detail === "string"
          ? body.detail
          : undefined,
    })
  }

  try {
    return (await response.json()) as T
  } catch {
    throw new Error("The API returned an invalid JSON response")
  }
}
