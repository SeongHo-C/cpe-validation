export interface GetJsonOptions {
  signal?: AbortSignal
}

export class ApiError extends Error {
  readonly status: number

  constructor(status: number) {
    super(`Request failed with status ${status}`)
    this.name = "ApiError"
    this.status = status
  }
}

export function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError"
}

/**
 * Fetch JSON from a relative GET endpoint without exposing response bodies.
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
    throw new ApiError(response.status)
  }

  try {
    return (await response.json()) as T
  } catch {
    throw new Error("The API returned an invalid JSON response")
  }
}
