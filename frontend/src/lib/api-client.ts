export interface GetJsonOptions {
  signal?: AbortSignal
}

export interface PutJsonOptions {
  signal?: AbortSignal
}

export interface MutationJsonOptions {
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

async function responseError(response: Response): Promise<ApiError> {
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
  const fieldDetails = body
    ? Object.entries(body)
        .filter(([key]) => key !== "code")
        .flatMap(([key, value]) => {
          if (typeof value === "string") {
            return [`${key}: ${value}`]
          }
          if (Array.isArray(value)) {
            return value
              .filter((item) => typeof item === "string")
              .map((item) => `${key}: ${item}`)
          }
          return []
        })
        .join(" ")
    : ""
  return new ApiError(response.status, {
    code:
      typeof body?.code === "string" ? body.code : undefined,
    detail:
      typeof body?.detail === "string"
        ? body.detail
        : fieldDetails || undefined,
  })
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
    throw await responseError(response)
  }

  try {
    return (await response.json()) as T
  } catch {
    throw new Error("The API returned an invalid JSON response")
  }
}

export async function putJson<T>(
  url: string,
  body: unknown,
  options: PutJsonOptions = {},
): Promise<T> {
  const response = await fetch(url, {
    method: "PUT",
    signal: options.signal,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    throw await responseError(response)
  }

  try {
    return (await response.json()) as T
  } catch {
    throw new Error("The API returned an invalid JSON response")
  }
}

async function mutationJson<T>(
  method: "POST" | "PATCH",
  url: string,
  body: unknown,
  options: MutationJsonOptions = {},
): Promise<T> {
  const response = await fetch(url, {
    method,
    signal: options.signal,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    throw await responseError(response)
  }

  try {
    return (await response.json()) as T
  } catch {
    throw new Error("The API returned an invalid JSON response")
  }
}

export function postJson<T>(
  url: string,
  body: unknown,
  options: MutationJsonOptions = {},
): Promise<T> {
  return mutationJson("POST", url, body, options)
}

export function patchJson<T>(
  url: string,
  body: unknown,
  options: MutationJsonOptions = {},
): Promise<T> {
  return mutationJson("PATCH", url, body, options)
}
