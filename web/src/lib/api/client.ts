import type { components } from "./generated";

export type SetupStatusResponse = components["schemas"]["SetupStatusResponse"];
export type SetupAdminRequest = components["schemas"]["SetupAdminRequest"];
export type LoginRequest = components["schemas"]["LoginRequest"];
export type PasswordChangeRequest = components["schemas"]["PasswordChangeRequest"];
export type UserDto = components["schemas"]["UserDto"];
export type AuthSessionResponse = components["schemas"]["AuthSessionResponse"];
export type SessionsResponse = components["schemas"]["SessionsResponse"];
export type HealthResponse = components["schemas"]["HealthResponse"];
export type SmbDoctorResponse = components["schemas"]["SmbDoctorResponse"];
export type AcceptedOperation = components["schemas"]["AcceptedOperation"];
export type ErrorResponse = components["schemas"]["ErrorResponse"];

let csrfToken: string | null = null;

export class ApiClientError extends Error {
  readonly status: number;
  readonly code: string;
  readonly fieldErrors: ErrorResponse["field_errors"];

  constructor(status: number, response: ErrorResponse) {
    super(response.message);
    this.name = "ApiClientError";
    this.status = status;
    this.code = response.code;
    this.fieldErrors = response.field_errors;
  }
}

export function setCsrfToken(token: string | null | undefined) {
  csrfToken = token ?? null;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();

  if (init.body !== undefined && init.body !== null) {
    headers.set("content-type", "application/json");
  }

  if (csrfToken && ["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    headers.set("x-csrf-token", csrfToken);
  }

  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "include",
  });

  if (!response.ok) {
    let body: ErrorResponse = {
      code: "HTTP_ERROR",
      message: `请求失败（${response.status}）`,
      field_errors: null,
    };

    try {
      body = (await response.json()) as ErrorResponse;
    } catch {
      // Keep the generic transport error when the server returned no JSON body.
    }

    throw new ApiClientError(response.status, body);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

function jsonBody(value: unknown): string {
  return JSON.stringify(value);
}

export const api = {
  setupStatus: () => request<SetupStatusResponse>("/api/v1/setup/status"),
  setupAdmin: (input: SetupAdminRequest) =>
    request<UserDto>("/api/v1/setup/admin", {
      method: "POST",
      body: jsonBody(input),
    }),
  login: (input: LoginRequest) =>
    request<AuthSessionResponse>("/api/v1/auth/login", {
      method: "POST",
      body: jsonBody(input),
    }),
  session: () => request<AuthSessionResponse>("/api/v1/auth/session"),
  logout: () =>
    request<void>("/api/v1/auth/logout", {
      method: "POST",
    }),
  changePassword: (input: PasswordChangeRequest) =>
    request<void>("/api/v1/auth/password", {
      method: "POST",
      body: jsonBody(input),
    }),
  sessions: () => request<SessionsResponse>("/api/v1/auth/sessions"),
  revokeSession: (id: string) =>
    request<void>(`/api/v1/auth/sessions/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  healthReady: () => request<HealthResponse>("/health/ready"),
  smbDoctor: () => request<SmbDoctorResponse>("/api/v1/system/smb/doctor"),
  systemVerify: () =>
    request<AcceptedOperation>("/api/v1/system/verify", {
      method: "POST",
    }),
};
