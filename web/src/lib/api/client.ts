import type { components } from "./generated";

export type AcceptedOperation =
  components["schemas"]["AcceptedOperation"];
export type ApiErrorBody = components["schemas"]["ErrorResponse"];
export type AuthSessionResponse =
  components["schemas"]["AuthSessionResponse"];
export type HealthResponse = components["schemas"]["HealthResponse"];
export type LoginRequest = components["schemas"]["LoginRequest"];
export type NfsKrbPrincipalCreateRequest =
  components["schemas"]["NfsKrbPrincipalCreateRequest"];
export type NfsKrbPrincipalsResponse =
  components["schemas"]["NfsKrbPrincipalsResponse"];
export type OperationDto = components["schemas"]["OperationDto"];
export type PasswordChangeRequest =
  components["schemas"]["PasswordChangeRequest"];
export type SessionDto = components["schemas"]["SessionDto"];
export type SessionsResponse = components["schemas"]["SessionsResponse"];
export type SetupAdminRequest =
  components["schemas"]["SetupAdminRequest"];
export type SetupStatusResponse =
  components["schemas"]["SetupStatusResponse"];
export type SharesResponse = components["schemas"]["SharesResponse"];
export type SmbDoctorResponse =
  components["schemas"]["SmbDoctorResponse"];
export type UsersResponse = components["schemas"]["UsersResponse"];

export class ApiError extends Error {
  readonly status: number;
  readonly body: ApiErrorBody | null;

  constructor(status: number, body: ApiErrorBody | null) {
    super(body?.message ?? "请求失败");
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

let csrfToken: string | null = null;

function observeSession(session: AuthSessionResponse) {
  csrfToken = session.authenticated ? (session.csrf_token ?? null) : null;
  return session;
}

async function requestJson<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();

  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  if (
    csrfToken &&
    ["POST", "PUT", "PATCH", "DELETE"].includes(method)
  ) {
    headers.set("x-csrf-token", csrfToken);
  }

  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "include",
  });

  if (!response.ok) {
    let body: ApiErrorBody | null = null;
    try {
      body = (await response.json()) as ApiErrorBody;
    } catch {
      body = null;
    }
    throw new ApiError(response.status, body);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export async function getSession() {
  return observeSession(
    await requestJson<AuthSessionResponse>("/api/v1/auth/session"),
  );
}

export async function getSetupStatus() {
  return requestJson<SetupStatusResponse>("/api/v1/setup/status");
}

export async function setupAdmin(input: SetupAdminRequest) {
  return requestJson<components["schemas"]["UserDto"]>(
    "/api/v1/setup/admin",
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export async function login(input: LoginRequest) {
  return observeSession(
    await requestJson<AuthSessionResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  );
}

export async function logout() {
  await requestJson<void>("/api/v1/auth/logout", { method: "POST" });
  csrfToken = null;
}

export async function changePassword(input: PasswordChangeRequest) {
  return requestJson<void>("/api/v1/auth/password", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function listSessions() {
  return requestJson<SessionsResponse>("/api/v1/auth/sessions");
}

export async function revokeSession(sessionId: string) {
  return requestJson<void>(
    `/api/v1/auth/sessions/${encodeURIComponent(sessionId)}`,
    { method: "DELETE" },
  );
}

export async function getReadiness(): Promise<HealthResponse> {
  const response = await fetch("/health/ready", {
    credentials: "include",
  });

  if (response.status === 200 || response.status === 503) {
    return (await response.json()) as HealthResponse;
  }

  throw new ApiError(response.status, null);
}

export async function getSmbDoctor() {
  return requestJson<SmbDoctorResponse>("/api/v1/system/smb/doctor");
}

export async function startSystemVerify() {
  return requestJson<AcceptedOperation>("/api/v1/system/verify", {
    method: "POST",
    headers: {
      "idempotency-key": crypto.randomUUID(),
    },
  });
}

export async function getOperation(operationId: string) {
  return requestJson<OperationDto>(
    `/api/v1/operations/${encodeURIComponent(operationId)}`,
  );
}

export async function listNfsPrincipals() {
  return requestJson<NfsKrbPrincipalsResponse>("/api/v1/nfs/principals");
}

export async function createNfsPrincipal(
  input: NfsKrbPrincipalCreateRequest,
) {
  return requestJson<components["schemas"]["NfsKrbPrincipalDto"]>(
    "/api/v1/nfs/principals",
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export async function deleteNfsPrincipal(principalId: string) {
  return requestJson<void>(
    `/api/v1/nfs/principals/${encodeURIComponent(principalId)}`,
    { method: "DELETE" },
  );
}

export async function listUsers() {
  return requestJson<UsersResponse>("/api/v1/users");
}

export async function listShares() {
  return requestJson<SharesResponse>("/api/v1/shares");
}
