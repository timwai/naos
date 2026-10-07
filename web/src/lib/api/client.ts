import type { components } from "./generated";

export type AcceptedOperation =
  components["schemas"]["AcceptedOperation"];
export type AclReplaceRequest = components["schemas"]["AclReplaceRequest"];
export type AclRulesResponse = components["schemas"]["AclRulesResponse"];
export type AclSimulateRequest =
  components["schemas"]["AclSimulateRequest"];
export type AclSimulationResponse =
  components["schemas"]["AclSimulationResponse"];
export type ApiErrorBody = components["schemas"]["ErrorResponse"];
export type AuditPageResponse =
  components["schemas"]["AuditPageResponse"];
export type CreateDirectoryRequest =
  components["schemas"]["CreateDirectoryRequest"];
export type FileDirectoryResponse =
  components["schemas"]["FileDirectoryResponse"];
export type FileSharesResponse =
  components["schemas"]["FileSharesResponse"];
export type MoveFileRequest =
  components["schemas"]["MoveFileRequest"];
export type AdminPasswordResetRequest =
  components["schemas"]["AdminPasswordResetRequest"];
export type AuthSessionResponse =
  components["schemas"]["AuthSessionResponse"];
export type GroupDetailDto = components["schemas"]["GroupDetailDto"];
export type GroupMembersReplaceRequest =
  components["schemas"]["GroupMembersReplaceRequest"];
export type GroupsResponse = components["schemas"]["GroupsResponse"];
export type GroupWriteRequest = components["schemas"]["GroupWriteRequest"];
export type HealthResponse = components["schemas"]["HealthResponse"];
export type LoginRequest = components["schemas"]["LoginRequest"];
export type NfsBindingDto = components["schemas"]["NfsBindingDto"];
export type NfsBindingUpsertRequest =
  components["schemas"]["NfsBindingUpsertRequest"];
export type NfsBindingsResponse =
  components["schemas"]["NfsBindingsResponse"];
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
export type ShareDto = components["schemas"]["ShareDto"];
export type ShareWriteRequest = components["schemas"]["ShareWriteRequest"];
export type SharesResponse = components["schemas"]["SharesResponse"];
export type SmbDoctorResponse =
  components["schemas"]["SmbDoctorResponse"];
export type UserCreateRequest =
  components["schemas"]["UserCreateRequest"];
export type UserUpdateRequest =
  components["schemas"]["UserUpdateRequest"];
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

export async function listFileShares() {
  return requestJson<FileSharesResponse>("/api/v1/files/shares");
}

export async function listDirectory(shareId: string, path = "/") {
  const params = new URLSearchParams({ path });
  return requestJson<FileDirectoryResponse>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/files?${params.toString()}`,
  );
}

export async function createDirectory(
  shareId: string,
  input: CreateDirectoryRequest,
) {
  return requestJson<void>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/directories`,
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export async function moveFile(
  shareId: string,
  input: MoveFileRequest,
) {
  return requestJson<void>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/files/move`,
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export async function deleteFile(shareId: string, path: string) {
  const params = new URLSearchParams({ path });
  return requestJson<void>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/files?${params.toString()}`,
    { method: "DELETE" },
  );
}

export async function uploadFile(
  shareId: string,
  path: string,
  file: File,
) {
  const params = new URLSearchParams({ path });
  const headers = new Headers({
    "content-type": file.type || "application/octet-stream",
  });
  if (csrfToken) {
    headers.set("x-csrf-token", csrfToken);
  }

  const response = await fetch(
    `/api/v1/shares/${encodeURIComponent(shareId)}/files/upload?${params.toString()}`,
    {
      method: "POST",
      headers,
      credentials: "include",
      body: file,
    },
  );
  if (!response.ok) {
    let body: ApiErrorBody | null = null;
    try {
      body = (await response.json()) as ApiErrorBody;
    } catch {
      body = null;
    }
    throw new ApiError(response.status, body);
  }
}

export async function downloadFile(shareId: string, path: string) {
  const params = new URLSearchParams({ path });
  const response = await fetch(
    `/api/v1/shares/${encodeURIComponent(shareId)}/files/download?${params.toString()}`,
    { credentials: "include" },
  );
  if (!response.ok) {
    let body: ApiErrorBody | null = null;
    try {
      body = (await response.json()) as ApiErrorBody;
    } catch {
      body = null;
    }
    throw new ApiError(response.status, body);
  }
  return response.blob();
}

export async function listUsers() {
  return requestJson<UsersResponse>("/api/v1/users");
}

export async function listGroups() {
  return requestJson<GroupsResponse>("/api/v1/groups");
}

export async function getGroup(groupId: string) {
  return requestJson<GroupDetailDto>(
    `/api/v1/groups/${encodeURIComponent(groupId)}`,
  );
}

export async function createGroup(input: GroupWriteRequest) {
  return requestJson<GroupDetailDto>("/api/v1/groups", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function updateGroup(
  groupId: string,
  input: GroupWriteRequest,
) {
  return requestJson<GroupDetailDto>(
    `/api/v1/groups/${encodeURIComponent(groupId)}`,
    {
      method: "PUT",
      body: JSON.stringify(input),
    },
  );
}

export async function replaceGroupMembers(
  groupId: string,
  input: GroupMembersReplaceRequest,
) {
  return requestJson<GroupDetailDto>(
    `/api/v1/groups/${encodeURIComponent(groupId)}/members`,
    {
      method: "PUT",
      body: JSON.stringify(input),
    },
  );
}

export async function deleteGroup(groupId: string) {
  return requestJson<void>(
    `/api/v1/groups/${encodeURIComponent(groupId)}`,
    { method: "DELETE" },
  );
}

export async function listUserGroups(userId: string) {
  return requestJson<GroupsResponse>(
    `/api/v1/users/${encodeURIComponent(userId)}/groups`,
  );
}

export async function createUser(
  input: UserCreateRequest,
  idempotencyKey = crypto.randomUUID(),
) {
  return requestJson<AcceptedOperation>("/api/v1/users", {
    method: "POST",
    headers: {
      "idempotency-key": idempotencyKey,
    },
    body: JSON.stringify(input),
  });
}

export async function updateUser(
  userId: string,
  input: UserUpdateRequest,
  idempotencyKey = crypto.randomUUID(),
) {
  return requestJson<AcceptedOperation>(
    `/api/v1/users/${encodeURIComponent(userId)}`,
    {
      method: "PUT",
      headers: {
        "idempotency-key": idempotencyKey,
      },
      body: JSON.stringify(input),
    },
  );
}

export async function resetUserPassword(
  userId: string,
  input: AdminPasswordResetRequest,
  idempotencyKey = crypto.randomUUID(),
) {
  return requestJson<AcceptedOperation>(
    `/api/v1/users/${encodeURIComponent(userId)}/password`,
    {
      method: "POST",
      headers: {
        "idempotency-key": idempotencyKey,
      },
      body: JSON.stringify(input),
    },
  );
}

export async function deleteUser(
  userId: string,
  idempotencyKey = crypto.randomUUID(),
) {
  return requestJson<AcceptedOperation>(
    `/api/v1/users/${encodeURIComponent(userId)}`,
    {
      method: "DELETE",
      headers: {
        "idempotency-key": idempotencyKey,
      },
    },
  );
}

export async function listShares() {
  return requestJson<SharesResponse>("/api/v1/shares");
}

export async function listShareAcl(shareId: string) {
  return requestJson<AclRulesResponse>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/acl`,
  );
}

export async function replaceShareAcl(
  shareId: string,
  input: AclReplaceRequest,
  idempotencyKey = crypto.randomUUID(),
) {
  return requestJson<AcceptedOperation>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/acl`,
    {
      method: "PUT",
      headers: {
        "idempotency-key": idempotencyKey,
      },
      body: JSON.stringify(input),
    },
  );
}

export async function simulateShareAcl(
  shareId: string,
  input: AclSimulateRequest,
) {
  return requestJson<AclSimulationResponse>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/acl/simulate`,
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export async function getShare(shareId: string) {
  return requestJson<ShareDto>(
    `/api/v1/shares/${encodeURIComponent(shareId)}`,
  );
}

export async function listNfsBindings(shareId: string) {
  return requestJson<NfsBindingsResponse>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/nfs-bindings`,
  );
}

export async function createNfsBinding(
  shareId: string,
  input: NfsBindingUpsertRequest,
) {
  return requestJson<NfsBindingDto>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/nfs-bindings`,
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export async function updateNfsBinding(
  shareId: string,
  bindingId: string,
  input: NfsBindingUpsertRequest,
) {
  return requestJson<NfsBindingDto>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/nfs-bindings/${encodeURIComponent(bindingId)}`,
    {
      method: "PUT",
      body: JSON.stringify(input),
    },
  );
}

export async function deleteNfsBinding(
  shareId: string,
  bindingId: string,
) {
  return requestJson<void>(
    `/api/v1/shares/${encodeURIComponent(shareId)}/nfs-bindings/${encodeURIComponent(bindingId)}`,
    { method: "DELETE" },
  );
}

export async function createShare(
  input: ShareWriteRequest,
  idempotencyKey = crypto.randomUUID(),
) {
  return requestJson<AcceptedOperation>("/api/v1/shares", {
    method: "POST",
    headers: {
      "idempotency-key": idempotencyKey,
    },
    body: JSON.stringify(input),
  });
}

export async function updateShare(
  shareId: string,
  input: ShareWriteRequest,
  idempotencyKey = crypto.randomUUID(),
) {
  return requestJson<AcceptedOperation>(
    `/api/v1/shares/${encodeURIComponent(shareId)}`,
    {
      method: "PUT",
      headers: {
        "idempotency-key": idempotencyKey,
      },
      body: JSON.stringify(input),
    },
  );
}

export async function deleteShare(
  shareId: string,
  idempotencyKey = crypto.randomUUID(),
) {
  return requestJson<AcceptedOperation>(
    `/api/v1/shares/${encodeURIComponent(shareId)}`,
    {
      method: "DELETE",
      headers: {
        "idempotency-key": idempotencyKey,
      },
    },
  );
}

export type AuditFilters = {
  from?: string;
  to?: string;
  protocol?: string;
  user_id?: string;
  share_id?: string;
  result?: string;
  q?: string;
  page?: number;
  page_size?: number;
};

export async function listAudit(filters: AuditFilters = {}) {
  const params = new URLSearchParams();
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  if (filters.protocol) params.set("protocol", filters.protocol);
  if (filters.user_id) params.set("user_id", filters.user_id);
  if (filters.share_id) params.set("share_id", filters.share_id);
  if (filters.result) params.set("result", filters.result);
  if (filters.q) params.set("q", filters.q);
  params.set("page", String(filters.page ?? 1));
  params.set("page_size", String(filters.page_size ?? 50));

  return requestJson<AuditPageResponse>(
    `/api/v1/audit?${params.toString()}`,
  );
}
