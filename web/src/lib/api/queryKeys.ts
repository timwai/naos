export const queryKeys = {
  audit: {
    list: (filters: object) =>
      ["audit", "list", filters] as const,
  },
  auth: {
    session: () => ["auth", "session"] as const,
    setup: () => ["auth", "setup"] as const,
    sessions: () => ["auth", "sessions"] as const,
  },
  files: {
    shares: () => ["files", "shares"] as const,
    directory: (shareId: string, path: string) =>
      ["files", "directory", shareId, path] as const,
  },
  groups: {
    list: () => ["groups", "list"] as const,
    detail: (groupId: string) => ["groups", "detail", groupId] as const,
    user: (userId: string) => ["groups", "user", userId] as const,
  },
  health: {
    ready: () => ["health", "ready"] as const,
  },
  nfs: {
    principals: () => ["nfs", "principals"] as const,
    bindings: (shareId: string) => ["nfs", "bindings", shareId] as const,
  },
  operations: {
    detail: (operationId: string) => ["operations", operationId] as const,
  },
  shares: {
    list: () => ["shares", "list"] as const,
    detail: (shareId: string) => ["shares", "detail", shareId] as const,
    acl: (shareId: string) => ["shares", shareId, "acl"] as const,
  },
  system: {
    drift: () => ["system", "drift"] as const,
    smbDoctor: () => ["system", "smb-doctor"] as const,
  },
  users: {
    list: () => ["users", "list"] as const,
  },
};
