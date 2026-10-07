export const queryKeys = {
  auth: {
    session: () => ["auth", "session"] as const,
    setup: () => ["auth", "setup"] as const,
    sessions: () => ["auth", "sessions"] as const,
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
    smbDoctor: () => ["system", "smb-doctor"] as const,
  },
  users: {
    list: () => ["users", "list"] as const,
  },
};
