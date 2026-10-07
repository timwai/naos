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
  },
  operations: {
    detail: (operationId: string) => ["operations", operationId] as const,
  },
  system: {
    smbDoctor: () => ["system", "smb-doctor"] as const,
  },
};
