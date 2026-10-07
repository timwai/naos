export const queryKeys = {
  setup: ["setup", "status"] as const,
  auth: {
    session: ["auth", "session"] as const,
    sessions: ["auth", "sessions"] as const,
  },
  health: {
    ready: ["health", "ready"] as const,
  },
  system: {
    smbDoctor: ["system", "smb-doctor"] as const,
  },
} as const;
