export const queryKeys = {
  auth: {
    session: () => ["auth", "session"] as const,
    setup: () => ["auth", "setup"] as const,
  },
  health: {
    ready: () => ["health", "ready"] as const,
  },
  system: {
    smbDoctor: () => ["system", "smb-doctor"] as const,
  },
};
