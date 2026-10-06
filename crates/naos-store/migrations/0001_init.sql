CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    system_account TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    path TEXT NOT NULL,
    canonical_path TEXT NOT NULL UNIQUE,
    comment TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    smb_enabled INTEGER NOT NULL DEFAULT 1,
    webdav_enabled INTEGER NOT NULL DEFAULT 0,
    nfs_enabled INTEGER NOT NULL DEFAULT 0,
    generation INTEGER NOT NULL DEFAULT 1,
    applied_generation INTEGER NOT NULL DEFAULT 0,
    apply_state TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS share_acl (
    id TEXT PRIMARY KEY,
    share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    rel_path TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    perm TEXT NOT NULL,
    inherit INTEGER NOT NULL,
    UNIQUE (share_id, rel_path, subject_type, subject_id)
);

CREATE TABLE IF NOT EXISTS nfs_bindings (
    id TEXT PRIMARY KEY,
    share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL,
    uid INTEGER,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    perm TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nfs_krb_principals (
    id TEXT PRIMARY KEY,
    principal TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_hash BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    client_ip TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    resource_type TEXT,
    resource_id TEXT,
    request_id TEXT,
    idempotency_key TEXT,
    progress INTEGER NOT NULL DEFAULT 0,
    phase TEXT,
    error_code TEXT,
    error_detail_json TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS operation_events (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    event TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    ts TEXT NOT NULL,
    PRIMARY KEY (operation_id, seq)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    actor_name TEXT,
    protocol TEXT,
    action TEXT NOT NULL,
    share_id TEXT REFERENCES shares(id) ON DELETE SET NULL,
    path TEXT,
    client_ip TEXT,
    result TEXT NOT NULL,
    detail_json TEXT,
    request_id TEXT,
    operation_id TEXT REFERENCES operations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS apply_history (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    desired_generation INTEGER,
    plan_json TEXT NOT NULL,
    status TEXT NOT NULL,
    rollback_json TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(actor_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_share ON audit_log(share_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_result ON audit_log(result, ts DESC);
CREATE INDEX IF NOT EXISTS idx_operations_state ON operations(state, created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
