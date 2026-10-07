CREATE TABLE IF NOT EXISTS nfs_exclusive_creates (
    share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    rel_path TEXT NOT NULL,
    verifier BLOB NOT NULL CHECK(length(verifier) = 8),
    identity BLOB CHECK(identity IS NULL OR length(identity) = 32),
    PRIMARY KEY (share_id, rel_path)
);
