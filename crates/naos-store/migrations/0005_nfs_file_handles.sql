CREATE TABLE IF NOT EXISTS nfs_file_handles (
    nonce BLOB PRIMARY KEY CHECK(length(nonce) = 8),
    share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    rel_path TEXT NOT NULL,
    UNIQUE (share_id, rel_path)
);

CREATE INDEX IF NOT EXISTS idx_nfs_file_handles_share
    ON nfs_file_handles(share_id);
