CREATE INDEX IF NOT EXISTS idx_nfs_bindings_share
    ON nfs_bindings(share_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nfs_bindings_l1_unique
    ON nfs_bindings(share_id, cidr)
    WHERE uid IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_nfs_bindings_l2_unique
    ON nfs_bindings(share_id, cidr, uid)
    WHERE uid IS NOT NULL;
