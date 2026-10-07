ALTER TABLE shares
    ADD COLUMN delete_requested INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_shares_apply_state
    ON shares(apply_state, generation, applied_generation);

CREATE INDEX IF NOT EXISTS idx_shares_delete_requested
    ON shares(delete_requested, generation);
