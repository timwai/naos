CREATE UNIQUE INDEX IF NOT EXISTS idx_operations_idempotency
    ON operations(idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_operation_events_operation
    ON operation_events(operation_id, seq);
