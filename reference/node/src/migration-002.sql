-- Migration 2: preserve original response octets and coordinate delivery workers.
-- Legacy TEXT evidence cannot recover invalid UTF-8 bytes; leave its BLOB NULL.
ALTER TABLE attempts ADD COLUMN body_bytes BLOB;
ALTER TABLE outbox ADD COLUMN claim_token TEXT;
ALTER TABLE outbox ADD COLUMN claim_until INTEGER NOT NULL DEFAULT 0;
