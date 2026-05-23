-- IAGA Sentinel 1.0 — M2 "Signed Action Receipts"
-- Table: receipts (append-only Merkle-linked log per run_id)

CREATE TABLE IF NOT EXISTS receipts (
    run_id        TEXT    NOT NULL,
    seq           BIGINT  NOT NULL,
    parent_hash   TEXT,
    input_hash    TEXT    NOT NULL,
    policy_hash   TEXT    NOT NULL,
    verdict       TEXT    NOT NULL,
    risk_score    INTEGER NOT NULL,
    timestamp     TEXT    NOT NULL,
    signer_key_id TEXT    NOT NULL,
    signature     TEXT    NOT NULL,
    body_json     TEXT    NOT NULL,
    PRIMARY KEY (run_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
CREATE INDEX IF NOT EXISTS idx_receipts_verdict   ON receipts(verdict);
