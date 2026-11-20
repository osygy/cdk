-- Every swap writes 8 proofs and 8 signatures, and three indexes on them put each of those
-- inserts on the same page:
-- - blind_signature_quote_id_index: a swap's signatures have no quote, so every key is NULL,
--   and Postgres keeps equal keys in the order of the rows, so each new one goes at the end.
-- - idx_proof_operation_id and idx_blind_sig_operation_id: operation IDs are UUID v7, which rise
--   with time, after an operation_kind that is the same for every swap, so each new key is the
--   largest and goes on the index's last page.
-- Each insert locks its page for a moment, so with dozens of transactions at once they queue
-- for it (LWLock BufferContent). saga_state's quote_id index is the same, once per swap.
--
-- Quote IDs: partial indexes, without the rows that have none, as idx_proof_quote_id is.
-- `quote_id = $1` implies `quote_id IS NOT NULL`, so the lookups by quote still use them.
--
-- Operation IDs: hash indexes on operation_id alone. Every lookup is `operation_id = $1`
-- (get_proof_ys_by_operation_id, get_blinded_secrets_by_operation_id), which a hash index
-- answers, and a hash spreads its inserts over all its buckets.
DROP INDEX IF EXISTS blind_signature_quote_id_index;
CREATE INDEX IF NOT EXISTS blind_signature_quote_id_index ON blind_signature(quote_id) WHERE quote_id IS NOT NULL;

DROP INDEX IF EXISTS idx_saga_state_quote_id;
CREATE INDEX IF NOT EXISTS idx_saga_state_quote_id ON saga_state(quote_id) WHERE quote_id IS NOT NULL;

DROP INDEX IF EXISTS idx_proof_operation_id;
CREATE INDEX IF NOT EXISTS idx_proof_operation_id ON proof USING hash (operation_id);

DROP INDEX IF EXISTS idx_blind_sig_operation_id;
CREATE INDEX IF NOT EXISTS idx_blind_sig_operation_id ON blind_signature USING hash (operation_id);
