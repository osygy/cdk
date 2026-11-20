-- A melt finds its input proofs by quote (get_proof_ys_by_quote_id). Without an index, that
-- scans the whole proof table once per melt. Partial: only proofs that belong to a quote, so
-- swaps' proofs (no quote) don't pay to keep it up.
CREATE INDEX IF NOT EXISTS idx_proof_quote_id ON proof(quote_id) WHERE quote_id IS NOT NULL;
