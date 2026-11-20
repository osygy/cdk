-- No query looks proofs up by (state, operation_kind): an index each insert and each change of
-- state has to keep up for nothing.
DROP INDEX IF EXISTS idx_proof_state_operation;
