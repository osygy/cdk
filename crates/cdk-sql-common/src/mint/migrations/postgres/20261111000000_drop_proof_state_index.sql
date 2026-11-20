-- No query looks proofs up by (state, operation_kind), and while `state` is indexed, Postgres
-- can't update a proof in place: each change of state writes a new row version and a new entry in
-- every index on the row.
DROP INDEX IF EXISTS idx_proof_state_operation;
