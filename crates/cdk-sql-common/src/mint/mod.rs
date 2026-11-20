//! SQL database implementation of the Mint
//!
//! This is a generic SQL implementation for the mint storage layer. Any database can be plugged in
//! as long as standard ANSI SQL is used, as Postgres and SQLite would understand it.
//!
//! This implementation also has a rudimentary but standard migration and versioning system.
//!
//! The trait expects an asynchronous interaction, but it also provides tools to spawn blocking
//! clients in a pool and expose them to an asynchronous environment, making them compatible with
//! Mint.
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use cdk_common::database::{self, DbTransactionFinalizer, Error, MintDatabase};
use cdk_common::QuoteId;

use crate::common::migrate;
use crate::database::{ConnectionWithTransaction, DatabaseExecutor};
use crate::pool::{DatabasePool, Pool, PooledResource};
use crate::stmt::{query, Statement};

mod auth;
mod completed_operations;
mod keys;
mod keyvalue;
mod proofs;
mod quotes;
mod saga;
mod signatures;

#[rustfmt::skip]
mod migrations {
    include!(concat!(env!("OUT_DIR"), "/migrations_mint.rs"));
}

pub use auth::SQLMintAuthDatabase;
#[cfg(feature = "prometheus")]
use cdk_prometheus::MintMetricGuard;
use migrations::MIGRATIONS;

/// Mint SQL Database
#[derive(Debug, Clone)]
pub struct SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    pub(crate) pool: Arc<Pool<RM>>,
}

/// SQL Transaction Writer
#[allow(missing_debug_implementations)]
pub struct SQLTransaction<RM>
where
    RM: DatabasePool + 'static,
{
    pub(crate) inner: ConnectionWithTransaction<RM::Connection, PooledResource<RM>>,
    /// Changes to `keyset_amounts` made in this transaction, by keyset ID. They're written once
    /// per keyset, just before commit, so the keyset's totals row stays locked only for that
    /// statement and the commit, not for the rest of the transaction. Dropped on rollback.
    pub(crate) keyset_deltas: BTreeMap<String, KeysetAmountsDelta>,
}

/// What a transaction adds to one keyset's row in `keyset_amounts`.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct KeysetAmountsDelta {
    pub(crate) issued: i64,
    pub(crate) redeemed: i64,
    pub(crate) fee_collected: i64,
}

/// Rows per multi-row `INSERT`. 64 rows of up to 11 columns stays under 999 parameters, the
/// lowest limit SQLite has had, and keeps the SQL texts a writer makes (one per row count) to 64.
/// A swap or melt of up to 64 inputs or outputs takes one statement.
pub(crate) const ROWS_PER_STATEMENT: usize = 64;

/// The rows of a multi-row `VALUES`: `row(0), row(1), ...`. Each row names its own
/// placeholders by its index (`:y0`, `:y1`, ...), so the rows bind one by one; a placeholder
/// without an index is shared by every row.
pub(crate) fn values_rows(rows: usize, row: impl Fn(usize) -> String) -> String {
    (0..rows).map(row).collect::<Vec<_>>().join(", ")
}

/// Sorted, deduplicated advisory lock keys for a batch of quotes.
fn quote_lock_keys(quote_ids: &[QuoteId]) -> Vec<String> {
    let mut keys = quote_ids
        .iter()
        .map(|quote_id| format!("cdk:quote:{quote_id}"))
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

impl<RM> SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    /// Creates a new instance
    pub async fn new<X>(db: X) -> Result<Self, Error>
    where
        X: Into<RM::Config>,
    {
        let pool = Pool::new(db.into());

        Self::migrate(pool.get().await.map_err(|e| Error::Database(Box::new(e)))?).await?;

        Ok(Self { pool })
    }

    async fn begin_transaction_from_pool(
        pool: &Arc<Pool<RM>>,
    ) -> Result<Box<dyn database::MintTransaction<Error> + Send + Sync>, Error> {
        let tx = SQLTransaction {
            inner: ConnectionWithTransaction::new(
                pool.get().await.map_err(|e| Error::Database(Box::new(e)))?,
            )
            .await?,
            keyset_deltas: BTreeMap::new(),
        };

        Ok(Box::new(tx))
    }

    /// Migrate
    async fn migrate(conn: PooledResource<RM>) -> Result<(), Error> {
        let tx = ConnectionWithTransaction::new(conn).await?;
        migrate(&tx, RM::Connection::name(), MIGRATIONS).await?;
        tx.commit().await?;
        Ok(())
    }
}

impl<RM> SQLTransaction<RM>
where
    RM: DatabasePool + 'static,
{
    /// Take quote advisory locks in one statement and stable key order.
    async fn take_quote_locks(&mut self, quote_ids: &[QuoteId]) -> Result<bool, Error> {
        if quote_ids.is_empty() || RM::Connection::name() != "postgres" {
            return Ok(false);
        }

        query(
            r#"
            SELECT pg_advisory_xact_lock(hashtextextended(key, 0))
            FROM (
                SELECT key FROM unnest(ARRAY[:keys]::TEXT[]) AS t(key) ORDER BY key
            ) sorted
            "#,
        )?
        .bind_vec("keys", quote_lock_keys(quote_ids))?
        .execute(&self.inner)
        .await?;

        Ok(true)
    }

    /// Records a change to a keyset's totals, to be written at commit.
    pub(crate) fn add_keyset_delta(
        &mut self,
        keyset_id: String,
        issued: i64,
        redeemed: i64,
        fee_collected: i64,
    ) {
        let delta = self.keyset_deltas.entry(keyset_id).or_default();
        delta.issued += issued;
        delta.redeemed += redeemed;
        delta.fee_collected += fee_collected;
    }

    /// The upserts that write the recorded totals, one per keyset, to run just before COMMIT
    /// and with it. The map is ordered by keyset ID, so concurrent transactions lock shared rows
    /// in the same order and can't deadlock.
    fn keyset_delta_statements(&mut self) -> Result<Vec<Statement>, Error> {
        let mut statements = Vec::new();
        for (keyset_id, delta) in std::mem::take(&mut self.keyset_deltas) {
            if delta.issued == 0 && delta.redeemed == 0 && delta.fee_collected == 0 {
                continue;
            }
            let statement = query(
                r#"
                INSERT INTO keyset_amounts (keyset_id, total_issued, total_redeemed, fee_collected)
                VALUES (:keyset_id, :issued, :redeemed, :fee_collected)
                ON CONFLICT (keyset_id)
                DO UPDATE SET
                    total_issued = keyset_amounts.total_issued + EXCLUDED.total_issued,
                    total_redeemed = keyset_amounts.total_redeemed + EXCLUDED.total_redeemed,
                    fee_collected = keyset_amounts.fee_collected + EXCLUDED.fee_collected
                "#,
            )?
            .bind("keyset_id", keyset_id)
            .bind("issued", delta.issued)
            .bind("redeemed", delta.redeemed)
            .bind("fee_collected", delta.fee_collected);
            statements.push(statement);
        }
        Ok(statements)
    }
}

#[async_trait]
impl<RM> database::MintTransaction<Error> for SQLTransaction<RM>
where
    RM: DatabasePool + 'static,
{
    async fn lock_quotes(&mut self, quote_ids: &[QuoteId]) -> Result<bool, Error> {
        self.take_quote_locks(quote_ids).await
    }
}

#[async_trait]
impl<RM> DbTransactionFinalizer for SQLTransaction<RM>
where
    RM: DatabasePool + 'static,
{
    type Err = Error;

    async fn commit(mut self: Box<Self>) -> Result<(), Error> {
        #[cfg(feature = "prometheus")]
        let metrics = MintMetricGuard::new("transaction_commit");

        // The totals go with the COMMIT, so their row stays locked for as little as the
        // database allows. On an error, dropping the transaction rolls it back.
        let result = match self.keyset_delta_statements() {
            Ok(statements) => self.inner.commit_after(statements).await,
            Err(err) => Err(err),
        };

        #[cfg(feature = "prometheus")]
        {
            metrics.record(result.is_ok());
        }

        Ok(result?)
    }

    async fn rollback(self: Box<Self>) -> Result<(), Error> {
        #[cfg(feature = "prometheus")]
        let metrics = MintMetricGuard::new("transaction_rollback");

        let result = self.inner.rollback().await;

        #[cfg(feature = "prometheus")]
        {
            metrics.record(result.is_ok());
        }
        Ok(result?)
    }
}

#[async_trait]
impl<RM> MintDatabase<Error> for SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    async fn begin_transaction(
        &self,
    ) -> Result<Box<dyn database::MintTransaction<Error> + Send + Sync>, Error> {
        Self::begin_transaction_from_pool(&self.pool).await
    }
}

#[cfg(all(test, feature = "prometheus"))]
mod tests {
    use std::fmt;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    use cdk_common::database::{DbTransactionFinalizer, Error as DatabaseError};
    use cdk_prometheus::METRICS;

    use super::SQLTransaction;
    use crate::database::{
        ConnectionWithTransaction, DatabaseConnector, DatabaseExecutor, DatabaseTransaction,
    };
    use crate::pool::{DatabaseConfig, DatabasePool, Error as PoolError, Pool};
    use crate::stmt::{Column, Statement};

    #[derive(Debug, Clone)]
    struct TestConfig {
        fail_commit: bool,
        fail_rollback: bool,
    }

    impl DatabaseConfig for TestConfig {
        fn max_size(&self) -> usize {
            1
        }

        fn default_timeout(&self) -> Duration {
            Duration::from_millis(10)
        }
    }

    #[derive(Debug)]
    struct TestResourceError;

    impl fmt::Display for TestResourceError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("test resource error")
        }
    }

    impl std::error::Error for TestResourceError {}

    #[derive(Debug)]
    struct TestConnection {
        fail_commit: bool,
        fail_rollback: bool,
    }

    #[async_trait::async_trait]
    impl DatabaseExecutor for TestConnection {
        fn name() -> &'static str {
            "test"
        }

        async fn execute(&self, _statement: Statement) -> Result<usize, DatabaseError> {
            Ok(0)
        }

        async fn fetch_one(
            &self,
            _statement: Statement,
        ) -> Result<Option<Vec<Column>>, DatabaseError> {
            Ok(None)
        }

        async fn fetch_all(
            &self,
            _statement: Statement,
        ) -> Result<Vec<Vec<Column>>, DatabaseError> {
            Ok(Vec::new())
        }

        async fn pluck(&self, _statement: Statement) -> Result<Option<Column>, DatabaseError> {
            Ok(None)
        }

        async fn batch(&self, _statement: Statement) -> Result<(), DatabaseError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TestTransaction;

    #[async_trait::async_trait]
    impl DatabaseTransaction<TestConnection> for TestTransaction {
        async fn commit(conn: &mut TestConnection) -> Result<(), DatabaseError> {
            if conn.fail_commit {
                Err(DatabaseError::Internal("commit failed".to_owned()))
            } else {
                Ok(())
            }
        }

        async fn begin(_conn: &mut TestConnection) -> Result<(), DatabaseError> {
            Ok(())
        }

        async fn rollback(conn: &mut TestConnection) -> Result<(), DatabaseError> {
            if conn.fail_rollback {
                Err(DatabaseError::Internal("rollback failed".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    impl DatabaseConnector for TestConnection {
        type Transaction = TestTransaction;
    }

    #[derive(Debug)]
    struct TestPool;

    impl DatabasePool for TestPool {
        type Connection = TestConnection;
        type Config = TestConfig;
        type Error = TestResourceError;

        fn new_resource(
            config: &Self::Config,
            _stale: Arc<AtomicBool>,
            _timeout: Duration,
        ) -> Result<Self::Connection, PoolError<Self::Error>> {
            Ok(TestConnection {
                fail_commit: config.fail_commit,
                fail_rollback: config.fail_rollback,
            })
        }
    }

    async fn new_transaction(fail_commit: bool, fail_rollback: bool) -> SQLTransaction<TestPool> {
        let pool = Pool::<TestPool>::new(TestConfig {
            fail_commit,
            fail_rollback,
        });
        let conn = pool
            .get()
            .await
            .expect("test resource should be checked out");
        let inner = ConnectionWithTransaction::new(conn)
            .await
            .expect("test transaction should begin");

        SQLTransaction {
            inner,
            keyset_deltas: Default::default(),
        }
    }

    fn labels_match(
        metric: &cdk_prometheus::prometheus::proto::Metric,
        labels: &[(&str, &str)],
    ) -> bool {
        labels.iter().all(|(name, value)| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == *name && label.value() == *value)
        })
    }

    fn counter_value(name: &str, labels: &[(&str, &str)]) -> f64 {
        for family in METRICS.registry().gather() {
            if family.name() != name {
                continue;
            }

            for metric in family.get_metric() {
                if labels_match(metric, labels) {
                    return metric.get_counter().value();
                }
            }
        }

        0.0
    }

    fn gauge_value(name: &str, labels: &[(&str, &str)]) -> f64 {
        for family in METRICS.registry().gather() {
            if family.name() != name {
                continue;
            }

            for metric in family.get_metric() {
                if labels_match(metric, labels) {
                    return metric.get_gauge().value();
                }
            }
        }

        0.0
    }

    fn histogram_count(name: &str, labels: &[(&str, &str)]) -> f64 {
        for family in METRICS.registry().gather() {
            if family.name() != name {
                continue;
            }

            for metric in family.get_metric() {
                if labels_match(metric, labels) {
                    return metric.get_histogram().sample_count() as f64;
                }
            }
        }

        0.0
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transaction_commit_records_success_duration_and_balances_in_flight() {
        let _lock = crate::metrics_test_lock::lock().await;
        let operation = "transaction_commit";
        let labels = [("operation", operation), ("status", "success")];
        let in_flight_labels = [("operation", operation)];

        let success_before = counter_value("cdk_mint_operations_total", &labels);
        let duration_count_before = histogram_count("cdk_mint_operation_duration_seconds", &labels);
        let in_flight_before = gauge_value("cdk_mint_in_flight_requests", &in_flight_labels);

        let tx = new_transaction(false, false).await;
        Box::new(tx)
            .commit()
            .await
            .expect("transaction commit should succeed");

        assert_eq!(
            counter_value("cdk_mint_operations_total", &labels),
            success_before + 1.0
        );
        assert_eq!(
            histogram_count("cdk_mint_operation_duration_seconds", &labels),
            duration_count_before + 1.0
        );
        assert_eq!(
            gauge_value("cdk_mint_in_flight_requests", &in_flight_labels),
            in_flight_before
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transaction_commit_records_error_duration_and_balances_in_flight() {
        let _lock = crate::metrics_test_lock::lock().await;
        let operation = "transaction_commit";
        let labels = [("operation", operation), ("status", "error")];
        let in_flight_labels = [("operation", operation)];

        let error_before = counter_value("cdk_mint_operations_total", &labels);
        let duration_count_before = histogram_count("cdk_mint_operation_duration_seconds", &labels);
        let in_flight_before = gauge_value("cdk_mint_in_flight_requests", &in_flight_labels);

        let tx = new_transaction(true, false).await;
        Box::new(tx)
            .commit()
            .await
            .expect_err("transaction commit should fail");

        assert_eq!(
            counter_value("cdk_mint_operations_total", &labels),
            error_before + 1.0
        );
        assert_eq!(
            histogram_count("cdk_mint_operation_duration_seconds", &labels),
            duration_count_before + 1.0
        );
        assert_eq!(
            gauge_value("cdk_mint_in_flight_requests", &in_flight_labels),
            in_flight_before
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transaction_rollback_records_success_duration_and_balances_in_flight() {
        let _lock = crate::metrics_test_lock::lock().await;
        let operation = "transaction_rollback";
        let labels = [("operation", operation), ("status", "success")];
        let in_flight_labels = [("operation", operation)];

        let success_before = counter_value("cdk_mint_operations_total", &labels);
        let duration_count_before = histogram_count("cdk_mint_operation_duration_seconds", &labels);
        let in_flight_before = gauge_value("cdk_mint_in_flight_requests", &in_flight_labels);

        let tx = new_transaction(false, false).await;
        Box::new(tx)
            .rollback()
            .await
            .expect("transaction rollback should succeed");

        assert_eq!(
            counter_value("cdk_mint_operations_total", &labels),
            success_before + 1.0
        );
        assert_eq!(
            histogram_count("cdk_mint_operation_duration_seconds", &labels),
            duration_count_before + 1.0
        );
        assert_eq!(
            gauge_value("cdk_mint_in_flight_requests", &in_flight_labels),
            in_flight_before
        );
    }
}

#[cfg(test)]
mod quote_lock_tests {
    use super::*;

    #[test]
    fn quote_lock_keys_are_sorted_and_deduplicated() {
        let first = QuoteId::BASE64("YQ==".to_owned());
        let second = QuoteId::BASE64("Yg==".to_owned());
        let mut expected = vec![format!("cdk:quote:{first}"), format!("cdk:quote:{second}")];
        expected.sort();

        assert_eq!(quote_lock_keys(&[second.clone(), first, second]), expected);
    }
}
