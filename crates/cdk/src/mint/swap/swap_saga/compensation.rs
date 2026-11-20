use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cdk_common::database::DynMintDatabase;
use cdk_common::{Error, PublicKey};
use tracing::instrument;
use uuid::Uuid;

use crate::mint::subscription::PubSubManager;

/// How many times a compensation that failed is retried before it's left to recovery at the
/// next start.
const RETRIES: u32 = 10;
/// The wait before the first retry. It doubles each time, up to [`MAX_RETRY_DELAY`]: about
/// 2.5 minutes in all.
const FIRST_RETRY_DELAY: Duration = Duration::from_millis(500);
/// The longest wait between two retries.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

#[async_trait]
pub trait CompensatingAction: Send + Sync {
    async fn execute(&self, db: &DynMintDatabase, pubsub: &PubSubManager) -> Result<(), Error>;
    fn name(&self) -> &'static str;
}

/// Compensation action to remove swap setup (both proofs and blinded messages).
///
/// This compensation is used when blind signing fails or finalization fails after
/// the setup transaction has committed. It removes:
/// - Output blinded messages (identified by blinded_secrets)
/// - Input proofs (identified by input_ys)
/// - Saga state record
///
/// This restores the database to its pre-swap state.
pub struct RemoveSwapSetup {
    /// Blinded secrets (B values) from the output blinded messages
    pub blinded_secrets: Vec<PublicKey>,
    /// Y values (public keys) from the input proofs
    pub input_ys: Vec<PublicKey>,
    /// Operation ID (saga ID) to delete
    pub operation_id: Uuid,
}

#[async_trait]
impl CompensatingAction for RemoveSwapSetup {
    #[instrument(skip_all)]
    async fn execute(&self, db: &DynMintDatabase, _pubsub: &PubSubManager) -> Result<(), Error> {
        if self.blinded_secrets.is_empty() && self.input_ys.is_empty() {
            return Ok(());
        }

        tracing::info!(
            "Compensation: Removing swap setup ({} blinded messages, {} proofs, saga {})",
            self.blinded_secrets.len(),
            self.input_ys.len(),
            self.operation_id
        );

        #[cfg(test)]
        {
            if crate::test_helpers::mint::should_fail_for("REMOVE_SWAP_SETUP") {
                return Err(Error::Database(cdk_common::database::Error::Database(
                    "Test failure: REMOVE_SWAP_SETUP".into(),
                )));
            }
        }

        let mut tx = db.begin_transaction().await?;

        // Undo only a swap that's still set up. With its saga record gone, the swap finished,
        // or something else undid it (recovery, a retry), and its inputs may belong to another
        // swap by now. Locking the record also keeps two compensations from running at once.
        if tx.get_saga_for_update(&self.operation_id).await?.is_none() {
            tracing::info!(
                "Compensation: swap {} already finished or undone, nothing to remove",
                self.operation_id
            );
            tx.rollback().await?;
            return Ok(());
        }

        // Remove blinded messages (outputs)
        if !self.blinded_secrets.is_empty() {
            tx.delete_blinded_messages(&self.blinded_secrets).await?;
        }

        // Remove proofs (inputs)
        if !self.input_ys.is_empty() {
            tx.remove_proofs(&self.input_ys, None).await?;
        }

        // Delete saga state record
        if let Err(e) = tx.delete_saga(&self.operation_id).await {
            tracing::warn!(
                "Failed to delete saga {} during compensation: {}",
                self.operation_id,
                e
            );
            // Continue anyway - saga cleanup is best-effort
        }

        tx.commit().await?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RemoveSwapSetup"
    }
}

/// Retries compensations that failed, in the background, waiting longer each time.
pub(crate) async fn retry_in_background(
    mut compensations: VecDeque<Box<dyn CompensatingAction>>,
    db: DynMintDatabase,
    pubsub: Arc<PubSubManager>,
) {
    let mut delay = FIRST_RETRY_DELAY;

    for attempt in 1..=RETRIES {
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(MAX_RETRY_DELAY);

        let mut failed = VecDeque::new();
        while let Some(compensation) = compensations.pop_front() {
            if let Err(e) = compensation.execute(&db, &pubsub).await {
                tracing::warn!(
                    "Compensation {} failed again (retry {} of {}): {}",
                    compensation.name(),
                    attempt,
                    RETRIES,
                    e
                );
                failed.push_back(compensation);
            }
        }

        if failed.is_empty() {
            tracing::info!("Compensations succeeded on retry {}", attempt);
            return;
        }
        compensations = failed;
    }

    tracing::error!(
        "{} compensations still failing after {} retries; left to recovery at the next start",
        compensations.len(),
        RETRIES
    );
}
