use cdk_common::SpendingConditionVerification;
use swap_saga::SwapSaga;
use tracing::{instrument, Instrument};

use super::{Mint, SwapRequest, SwapResponse};
use crate::Error;

pub mod swap_saga;

#[cfg(test)]
mod tests;

impl Mint {
    /// Process Swap
    #[instrument(skip_all)]
    pub async fn process_swap_request(
        &self,
        swap_request: SwapRequest,
    ) -> Result<SwapResponse, Error> {
        #[cfg(feature = "prometheus")]
        let metrics = super::MintMetricGuard::new("process_swap_request");

        // The swap runs in its own task, so once it has changed anything it runs to the end, even
        // if its caller goes away (an HTTP client that hangs up drops this future). Dropped
        // halfway, a swap would leave its inputs pending until recovery at the next start. A
        // client that hung up can get its signatures back with a restore.
        //
        // The task sees the caller go when `caller` is dropped, along with this future.
        let (caller_here, caller) = tokio::sync::oneshot::channel::<()>();
        let mint = self.clone();
        let swap = async move {
            mint.run_swap(swap_request, || caller_here.is_closed())
                .await
        };
        let result = cdk_common::task::spawn(swap.instrument(tracing::Span::current()))
            .await
            .unwrap_or_else(|err| {
                if err.is_panic() {
                    // A panic carries on as if the swap had run here.
                    std::panic::resume_unwind(err.into_panic());
                }
                tracing::error!("Swap task failed: {}", err);
                Err(Error::Internal)
            });

        #[cfg(feature = "prometheus")]
        {
            metrics.record(result.is_ok());
        }

        drop(caller);
        result
    }

    /// Runs a swap from start to finish: see [`Mint::process_swap_request`].
    ///
    /// `caller_gone` says whether the caller has gone away. Checked before the setup only: a
    /// swap whose caller went away before then is skipped, as it has changed nothing yet. Under
    /// overload, that sheds the swaps whose clients gave up waiting, as dropping them used to.
    async fn run_swap(
        &self,
        swap_request: SwapRequest,
        caller_gone: impl Fn() -> bool,
    ) -> Result<SwapResponse, Error> {
        swap_request.input_amount()?;
        swap_request.output_amount()?;

        let input_proofs = swap_request.inputs();

        if input_proofs.is_empty() {
            return Err(Error::TransactionUnbalanced(
                0,
                swap_request.output_amount()?.to_u64(),
                0,
            ));
        }

        // Verify inputs (cryptographic verification, no DB needed)
        let input_verification = self.verify_inputs(input_proofs).await.map_err(|err| {
            tracing::debug!("Input verification failed: {:?}", err);
            err
        })?;

        // Verify spending conditions (NUT-10/NUT-11/NUT-14), i.e. P2PK
        // and HTLC (including SIGALL)
        swap_request.verify_spending_conditions()?;

        if caller_gone() {
            tracing::debug!("Swap skipped before its setup: the caller went away");
            return Err(Error::Internal);
        }

        // Step 1: Initialize the swap saga
        let init_saga = SwapSaga::new(self, self.localstore.clone(), self.pubsub_manager.clone());

        // Step 2: TX1 - Setup swap (verify balance + add inputs as pending + add output blinded messages)
        let setup_saga = init_saga
            .setup_swap(
                swap_request.inputs(),
                swap_request.outputs(),
                None,
                input_verification,
            )
            .await?;

        // Lets a test drop the caller between the setup and the end.
        #[cfg(test)]
        while crate::test_helpers::mint::should_fail_for("PAUSE_AFTER_SWAP_SETUP") {
            tokio::task::yield_now().await;
        }

        // Step 3: Blind sign outputs (no DB transaction)
        let signed_saga = setup_saga.sign_outputs().await?;

        // Step 4: TX2 - Finalize swap (add signatures + mark inputs spent)
        let response = signed_saga.finalize().await?;

        Ok(response)
    }
}
