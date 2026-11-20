//! Signatures database implementation

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use async_trait::async_trait;
use cdk_common::database::{self, Error, MintSignatureTransaction, MintSignaturesDatabase};
use cdk_common::quote_id::QuoteId;
use cdk_common::util::unix_time;
use cdk_common::{Amount, BlindSignature, BlindSignatureDleq, Id, PublicKey, SecretKey};

use super::proofs::sql_row_to_hashmap_amount;
use super::{values_rows, SQLMintDatabase, SQLTransaction, ROWS_PER_STATEMENT};
use crate::pool::DatabasePool;
use crate::stmt::{query, Column};
use crate::{column_as_nullable_string, column_as_number, column_as_string, unpack_into};

pub(crate) fn sql_row_to_blind_signature(row: Vec<Column>) -> Result<BlindSignature, Error> {
    unpack_into!(
        let (
            keyset_id, amount, c, dleq_e, dleq_s
        ) = row
    );

    let dleq = match (
        column_as_nullable_string!(dleq_e),
        column_as_nullable_string!(dleq_s),
    ) {
        (Some(e), Some(s)) => Some(BlindSignatureDleq {
            e: SecretKey::from_hex(e)?,
            s: SecretKey::from_hex(s)?,
        }),
        _ => None,
    };

    let amount: u64 = column_as_number!(amount);

    Ok(BlindSignature {
        amount: Amount::from(amount),
        keyset_id: column_as_string!(keyset_id, Id::from_str, Id::from_bytes),
        c: column_as_string!(c, PublicKey::from_hex, PublicKey::from_slice),
        dleq,
    })
}

#[async_trait]
impl<RM> MintSignatureTransaction for SQLTransaction<RM>
where
    RM: DatabasePool + 'static,
{
    type Err = Error;

    async fn add_blind_signatures(
        &mut self,
        blinded_messages: &[PublicKey],
        blind_signatures: &[BlindSignature],
        quote_id: Option<QuoteId>,
    ) -> Result<(), Self::Err> {
        let current_time = unix_time();

        if blinded_messages.len() != blind_signatures.len() {
            return Err(database::Error::Internal(
                "Mismatched array lengths for blinded messages and blind signatures".to_string(),
            ));
        }

        // Select all existing rows for the given blinded messages at once
        let mut existing_rows = query(
            r#"
            SELECT blinded_message, c, dleq_e, dleq_s
            FROM blind_signature
            WHERE blinded_message IN (:blinded_messages)
            ORDER BY blinded_message
            FOR UPDATE
            "#,
        )?
        .bind_vec(
            "blinded_messages",
            blinded_messages
                .iter()
                .map(|message| message.to_bytes().to_vec())
                .collect(),
        )?
        .fetch_all(&self.inner)
        .await?
        .into_iter()
        .map(|mut row| {
            Ok((
                column_as_string!(&row.remove(0), PublicKey::from_hex, PublicKey::from_slice),
                (row[0].clone(), row[1].clone(), row[2].clone()),
            ))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;

        let mut ordered_signatures = blinded_messages
            .iter()
            .zip(blind_signatures)
            .enumerate()
            .collect::<Vec<_>>();
        ordered_signatures.sort_unstable_by(|(_, (left, _)), (_, (right, _))| {
            left.to_bytes().cmp(&right.to_bytes())
        });

        // Check every row before writing any: a message signed already is a duplicate, and so
        // is one that comes twice in the request. The rest are written together below.
        let mut seen = HashSet::new();
        for (_, (message, _)) in &ordered_signatures {
            if !seen.insert(*message) {
                return Err(database::Error::Duplicate);
            }
            match existing_rows.remove(*message) {
                // Unknown blind message: inserted with all columns.
                None => {}
                // Blind message with no c: its c, dleq_e and dleq_s filled in.
                Some((Column::Null, _, _)) => {}
                Some(_) => {
                    // Blind message already has c: Error
                    tracing::error!(
                        "Attempting to add signature to message already signed {}",
                        message
                    );

                    return Err(database::Error::Duplicate);
                }
            }
        }

        // Many rows to a statement, still in blinded-message order, keeping the request's order
        // index. One upsert does both: a new message is inserted with every column, and a pending
        // one (in the table, its c NULL) gets the columns the UPDATE used to set.
        let quote_id = quote_id.map(|q| q.to_string());
        for chunk in ordered_signatures.chunks(ROWS_PER_STATEMENT) {
            let sql = format!(
                r#"
                INSERT INTO blind_signature
                (blinded_message, amount, keyset_id, c, quote_id, dleq_e, dleq_s, created_time, signed_time, order_index)
                VALUES {}
                ON CONFLICT (blinded_message) DO UPDATE
                SET c = excluded.c, dleq_e = excluded.dleq_e, dleq_s = excluded.dleq_s,
                    signed_time = excluded.signed_time, amount = excluded.amount
                "#,
                values_rows(chunk.len(), |i| {
                    format!(
                    "(:blinded_message{i}, :amount{i}, :keyset_id{i}, :c{i}, :quote_id, :dleq_e{i}, \
                     :dleq_s{i}, :created_time, :signed_time, :order_index{i})"
                )
                })
            );
            let mut stmt = query(&sql)?
                .bind("quote_id", quote_id.clone())
                .bind("created_time", current_time as i64)
                .bind("signed_time", current_time as i64);
            for (row, (i, (message, signature))) in chunk.iter().enumerate() {
                stmt = stmt
                    .bind(format!("blinded_message{row}"), message.to_bytes().to_vec())
                    .bind(format!("amount{row}"), u64::from(signature.amount) as i64)
                    .bind(format!("keyset_id{row}"), signature.keyset_id.to_string())
                    .bind(format!("c{row}"), signature.c.to_bytes().to_vec())
                    .bind(
                        format!("dleq_e{row}"),
                        signature.dleq.as_ref().map(|dleq| dleq.e.to_secret_hex()),
                    )
                    .bind(
                        format!("dleq_s{row}"),
                        signature.dleq.as_ref().map(|dleq| dleq.s.to_secret_hex()),
                    )
                    .bind(format!("order_index{row}"), *i as i64);
            }
            stmt.execute(&self.inner).await?;
        }

        // Written at commit (see SQLTransaction::keyset_deltas).
        for (_, (_, signature)) in &ordered_signatures {
            self.add_keyset_delta(
                signature.keyset_id.to_string(),
                u64::from(signature.amount) as i64,
                0,
                0,
            );
        }

        debug_assert!(
            existing_rows.is_empty(),
            "Unexpected existing rows remain: {:?}",
            existing_rows.keys().collect::<Vec<_>>()
        );

        if !existing_rows.is_empty() {
            tracing::error!("Did not check all existing rows");
            return Err(Error::Internal(
                "Did not check all existing rows".to_string(),
            ));
        }

        Ok(())
    }

    async fn get_blind_signatures(
        &mut self,
        blinded_messages: &[PublicKey],
    ) -> Result<Vec<Option<BlindSignature>>, Self::Err> {
        let mut blinded_signatures = query(
            r#"SELECT
                keyset_id,
                amount,
                c,
                dleq_e,
                dleq_s,
                blinded_message
            FROM
                blind_signature
            WHERE blinded_message IN (:b) AND c IS NOT NULL
            "#,
        )?
        .bind_vec(
            "b",
            blinded_messages
                .iter()
                .map(|b| b.to_bytes().to_vec())
                .collect(),
        )?
        .fetch_all(&self.inner)
        .await?
        .into_iter()
        .map(|mut row| {
            Ok((
                column_as_string!(
                    &row.pop().ok_or(Error::InvalidDbResponse)?,
                    PublicKey::from_hex,
                    PublicKey::from_slice
                ),
                sql_row_to_blind_signature(row)?,
            ))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
        Ok(blinded_messages
            .iter()
            .map(|y| blinded_signatures.remove(y))
            .collect())
    }
}

#[async_trait]
impl<RM> MintSignaturesDatabase for SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    type Err = Error;

    async fn get_blind_signatures(
        &self,
        blinded_messages: &[PublicKey],
    ) -> Result<Vec<Option<BlindSignature>>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;
        let mut blinded_signatures = query(
            r#"SELECT
                keyset_id,
                amount,
                c,
                dleq_e,
                dleq_s,
                blinded_message
            FROM
                blind_signature
            WHERE blinded_message IN (:b) AND c IS NOT NULL
            "#,
        )?
        .bind_vec(
            "b",
            blinded_messages
                .iter()
                .map(|b_| b_.to_bytes().to_vec())
                .collect(),
        )?
        .fetch_all(&*conn)
        .await?
        .into_iter()
        .map(|mut row| {
            Ok((
                column_as_string!(
                    &row.pop().ok_or(Error::InvalidDbResponse)?,
                    PublicKey::from_hex,
                    PublicKey::from_slice
                ),
                sql_row_to_blind_signature(row)?,
            ))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
        Ok(blinded_messages
            .iter()
            .map(|y| blinded_signatures.remove(y))
            .collect())
    }

    async fn get_blind_signatures_for_keyset(
        &self,
        keyset_id: &Id,
    ) -> Result<Vec<BlindSignature>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;
        Ok(query(
            r#"
            SELECT
                keyset_id,
                amount,
                c,
                dleq_e,
                dleq_s
            FROM
                blind_signature
            WHERE
                keyset_id=:keyset_id AND c IS NOT NULL
            "#,
        )?
        .bind("keyset_id", keyset_id.to_string())
        .fetch_all(&*conn)
        .await?
        .into_iter()
        .map(sql_row_to_blind_signature)
        .collect::<Result<Vec<BlindSignature>, _>>()?)
    }

    /// Get [`BlindSignature`]s for quote
    async fn get_blind_signatures_for_quote(
        &self,
        quote_id: &QuoteId,
    ) -> Result<Vec<BlindSignature>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;
        Ok(query(
            r#"
            SELECT
                keyset_id,
                amount,
                c,
                dleq_e,
                dleq_s
            FROM
                blind_signature
            WHERE
                quote_id=:quote_id AND c IS NOT NULL
            ORDER BY order_index ASC
            "#,
        )?
        .bind("quote_id", quote_id.to_string())
        .fetch_all(&*conn)
        .await?
        .into_iter()
        .map(sql_row_to_blind_signature)
        .collect::<Result<Vec<BlindSignature>, _>>()?)
    }

    /// Get total proofs redeemed by keyset id
    async fn get_total_issued(&self) -> Result<HashMap<Id, Amount>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;
        query(
            r#"
            SELECT
                keyset_id,
                total_issued as amount
            FROM
                keyset_amounts
        "#,
        )?
        .fetch_all(&*conn)
        .await?
        .into_iter()
        .map(sql_row_to_hashmap_amount)
        .collect()
    }

    async fn get_blinded_secrets_by_operation_id(
        &self,
        operation_id: &uuid::Uuid,
    ) -> Result<Vec<PublicKey>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;
        query(
            r#"
            SELECT
                blinded_message
            FROM
                blind_signature
            WHERE
                operation_id = :operation_id
            "#,
        )?
        .bind("operation_id", operation_id.to_string())
        .fetch_all(&*conn)
        .await?
        .into_iter()
        .map(|row| -> Result<PublicKey, Error> {
            Ok(column_as_string!(
                &row[0],
                PublicKey::from_hex,
                PublicKey::from_slice
            ))
        })
        .collect::<Result<Vec<_>, _>>()
    }
}
