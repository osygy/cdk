use cdk_common::database::Error;
use cdk_sql_common::run_db_operation;
use cdk_sql_common::stmt::{Column, Statement};
use futures_util::future::{try_join, try_join_all};
use futures_util::{pin_mut, TryStreamExt};
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, Error as PgError, Statement as PgStatement};

use crate::cache::StatementCache;
use crate::value::PgValue;

/// A connection's prepared statements, by SQL text.
pub(crate) type Statements = StatementCache<PgStatement>;

#[inline(always)]
fn to_pgsql_error(err: PgError) -> Error {
    if let Some(err) = err.as_db_error() {
        let code = err.code().to_owned();
        if code == SqlState::INTEGRITY_CONSTRAINT_VIOLATION || code == SqlState::UNIQUE_VIOLATION {
            return Error::Duplicate;
        }

        if code == SqlState::T_R_DEADLOCK_DETECTED {
            return Error::Locked;
        }
    }

    Error::Database(Box::new(err))
}

/// Returns the prepared statement for `sql`, preparing it on this connection the first time.
async fn prepare_cached(
    conn: &Client,
    statements: &Statements,
    sql: &str,
) -> Result<PgStatement, Error> {
    if let Some(prepared) = statements.get(sql) {
        return Ok(prepared);
    }
    let prepared = conn.prepare(sql).await.map_err(to_pgsql_error)?;
    Ok(statements.insert(sql, prepared))
}

/// Maps a statement's error, and forgets the statement if the server won't run it as prepared
/// any more: its result columns changed under it (`cached plan must not change result type`,
/// after another mint migrated a shared database), or the server no longer has it. The request
/// fails, and the next one prepares the statement again. No retry: in a transaction, the error
/// has already aborted it. 0A000 also means other unsupported features; forgetting the
/// statement then only costs a prepare.
fn forget_if_stale<'a>(
    statements: &'a Statements,
    sql: &'a str,
) -> impl FnOnce(PgError) -> Error + 'a {
    move |err| {
        let stale = err.code().is_some_and(|code| {
            *code == SqlState::FEATURE_NOT_SUPPORTED
                || *code == SqlState::INVALID_SQL_STATEMENT_NAME
        });
        if stale {
            statements.remove(sql);
        }
        to_pgsql_error(err)
    }
}

#[inline(always)]
pub async fn pg_batch(conn: &Client, statement: Statement) -> Result<(), Error> {
    let (sql, _placeholder_values) = statement.to_sql()?;

    run_db_operation(&sql, conn.batch_execute(&sql), to_pgsql_error).await
}

#[inline(always)]
pub async fn pg_execute(
    conn: &Client,
    statements: &Statements,
    statement: Statement,
) -> Result<usize, Error> {
    let (sql, placeholder_values) = statement.to_sql()?;
    let prepared_statement = prepare_cached(conn, statements, &sql).await?;

    run_db_operation(
        &sql,
        async {
            conn.execute_raw(
                &prepared_statement,
                placeholder_values
                    .iter()
                    .map(|x| x.into())
                    .collect::<Vec<PgValue>>(),
            )
            .await
            .map(|x| x as usize)
        },
        forget_if_stale(statements, &sql),
    )
    .await
}

/// Runs `statements`, then COMMIT, sent to Postgres in one go. Each statement is prepared first;
/// then their executions and the COMMIT go out together, without waiting for each reply in turn
/// (tokio-postgres pipelines requests polled together, in the order they're polled). Postgres
/// runs them in that order, so a row lock a statement takes is held only until the COMMIT right
/// behind it, with no round trip in between. If a statement fails, Postgres aborts the
/// transaction and answers the COMMIT with a rollback, and the statement's error is returned.
pub async fn pg_execute_then_commit(
    conn: &Client,
    prepared_statements: &Statements,
    statements: Vec<Statement>,
) -> Result<(), Error> {
    // `try_join_all` polls up to 30 futures in order, and so sends their requests in order;
    // beyond that it doesn't promise to. A transaction has one statement per keyset it touched,
    // so this is only a safeguard.
    const PIPELINED_MAX: usize = 30;
    if statements.len() > PIPELINED_MAX {
        for statement in statements {
            pg_execute(conn, prepared_statements, statement).await?;
        }
        return run_db_operation("COMMIT", conn.batch_execute("COMMIT"), to_pgsql_error).await;
    }

    let mut prepared = Vec::with_capacity(statements.len());
    for statement in statements {
        let (sql, placeholder_values) = statement.to_sql()?;
        let prepared_statement = prepare_cached(conn, prepared_statements, &sql).await?;
        prepared.push((sql, prepared_statement, placeholder_values));
    }

    let executions = prepared
        .iter()
        .map(|(sql, prepared_statement, placeholder_values)| {
            run_db_operation(
                sql,
                conn.execute_raw(
                    prepared_statement,
                    placeholder_values
                        .iter()
                        .map(|x| x.into())
                        .collect::<Vec<PgValue>>(),
                ),
                forget_if_stale(prepared_statements, sql),
            )
        });
    let commit = run_db_operation("COMMIT", conn.batch_execute("COMMIT"), to_pgsql_error);

    try_join(try_join_all(executions), commit).await?;
    Ok(())
}

#[inline(always)]
pub async fn pg_fetch_one(
    conn: &Client,
    statements: &Statements,
    statement: Statement,
) -> Result<Option<Vec<Column>>, Error> {
    let (sql, placeholder_values) = statement.to_sql()?;
    let prepared_statement = prepare_cached(conn, statements, &sql).await?;

    run_db_operation(
        &sql,
        async {
            let stream = conn
                .query_raw(
                    &prepared_statement,
                    placeholder_values
                        .iter()
                        .map(|x| x.into())
                        .collect::<Vec<PgValue>>(),
                )
                .await?;

            pin_mut!(stream);

            stream
                .try_next()
                .await?
                .map(|row| {
                    (0..row.len())
                        .map(|i| row.try_get::<_, PgValue>(i).map(|value| value.into()))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
        },
        forget_if_stale(statements, &sql),
    )
    .await
}

#[inline(always)]
pub async fn pg_fetch_all(
    conn: &Client,
    statements: &Statements,
    statement: Statement,
) -> Result<Vec<Vec<Column>>, Error> {
    let (sql, placeholder_values) = statement.to_sql()?;
    let prepared_statement = prepare_cached(conn, statements, &sql).await?;

    run_db_operation(
        &sql,
        async {
            let stream = conn
                .query_raw(
                    &prepared_statement,
                    placeholder_values
                        .iter()
                        .map(|x| x.into())
                        .collect::<Vec<PgValue>>(),
                )
                .await?;

            pin_mut!(stream);

            let mut rows = vec![];
            while let Some(row) = stream.try_next().await? {
                rows.push(
                    (0..row.len())
                        .map(|i| row.try_get::<_, PgValue>(i).map(|value| value.into()))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }

            Ok(rows)
        },
        forget_if_stale(statements, &sql),
    )
    .await
}

#[inline(always)]
pub async fn pg_pluck(
    conn: &Client,
    statements: &Statements,
    statement: Statement,
) -> Result<Option<Column>, Error> {
    let (sql, placeholder_values) = statement.to_sql()?;
    let prepared_statement = prepare_cached(conn, statements, &sql).await?;

    run_db_operation(
        &sql,
        async {
            let stream = conn
                .query_raw(
                    &prepared_statement,
                    placeholder_values
                        .iter()
                        .map(|x| x.into())
                        .collect::<Vec<PgValue>>(),
                )
                .await?;

            pin_mut!(stream);

            stream
                .try_next()
                .await?
                .map(|row| row.try_get::<_, PgValue>(0).map(|value| value.into()))
                .transpose()
        },
        forget_if_stale(statements, &sql),
    )
    .await
}
