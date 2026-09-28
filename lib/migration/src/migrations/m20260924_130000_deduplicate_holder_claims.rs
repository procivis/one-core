use std::collections::HashMap;
use std::collections::hash_map::Entry;

use sea_orm::{DbBackend, FromQueryResult, TransactionTrait};
use sea_orm_migration::prelude::*;
use shared_types::{ClaimId, ClaimSchemaId, CredentialId};
use time::OffsetDateTime;

use crate::datatype::uuid_char;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // A failed MySQL run can leave completed chunks committed. Keep the
        // completed parent IDs until the following migration removes this table.
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(DeduplicationProgress::Table)
                    .col(uuid_char(DeduplicationProgress::ParentId).primary_key())
                    .to_owned(),
            )
            .await?;
        let connection = manager.get_connection();
        // Preceding MySQL DDL may have committed the runner's pinned transaction.
        // A nested SeaORM transaction would then create a savepoint without an
        // active transaction. Commit each replacement chunk on that connection
        // so a large migration does not hold locks and undo rows until the end.
        // Completed chunks are safe to revisit if the migration is restarted.
        if manager.get_database_backend() == DbBackend::MySql
            && matches!(connection, SchemaManagerConnection::Transaction(_))
        {
            // Close any runner transaction before the read phase as well. The
            // migration lock is connection-scoped on MySQL, not transaction-scoped.
            connection.execute_unprepared("COMMIT").await?;
            deduplicate(connection, true).await
        } else {
            // PostgreSQL's migration lock and SQLite's migration serialization
            // require the runner's enclosing transaction to stay open.
            let transaction = connection.begin().await?;
            match deduplicate(&transaction, false).await {
                Ok(()) => transaction.commit().await,
                Err(error) => {
                    transaction.rollback().await?;
                    Err(error)
                }
            }
        }
    }
}

#[derive(FromQueryResult)]
struct BatchParent {
    id: CredentialId,
    created_date: OffsetDateTime,
}

#[derive(FromQueryResult)]
struct ClaimRow {
    id: ClaimId,
    claim_schema_id: ClaimSchemaId,
    path: String,
    value: Option<Vec<u8>>,
    selectively_disclosable: bool,
}

/// Fetch one unprocessed holder parent at a time. New parents committed before
/// the final lookup can join the work, and completed parents are skipped on retry.
async fn deduplicate(
    connection: &impl ConnectionTrait,
    commit_each_chunk: bool,
) -> Result<(), DbErr> {
    let mut completed = 0;
    let mut cursor: Option<BatchParent> = None;
    loop {
        let Some(parent) = next_batch_parent(connection, cursor.as_ref()).await? else {
            if cursor.take().is_some() {
                // Catch a newly inserted parent with an older timestamp.
                continue;
            }
            break;
        };
        let (duplicates, deleted) =
            deduplicate_batch(connection, &parent, commit_each_chunk).await?;
        connection
            .execute(
                &Query::insert()
                    .into_table(DeduplicationProgress::Table)
                    .columns([DeduplicationProgress::ParentId])
                    .values([parent.id.into()])
                    .map_err(|error| DbErr::Migration(error.to_string()))?
                    .to_owned(),
            )
            .await?;
        completed += 1;
        tracing::debug!(
            parent_id = %parent.id,
            completed,
            duplicates,
            deleted,
            "Deduplicated holder batch claims"
        );
        cursor = Some(parent);
    }
    Ok(())
}

async fn next_batch_parent(
    connection: &impl ConnectionTrait,
    cursor: Option<&BatchParent>,
) -> Result<Option<BatchParent>, DbErr> {
    let mut unprocessed = Query::select()
        .columns([
            (Credential::Table, Credential::Id),
            (Credential::Table, Credential::CreatedDate),
        ])
        .from(Credential::Table)
        .left_join(
            DeduplicationProgress::Table,
            Expr::col((Credential::Table, Credential::Id)).equals((
                DeduplicationProgress::Table,
                DeduplicationProgress::ParentId,
            )),
        )
        .and_where(Expr::col((Credential::Table, Credential::Role)).eq("HOLDER"))
        .and_where(Expr::col((Credential::Table, Credential::Type)).eq("BATCH_PARENT"))
        .and_where(
            Expr::col((
                DeduplicationProgress::Table,
                DeduplicationProgress::ParentId,
            ))
            .is_null(),
        )
        .order_by((Credential::Table, Credential::CreatedDate), Order::Asc)
        .order_by((Credential::Table, Credential::Id), Order::Asc)
        .limit(1)
        .to_owned();
    if let Some(cursor) = cursor {
        unprocessed.cond_where(
            Condition::any()
                .add(
                    Expr::col((Credential::Table, Credential::CreatedDate)).gt(cursor.created_date),
                )
                .add(
                    Condition::all()
                        .add(
                            Expr::col((Credential::Table, Credential::CreatedDate))
                                .eq(cursor.created_date),
                        )
                        .add(Expr::col((Credential::Table, Credential::Id)).gt(cursor.id)),
                ),
        );
    }
    BatchParent::find_by_statement(connection.get_database_backend().build(&unprocessed))
        .one(connection)
        .await
}

/// Include deleted, expired and consumed items: their claims and proofs still exist.
fn batch_item_ids(parent: &BatchParent) -> SelectStatement {
    Query::select()
        .column(Credential::Id)
        .from(Credential::Table)
        .and_where(Expr::col(Credential::ParentId).eq(parent.id))
        .and_where(Expr::col(Credential::Role).eq("HOLDER"))
        .and_where(Expr::col(Credential::Type).eq("BATCH_ITEM"))
        .to_owned()
}

/// Read both current item claims and historical claims retained only by proofs.
/// The oldest claim row wins, with its ID breaking timestamp ties.
async fn load_batch_claims(
    connection: &impl ConnectionTrait,
    parent: &BatchParent,
) -> Result<Vec<ClaimRow>, DbErr> {
    let mut all_claim_ids = Query::select()
        .column(ClaimReference::ClaimId)
        .from(Alias::new("credential_claim"))
        .and_where(Expr::col(ClaimReference::CredentialId).in_subquery(batch_item_ids(parent)))
        .to_owned();
    let proof_claim_ids = Query::select()
        .column(ClaimReference::ClaimId)
        .from(Alias::new("proof_claim"))
        .and_where(Expr::col(ClaimReference::CredentialId).in_subquery(batch_item_ids(parent)))
        .to_owned();
    all_claim_ids.union(UnionType::Distinct, proof_claim_ids);
    let claims_oldest_first = Query::select()
        .columns([
            Claim::Id,
            Claim::ClaimSchemaId,
            Claim::Path,
            Claim::Value,
            Claim::SelectivelyDisclosable,
        ])
        .from(Claim::Table)
        .and_where(Expr::col(Claim::Id).in_subquery(all_claim_ids))
        .order_by(Claim::CreatedDate, Order::Asc)
        .order_by(Claim::Id, Order::Asc)
        .to_owned();
    ClaimRow::find_by_statement(
        connection
            .get_database_backend()
            .build(&claims_oldest_first),
    )
    .all(connection)
    .await
}

/// Compare exact bytes and all semantic fields in Rust, avoiding database collation
/// differences. Timestamps belong to the canonical row and are not part of identity.
///
/// For example, a chunk mapping both `duplicate-a` and `duplicate-b` to `canonical`
/// updates credential associations as follows (readable names stand in for bound UUIDs):
///
/// ```sql
/// UPDATE credential_claim
/// SET claim_id = CASE
///     WHEN claim_id = 'duplicate-a' THEN 'canonical'
///     WHEN claim_id = 'duplicate-b' THEN 'canonical'
///     ELSE claim_id
/// END
/// WHERE claim_id IN ('duplicate-a', 'duplicate-b')
///   AND credential_id IN (
///       SELECT id FROM credential
///       WHERE parent_id = 'batch-parent'
///         AND role = 'HOLDER'
///         AND type = 'BATCH_ITEM'
///   );
/// ```
///
/// Each credential has only one claim per path, so these duplicate IDs belong to
/// different credentials. Updating only `claim_id` keeps the associations distinct.
/// The same mapping is applied to `proof_claim`, preserving both `credential_id`
/// and `proof_id`.
/// Finally, duplicate claim rows are deleted only if neither link table references them.
async fn deduplicate_batch(
    connection: &impl ConnectionTrait,
    parent: &BatchParent,
    commit_each_chunk: bool,
) -> Result<(usize, u64), DbErr> {
    let mut canonical = HashMap::new();
    let mut duplicates = Vec::new();
    for claim in load_batch_claims(connection, parent).await? {
        let contents = (
            claim.claim_schema_id,
            claim.path,
            claim.value,
            claim.selectively_disclosable,
        );
        match canonical.entry(contents) {
            Entry::Vacant(entry) => {
                entry.insert(claim.id);
            }
            Entry::Occupied(entry) => {
                duplicates.push((claim.id, *entry.get()));
            }
        }
    }
    let mut deleted = 0;
    // Bound CASE expressions and bind counts, and avoid one round trip per claim.
    for replacements in duplicates.chunks(200) {
        if commit_each_chunk {
            connection.execute_unprepared("START TRANSACTION").await?;
        }
        let result = async {
            remap_batch_references(connection, parent, replacements).await?;
            delete_unreferenced_claims(connection, replacements).await
        }
        .await;
        if commit_each_chunk {
            connection
                .execute_unprepared(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .await?;
        }
        deleted += result?;
    }
    Ok((duplicates.len(), deleted))
}

/// Update only claim IDs in references belonging to this batch, preserving proof
/// and credential IDs. Claim paths are unique within each credential, so remapping
/// equal claims across items cannot collide with an existing association.
async fn remap_batch_references(
    connection: &impl ConnectionTrait,
    parent: &BatchParent,
    replacements: &[(ClaimId, ClaimId)],
) -> Result<(), DbErr> {
    let batch_references = Condition::all()
        .add(Expr::col(ClaimReference::ClaimId).is_in(replacements.iter().map(|(id, _)| *id)))
        .add(Expr::col(ClaimReference::CredentialId).in_subquery(batch_item_ids(parent)));
    let mut canonical_ids = CaseStatement::new();
    for &(duplicate_id, canonical_id) in replacements {
        canonical_ids = canonical_ids.case(
            Expr::col(ClaimReference::ClaimId).eq(duplicate_id),
            canonical_id,
        );
    }
    let canonical_ids = canonical_ids.finally(Expr::col(ClaimReference::ClaimId));

    for table in ["credential_claim", "proof_claim"] {
        let update_references = Query::update()
            .table(Alias::new(table))
            .value(ClaimReference::ClaimId, canonical_ids.clone())
            .cond_where(batch_references.clone())
            .to_owned();
        connection.execute(&update_references).await?;
    }
    Ok(())
}

/// An explicitly shared duplicate may still be used outside this batch; keep it
/// until its last credential and proof references are gone.
async fn delete_unreferenced_claims(
    connection: &impl ConnectionTrait,
    replacements: &[(ClaimId, ClaimId)],
) -> Result<u64, DbErr> {
    let credential_references = Query::select()
        .expr(Expr::value(1))
        .from(Alias::new("credential_claim"))
        .and_where(
            Expr::col((Alias::new("credential_claim"), ClaimReference::ClaimId))
                .equals((Claim::Table, Claim::Id)),
        )
        .to_owned();
    let proof_references = Query::select()
        .expr(Expr::value(1))
        .from(Alias::new("proof_claim"))
        .and_where(
            Expr::col((Alias::new("proof_claim"), ClaimReference::ClaimId))
                .equals((Claim::Table, Claim::Id)),
        )
        .to_owned();
    let unreferenced_claim = Query::delete()
        .from_table(Claim::Table)
        .and_where(Expr::col(Claim::Id).is_in(replacements.iter().map(|(id, _)| *id)))
        .and_where(Expr::exists(credential_references).not())
        .and_where(Expr::exists(proof_references).not())
        .to_owned();
    Ok(connection
        .execute(&unreferenced_claim)
        .await?
        .rows_affected())
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    Id,
    ParentId,
    Role,
    Type,
    CreatedDate,
}

#[derive(DeriveIden)]
#[expect(clippy::enum_variant_names)]
enum Claim {
    Table,
    Id,
    ClaimSchemaId,
    Path,
    Value,
    SelectivelyDisclosable,
    CreatedDate,
}

#[derive(DeriveIden)]
enum ClaimReference {
    CredentialId,
    ClaimId,
}

#[derive(DeriveIden)]
enum DeduplicationProgress {
    #[sea_orm(iden = "holder_claim_deduplication_progress")]
    Table,
    ParentId,
}
