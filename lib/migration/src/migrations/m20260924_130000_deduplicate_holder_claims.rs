use std::collections::HashMap;
use std::collections::hash_map::Entry;

use sea_orm::{DbBackend, FromQueryResult, TransactionTrait};
use sea_orm_migration::prelude::*;
use shared_types::{ClaimId, ClaimSchemaId, CredentialId};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        // Preceding MySQL DDL may have committed the runner's pinned transaction.
        // A nested SeaORM transaction would then create a savepoint without an
        // active transaction, so start a real transaction on that connection.
        if manager.get_database_backend() == DbBackend::MySql
            && matches!(connection, SchemaManagerConnection::Transaction(_))
        {
            connection.execute_unprepared("START TRANSACTION").await?;
            let result = deduplicate(connection).await;
            connection
                .execute_unprepared(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .await?;
            result
        } else {
            let transaction = connection.begin().await?;
            match deduplicate(&transaction).await {
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
}

#[derive(FromQueryResult)]
struct ClaimRow {
    id: ClaimId,
    claim_schema_id: ClaimSchemaId,
    path: String,
    value: Option<Vec<u8>>,
    selectively_disclosable: bool,
}

/// Process holder parents oldest first. Each batch has its own canonical claims;
/// other roles and unrelated credentials retain their existing associations.
async fn deduplicate(connection: &impl ConnectionTrait) -> Result<(), DbErr> {
    let parents_oldest_first = Query::select()
        .column(Credential::Id)
        .from(Credential::Table)
        .and_where(Expr::col(Credential::Role).eq("HOLDER"))
        .and_where(Expr::col(Credential::Type).eq("BATCH_PARENT"))
        .order_by(Credential::CreatedDate, Order::Asc)
        .order_by(Credential::Id, Order::Asc)
        .to_owned();
    let parents = BatchParent::find_by_statement(
        connection
            .get_database_backend()
            .build(&parents_oldest_first),
    )
    .all(connection)
    .await?;
    let total = parents.len();
    for (index, parent) in parents.iter().enumerate() {
        let (duplicates, deleted) = deduplicate_batch(connection, parent).await?;
        tracing::debug!(
            parent_id = %parent.id,
            current = index + 1,
            total,
            duplicates,
            deleted,
            "Deduplicated holder batch claims"
        );
    }
    Ok(())
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
        remap_batch_references(connection, parent, replacements).await?;
        deleted += delete_unreferenced_claims(connection, replacements).await?;
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
