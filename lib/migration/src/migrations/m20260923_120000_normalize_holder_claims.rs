use std::collections::{HashMap, HashSet};

use sea_orm::{DbBackend, FromQueryResult, TransactionTrait};
use sea_orm_migration::prelude::*;
use shared_types::{ClaimId, ClaimSchemaId, CredentialId, CredentialSchemaId, ProofId};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        // SeaORM implements nested transactions with SAVEPOINT. MySQL DDL
        // commits the runner's outer transaction without resetting SQLx's nesting
        // depth, so begin() would issue a savepoint outside an active transaction.
        // Start a real transaction on the runner's pinned connection instead.
        // The migration regression test exercises rollback after preceding DDL.
        if manager.get_database_backend() == DbBackend::MySql
            && matches!(connection, SchemaManagerConnection::Transaction(_))
        {
            connection.execute_unprepared("START TRANSACTION").await?;
            let result = normalize(connection).await;
            connection
                .execute_unprepared(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .await?;
            result
        } else {
            let transaction = connection.begin().await?;
            match normalize(&transaction).await {
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
struct CredentialRow {
    id: CredentialId,
    credential_schema_id: CredentialSchemaId,
}

#[derive(Clone, FromQueryResult)]
struct ClaimRow {
    id: ClaimId,
    claim_schema_id: ClaimSchemaId,
    path: String,
    value: Option<Vec<u8>>,
    selectively_disclosable: bool,
}

impl ClaimRow {
    fn matches(&self, other: &Self) -> bool {
        self.claim_schema_id == other.claim_schema_id
            && self.path == other.path
            && self.value == other.value
            && self.selectively_disclosable == other.selectively_disclosable
    }
}

#[derive(FromQueryResult)]
struct ProofClaimRow {
    proof_id: ProofId,
    credential_id: CredentialId,
    claim_id: ClaimId,
    completed_date: Option<OffsetDateTime>,
}

#[derive(FromQueryResult)]
struct BatchItemRow {
    id: CredentialId,
    consumed_at: Option<OffsetDateTime>,
}

struct BatchItemClaims {
    item: BatchItemRow,
    claims: Vec<ClaimRow>,
    copied_ids: HashMap<ClaimId, ClaimId>,
}

struct ProofClaimGroup {
    proof_id: ProofId,
    credential_id: CredentialId,
    completed_date: Option<OffsetDateTime>,
    claim_ids: Vec<ClaimId>,
}

struct ItemMatch {
    item_id: CredentialId,
    claim_ids: Vec<ClaimId>,
    consumed_at: Option<OffsetDateTime>,
    distance_ns: Option<i128>,
}

impl ItemMatch {
    fn proximity(&self) -> (bool, Option<i128>, bool) {
        (
            self.distance_ns.is_none(),
            self.distance_ns,
            self.consumed_at.is_none(),
        )
    }

    fn available_for(
        &self,
        proof_id: ProofId,
        assigned: &HashMap<CredentialId, HashSet<ProofId>>,
    ) -> bool {
        self.consumed_at.is_some()
            && assigned
                .get(&self.item_id)
                .is_none_or(|proofs| proofs.len() == 1 && proofs.contains(&proof_id))
    }
}

struct ProofCandidates {
    group: ProofClaimGroup,
    items: Vec<ItemMatch>,
}

struct ProofRemapping {
    group: ProofClaimGroup,
    target: ItemMatch,
}

#[derive(Default)]
struct ParentSummary {
    copied_items: usize,
    copied_claims: usize,
    remapped_proof_claims: usize,
    errors: Vec<String>,
}

/// Load the stored claim fields used to compare historical proof inputs.
async fn claims(
    connection: &impl ConnectionTrait,
    owner: CredentialId,
) -> Result<Vec<ClaimRow>, DbErr> {
    ClaimRow::find_by_statement(
        connection.get_database_backend().build(
            Query::select()
                .columns([
                    Claim::Id,
                    Claim::ClaimSchemaId,
                    Claim::Path,
                    Claim::Value,
                    Claim::SelectivelyDisclosable,
                ])
                .from(Claim::Table)
                .and_where(Expr::col(Claim::CredentialId).eq(owner))
                .order_by(Claim::Id, Order::Asc),
        ),
    )
    .all(connection)
    .await
}

/// Validate the legacy shape, normalize each parent, and report all mapping errors.
/// The caller rolls back the whole migration if any parent cannot be normalized.
async fn normalize(connection: &impl ConnectionTrait) -> Result<(), DbErr> {
    validate_parents_have_items(connection).await?;
    let parents = CredentialRow::find_by_statement(
        connection
            .get_database_backend()
            .build(&holder_batch_parents_query()),
    )
    .all(connection)
    .await?;
    let total = parents.len();
    let mut errors = Vec::new();
    for (index, parent) in parents.iter().enumerate() {
        let summary = normalize_parent(connection, parent).await?;
        tracing::debug!(
            parent_id = %parent.id,
            current = index + 1,
            total,
            copied_items = summary.copied_items,
            copied_claims = summary.copied_claims,
            remapped_proof_claims = summary.remapped_proof_claims,
            errors = summary.errors.len(),
            "Processed holder batch parent"
        );
        errors.extend(summary.errors);
    }
    if !errors.is_empty() {
        let report = format!("Cannot normalize holder claims:\n{}", errors.join("\n"));
        tracing::error!("{report}");
        return Err(DbErr::Migration(report));
    }
    Ok(())
}

/// Select holder batch parents oldest first, breaking creation-date ties by ID.
fn holder_batch_parents_query() -> SelectStatement {
    Query::select()
        .columns([Credential::Id, Credential::CredentialSchemaId])
        .from(Credential::Table)
        .and_where(Expr::col(Credential::Role).eq("HOLDER"))
        .and_where(Expr::col(Credential::Type).eq("BATCH_PARENT"))
        .order_by(Credential::CreatedDate, Order::Asc)
        .order_by(Credential::Id, Order::Asc)
        .to_owned()
}

/// Report every parent with stored claims but no compatible item before any writes.
async fn validate_parents_have_items(connection: &impl ConnectionTrait) -> Result<(), DbErr> {
    let parent_owned_claims = Query::select()
        .expr(Expr::value(1))
        .from(Claim::Table)
        .and_where(
            Expr::col((Claim::Table, Claim::CredentialId))
                .equals((Credential::Table, Credential::Id)),
        )
        .to_owned();
    let item = Alias::new("item");
    let compatible_batch_items = Query::select()
        .expr(Expr::value(1))
        .from_as(Credential::Table, item.clone())
        .and_where(
            Expr::col((item.clone(), Credential::ParentId))
                .equals((Credential::Table, Credential::Id)),
        )
        .and_where(
            Expr::col((item.clone(), Credential::CredentialSchemaId))
                .equals((Credential::Table, Credential::CredentialSchemaId)),
        )
        .and_where(Expr::col((item.clone(), Credential::Role)).eq("HOLDER"))
        .and_where(Expr::col((item, Credential::Type)).eq("BATCH_ITEM"))
        .to_owned();
    let parents_with_claims_without_items = holder_batch_parents_query()
        .and_where(Expr::exists(parent_owned_claims))
        .and_where(Expr::exists(compatible_batch_items).not())
        .to_owned();
    let childless = CredentialRow::find_by_statement(
        connection
            .get_database_backend()
            .build(&parents_with_claims_without_items),
    )
    .all(connection)
    .await?;
    if childless.is_empty() {
        return Ok(());
    }
    let report = format!(
        "Cannot normalize holder claims: {} holder batch parents have stored claims but no compatible batch items; parent_ids=[{}]",
        childless.len(),
        childless
            .iter()
            .map(|parent| parent.id.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    tracing::error!("{report}");
    Err(DbErr::Migration(report))
}

/// Copy missing item claims, resolve proof provenance, then remove parent claims.
/// Preserve existing item claims and explicit item references. Return counts for
/// one progress summary and mapping errors for diagnostics across all parents.
async fn normalize_parent(
    connection: &impl ConnectionTrait,
    parent: &CredentialRow,
) -> Result<ParentSummary, DbErr> {
    let parent_claims = claims(connection, parent.id).await?;
    let references = load_batch_proof_claims(connection, parent.id).await?;
    if parent_claims.is_empty() && !references.iter().any(|r| r.credential_id == parent.id) {
        return Ok(ParentSummary::default());
    }
    let (items, source_claims) = materialize_item_claims(connection, parent, parent_claims).await?;
    let groups = group_proof_claims(references);
    let (mappings, errors) = plan_proof_remapping(parent.id, groups, &items, &source_claims);
    let mut summary = ParentSummary {
        copied_items: items
            .iter()
            .filter(|item| !item.copied_ids.is_empty())
            .count(),
        copied_claims: items.iter().map(|item| item.copied_ids.len()).sum(),
        errors,
        ..Default::default()
    };
    if summary.errors.is_empty() {
        summary.remapped_proof_claims = apply_proof_remapping(connection, mappings).await?;
        delete_parent_claims(connection, parent.id).await?;
    }
    Ok(summary)
}

/// Load all proof inputs for this batch, including already concrete references.
/// Those references reserve their recorded items during timestamp matching.
async fn load_batch_proof_claims(
    connection: &impl ConnectionTrait,
    parent_id: CredentialId,
) -> Result<Vec<ProofClaimRow>, DbErr> {
    let source_credential = Alias::new("source_credential");
    let batch_proof_claims = Query::select()
        .columns([
            (ProofClaim::Table, ProofClaim::ProofId),
            (ProofClaim::Table, ProofClaim::CredentialId),
            (ProofClaim::Table, ProofClaim::ClaimId),
        ])
        .column((Proof::Table, Proof::CompletedDate))
        .from(ProofClaim::Table)
        .inner_join(
            Claim::Table,
            Expr::col((Claim::Table, Claim::Id)).equals((ProofClaim::Table, ProofClaim::ClaimId)),
        )
        .inner_join(
            Proof::Table,
            Expr::col((Proof::Table, Proof::Id)).equals((ProofClaim::Table, ProofClaim::ProofId)),
        )
        .join_as(
            JoinType::InnerJoin,
            Credential::Table,
            source_credential.clone(),
            Expr::col((source_credential.clone(), Credential::Id))
                .equals((ProofClaim::Table, ProofClaim::CredentialId)),
        )
        .cond_where(
            Condition::any()
                .add(Expr::col((ProofClaim::Table, ProofClaim::CredentialId)).eq(parent_id))
                .add(Expr::col((source_credential, Credential::ParentId)).eq(parent_id))
                .add(Expr::col((Claim::Table, Claim::CredentialId)).eq(parent_id)),
        )
        .order_by((ProofClaim::Table, ProofClaim::ClaimId), Order::Asc)
        .to_owned();
    ProofClaimRow::find_by_statement(connection.get_database_backend().build(&batch_proof_claims))
        .all(connection)
        .await
}

/// Fill only empty items with copies of the parent's stored claims. Include deleted,
/// consumed and expired items because historical proofs can still refer to them.
async fn materialize_item_claims(
    connection: &impl ConnectionTrait,
    parent: &CredentialRow,
    parent_claims: Vec<ClaimRow>,
) -> Result<(Vec<BatchItemClaims>, HashMap<ClaimId, ClaimRow>), DbErr> {
    let compatible_items_oldest_first = Query::select()
        .columns([Credential::Id, Credential::ConsumedAt])
        .from(Credential::Table)
        .and_where(Expr::col(Credential::ParentId).eq(parent.id))
        .and_where(Expr::col(Credential::Role).eq("HOLDER"))
        .and_where(Expr::col(Credential::Type).eq("BATCH_ITEM"))
        .and_where(Expr::col(Credential::CredentialSchemaId).eq(parent.credential_schema_id))
        .order_by(Credential::CreatedDate, Order::Asc)
        .order_by(Credential::Id, Order::Asc)
        .to_owned();
    let items = BatchItemRow::find_by_statement(
        connection
            .get_database_backend()
            .build(&compatible_items_oldest_first),
    )
    .all(connection)
    .await?;
    let mut source_claims: HashMap<_, _> = parent_claims
        .iter()
        .map(|claim| (claim.id, claim.clone()))
        .collect();
    let mut item_claims = Vec::with_capacity(items.len());
    for item in items {
        let mut own_claims = claims(connection, item.id).await?;
        let mut copied_ids = HashMap::new();
        source_claims.extend(own_claims.iter().map(|claim| (claim.id, claim.clone())));
        if own_claims.is_empty() {
            own_claims = copy_claims(connection, &parent_claims, item.id).await?;
            copied_ids.extend(
                parent_claims
                    .iter()
                    .zip(&own_claims)
                    .map(|(source, copy)| (source.id, copy.id)),
            );
        }
        item_claims.push(BatchItemClaims {
            item,
            claims: own_claims,
            copied_ids,
        });
    }
    Ok((item_claims, source_claims))
}

/// Keep the entire disclosed set together for each proof and recorded credential.
fn group_proof_claims(references: Vec<ProofClaimRow>) -> Vec<ProofClaimGroup> {
    let mut groups = HashMap::new();
    for reference in references {
        groups
            .entry((reference.proof_id, reference.credential_id))
            .or_insert_with(|| ProofClaimGroup {
                proof_id: reference.proof_id,
                credential_id: reference.credential_id,
                completed_date: reference.completed_date,
                claim_ids: vec![],
            })
            .claim_ids
            .push(reference.claim_id);
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    // Preserve deterministic timestamp tie-breaking without requiring Ord on the ID types.
    groups.sort_unstable_by_key(|group| {
        (Uuid::from(group.proof_id), Uuid::from(group.credential_id))
    });
    groups
}

/// Match stored claim contents without changing explicit item provenance. Copied
/// IDs take precedence over value matching so duplicate source rows stay distinct.
fn compatible_item_matches(
    group: &ProofClaimGroup,
    items: &[BatchItemClaims],
    source_claims: &HashMap<ClaimId, ClaimRow>,
) -> Vec<ItemMatch> {
    items
        .iter()
        .filter_map(|item| {
            let claim_ids: Option<Vec<_>> = group
                .claim_ids
                .iter()
                .map(|id| {
                    let source = source_claims.get(id)?;
                    item.claims
                        .iter()
                        .find(|claim| &claim.id == item.copied_ids.get(id).unwrap_or(id))
                        .or_else(|| item.claims.iter().find(|claim| claim.matches(source)))
                        .map(|claim| claim.id)
                })
                .collect();
            claim_ids.map(|claim_ids| ItemMatch {
                item_id: item.item.id,
                claim_ids,
                consumed_at: item.item.consumed_at,
                distance_ns: group
                    .completed_date
                    .zip(item.item.consumed_at)
                    .map(|(completed, consumed)| (completed - consumed).whole_nanoseconds().abs()),
            })
        })
        .collect()
}

/// Preserve recorded item IDs, then reconstruct legacy parent references by time.
/// Counts are diagnostic: failures or multiple items in one proof can make the
/// number of consumed items differ from the number of distinct proofs.
fn plan_proof_remapping(
    parent_id: CredentialId,
    groups: Vec<ProofClaimGroup>,
    items: &[BatchItemClaims],
    source_claims: &HashMap<ClaimId, ClaimRow>,
) -> (Vec<ProofRemapping>, Vec<String>) {
    let mut proof_ids: Vec<_> = groups.iter().map(|group| group.proof_id).collect();
    proof_ids.sort_unstable_by_key(|id| Uuid::from(*id));
    proof_ids.dedup();
    let mut consumed_item_ids: Vec<_> = items
        .iter()
        .filter(|item| item.item.consumed_at.is_some())
        .map(|item| item.item.id)
        .collect();
    consumed_item_ids.sort_unstable_by_key(|id| Uuid::from(*id));
    let counts_match = consumed_item_ids.len() == proof_ids.len();
    if !counts_match {
        tracing::warn!(
            parent_id = %parent_id,
            consumed_items = consumed_item_ids.len(),
            proofs = proof_ids.len(),
            ?consumed_item_ids,
            ?proof_ids,
            "Consumed item count differs from proof count; using closest compatible consumption timestamps"
        );
    }
    let mut mappings = Vec::new();
    let mut pending = Vec::new();
    let mut errors = Vec::new();
    for group in groups {
        let mut candidates = compatible_item_matches(&group, items, source_claims);
        if group.credential_id != parent_id {
            candidates.retain(|item| item.item_id == group.credential_id);
        }
        if candidates.is_empty() {
            errors.push(format!(
                "parent_id={parent_id}, proof_id={}, credential_id={}, claim_ids=[{}]: no single compatible batch item",
                group.proof_id,
                group.credential_id,
                group.claim_ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ));
        } else if group.credential_id != parent_id {
            // Explicit provenance always wins over timestamp proximity.
            mappings.push(ProofRemapping {
                group,
                target: candidates.remove(0),
            });
        } else {
            pending.push(ProofCandidates {
                group,
                items: candidates,
            });
        }
    }
    assign_closest_items(parent_id, pending, &mut mappings, counts_match);
    (mappings, errors)
}

/// Assign the closest compatible proof/item pair first. When counts match, reserve
/// each consumed item for one proof. If that is impossible, warn and reuse the
/// closest compatible item. Timestamps are a heuristic, not exact provenance.
fn assign_closest_items(
    parent_id: CredentialId,
    mut pending: Vec<ProofCandidates>,
    mappings: &mut Vec<ProofRemapping>,
    mut distinct_items: bool,
) {
    let mut assigned: HashMap<_, HashSet<_>> = HashMap::new();
    for mapping in mappings.iter() {
        assigned
            .entry(mapping.target.item_id)
            .or_default()
            .insert(mapping.group.proof_id);
    }
    while !pending.is_empty() {
        let closest = pending
            .iter()
            .enumerate()
            .flat_map(|(proof_index, candidates)| {
                candidates
                    .items
                    .iter()
                    .enumerate()
                    .filter(|(_, item)| {
                        !distinct_items || item.available_for(candidates.group.proof_id, &assigned)
                    })
                    .map(move |(item_index, item)| (proof_index, item_index, item.proximity()))
            })
            .min_by_key(|(_, _, proximity)| *proximity);
        let Some((proof_index, item_index, _)) = closest else {
            tracing::warn!(
                parent_id = %parent_id,
                "Cannot assign distinct compatible consumed items; reusing the closest compatible item"
            );
            distinct_items = false;
            continue;
        };
        let mut candidates = pending.remove(proof_index);
        let target = candidates.items.remove(item_index);
        let tied_items: Vec<_> = candidates
            .items
            .iter()
            .filter(|item| {
                item.proximity() == target.proximity()
                    && (!distinct_items || item.available_for(candidates.group.proof_id, &assigned))
            })
            .map(|item| item.item_id)
            .collect();
        let tied_proofs: Vec<_> = pending
            .iter()
            .filter(|other| {
                other.items.iter().any(|item| {
                    item.item_id == target.item_id && item.proximity() == target.proximity()
                })
            })
            .map(|other| other.group.proof_id)
            .collect();
        if target.distance_ns.is_none() || !tied_items.is_empty() || !tied_proofs.is_empty() {
            tracing::warn!(
                parent_id = %parent_id,
                proof_id = %candidates.group.proof_id,
                item_id = %target.item_id,
                ?tied_items,
                ?tied_proofs,
                "Missing or ambiguous timestamps; using deterministic closest compatible item"
            );
        }
        assigned
            .entry(target.item_id)
            .or_default()
            .insert(candidates.group.proof_id);
        mappings.push(ProofRemapping {
            group: candidates.group,
            target,
        });
    }
}

/// Replace each association with its resolved item and item-owned claim. Inserting
/// first allows an already existing target association without losing the source.
/// Return the number of replaced associations for the batch parent's summary.
async fn apply_proof_remapping(
    connection: &impl ConnectionTrait,
    mappings: Vec<ProofRemapping>,
) -> Result<usize, DbErr> {
    let mut remapped = 0;
    for ProofRemapping { group, target } in mappings {
        for (old_id, new_id) in group.claim_ids.iter().zip(&target.claim_ids) {
            if group.credential_id == target.item_id && old_id == new_id {
                continue;
            }
            let insert_item_reference = Query::insert()
                .into_table(ProofClaim::Table)
                .columns([
                    ProofClaim::ProofId,
                    ProofClaim::CredentialId,
                    ProofClaim::ClaimId,
                ])
                .values([
                    group.proof_id.into(),
                    target.item_id.into(),
                    (*new_id).into(),
                ])
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .on_conflict(
                    OnConflict::columns([
                        ProofClaim::ProofId,
                        ProofClaim::CredentialId,
                        ProofClaim::ClaimId,
                    ])
                    .do_nothing_on([ProofClaim::ProofId])
                    .to_owned(),
                )
                .to_owned();
            connection.execute(&insert_item_reference).await?;
            let delete_legacy_reference = Query::delete()
                .from_table(ProofClaim::Table)
                .and_where(Expr::col(ProofClaim::ProofId).eq(group.proof_id))
                .and_where(Expr::col(ProofClaim::CredentialId).eq(group.credential_id))
                .and_where(Expr::col(ProofClaim::ClaimId).eq(old_id))
                .to_owned();
            connection.execute(&delete_legacy_reference).await?;
            remapped += 1;
        }
    }
    Ok(remapped)
}

/// Remove parent-owned claims only after every proof input for this parent maps.
async fn delete_parent_claims(
    connection: &impl ConnectionTrait,
    parent_id: CredentialId,
) -> Result<(), DbErr> {
    let parent_owned_claims = Query::delete()
        .from_table(Claim::Table)
        .and_where(Expr::col(Claim::CredentialId).eq(parent_id))
        .to_owned();
    connection.execute(&parent_owned_claims).await?;
    Ok(())
}

/// Copy claim bytes, timestamps and flags directly in SQL, in bounded chunks.
async fn copy_claims(
    connection: &impl ConnectionTrait,
    source: &[ClaimRow],
    owner: CredentialId,
) -> Result<Vec<ClaimRow>, DbErr> {
    let copies: Vec<_> = source
        .iter()
        .map(|claim| ClaimRow {
            id: Uuid::new_v4().into(),
            ..claim.clone()
        })
        .collect();
    // Copy the stored bytes, timestamps and flags directly in SQL. Chunking keeps
    // the CASE expression and bind count bounded even for large claim sets.
    for (originals, copies) in source.chunks(200).zip(copies.chunks(200)) {
        let mut ids = CaseStatement::new();
        for (original, copy) in originals.iter().zip(copies) {
            ids = ids.case(Expr::col(Claim::Id).eq(original.id), copy.id);
        }
        let copied_claim_values = Query::select()
            .expr(ids.finally(Expr::col(Claim::Id)))
            .expr(Expr::value(owner))
            .columns([
                Claim::ClaimSchemaId,
                Claim::Path,
                Claim::Value,
                Claim::SelectivelyDisclosable,
                Claim::CreatedDate,
                Claim::LastModified,
            ])
            .from(Claim::Table)
            .and_where(Expr::col(Claim::Id).is_in(originals.iter().map(|claim| claim.id)))
            .to_owned();
        let insert_item_claims = Query::insert()
            .into_table(Claim::Table)
            .columns([
                Claim::Id,
                Claim::CredentialId,
                Claim::ClaimSchemaId,
                Claim::Path,
                Claim::Value,
                Claim::SelectivelyDisclosable,
                Claim::CreatedDate,
                Claim::LastModified,
            ])
            .select_from(copied_claim_values)
            .map_err(|error| DbErr::Migration(error.to_string()))?
            .to_owned();
        connection.execute(&insert_item_claims).await?;
    }
    Ok(copies)
}

#[derive(DeriveIden)]
#[expect(clippy::enum_variant_names)]
enum Credential {
    Table,
    Id,
    ParentId,
    Role,
    Type,
    CreatedDate,
    ConsumedAt,
    CredentialSchemaId,
}
#[derive(DeriveIden)]
#[expect(clippy::enum_variant_names)]
enum Claim {
    Table,
    Id,
    CredentialId,
    ClaimSchemaId,
    Path,
    Value,
    SelectivelyDisclosable,
    CreatedDate,
    LastModified,
}
#[derive(DeriveIden)]
enum ProofClaim {
    Table,
    ProofId,
    CredentialId,
    ClaimId,
}

#[derive(DeriveIden)]
enum Proof {
    Table,
    Id,
    CompletedDate,
}
