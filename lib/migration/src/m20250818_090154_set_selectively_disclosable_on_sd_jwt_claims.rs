use std::collections::HashMap;

use sea_orm::{DbBackend, FromQueryResult};
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{CredentialSchema, CredentialSchemaClaimSchema};
use crate::m20240611_110000_introduce_path_and_array::{Claim, ClaimSchema};
use crate::m20250814_120106_add_selectively_disclosable_column_to_claims::ClaimNew;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(FromQueryResult)]
struct IdResult {
    id: String,
}

#[derive(FromQueryResult, Eq, PartialEq, Hash)]
struct ClaimSchemaIdKey {
    id: String,
    key: String,
    array: bool,
}

#[derive(FromQueryResult, Eq, PartialEq, Hash)]
struct ClaimIdPath {
    id: String,
    credential_id: String,
    path: String,
}

struct ClaimSchemaInfo {
    array: bool,
    selectively_disclosable: bool,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let credential_schemas = IdResult::find_by_statement(
            backend.build(
                Query::select()
                    .column(CredentialSchema::Id)
                    .from(CredentialSchema::Table)
                    .and_where(Expr::col(CredentialSchema::Format).in_tuples([
                        "SD_JWT",
                        "SD_JWT_VC",
                        "SD_JWT_VC_SWIYU",
                    ])),
            ),
        )
        .all(db)
        .await?;

        for credential_schema in credential_schemas {
            let result = process_credential_schema(db, backend, &credential_schema).await;
            if let Err(err) = result {
                tracing::warn!(
                    "Failed to migrate credential schema {}: {err}",
                    credential_schema.id
                )
            }
        }
        Ok(())
    }
}

async fn process_credential_schema(
    db: &SchemaManagerConnection<'_>,
    backend: DbBackend,
    credential_schema: &IdResult,
) -> Result<(), DbErr> {
    let mut key_to_claim_schema_info = HashMap::<String, ClaimSchemaInfo>::new();
    let claim_schemas = ClaimSchemaIdKey::find_by_statement(
        backend.build(
            Query::select()
                .column((ClaimSchema::Table, ClaimSchema::Id))
                .columns([ClaimSchema::Key, ClaimSchema::Array])
                .from(ClaimSchema::Table)
                .inner_join(
                    CredentialSchemaClaimSchema::Table,
                    Expr::col((ClaimSchema::Table, ClaimSchema::Id))
                        .equals(CredentialSchemaClaimSchema::ClaimSchemaId),
                )
                .inner_join(
                    CredentialSchema::Table,
                    Expr::col((CredentialSchema::Table, CredentialSchema::Id))
                        .equals(CredentialSchemaClaimSchema::CredentialSchemaId),
                )
                .and_where(
                    Expr::col((CredentialSchema::Table, CredentialSchema::Id))
                        .eq(&credential_schema.id),
                )
                // shorter paths first -> traverse from root to leaves
                .order_by(ClaimSchema::Key, Order::Asc),
        ),
    )
    .all(db)
    .await?;

    for claim_schema in claim_schemas {
        let selectively_disclosable = if let Some((parent, _)) = claim_schema.key.rsplit_once('/') {
            let parent = key_to_claim_schema_info
                .get(parent)
                .ok_or(DbErr::Custom(format!(
                    "missing parent claim schema with key {parent}"
                )))?;
            // child claims of arrays are never selectively disclosable
            parent.selectively_disclosable && !parent.array
        } else {
            true
        };

        if selectively_disclosable {
            if claim_schema.array {
                // manually collect claims because we only want to mark the array container as
                // selectively disclosable and _not_ its individual array elements
                let claim_candidates = ClaimIdPath::find_by_statement(
                    backend.build(
                        Query::select()
                            .columns([Claim::Id, Claim::Path, Claim::CredentialId])
                            .from(Claim::Table)
                            .and_where(Expr::col(Claim::ClaimSchemaId).eq(claim_schema.id))
                            // shorter paths first -> container claim is ordered before its elements
                            .order_by(Claim::Path, Order::Asc),
                    ),
                )
                .all(db)
                .await?;

                let claim_ids = claim_candidates
                    .into_iter()
                    .fold(
                        HashMap::<String, Vec<ClaimIdPath>>::new(),
                        |mut acc, claim| {
                            let entry = acc.entry(claim.credential_id.clone()).or_default();
                            if !entry.iter().any(|existing: &ClaimIdPath| {
                                claim.path.starts_with(&existing.path)
                            }) {
                                entry.push(claim);
                            }
                            acc
                        },
                    )
                    .into_iter()
                    .flat_map(|(_, claims)| claims.into_iter().map(|claim| claim.id))
                    .collect::<Vec<_>>();
                db.execute(
                    backend.build(
                        Query::update()
                            .table(Claim::Table)
                            .value(ClaimNew::SelectivelyDisclosable, true)
                            .and_where(Expr::col(Claim::Id).in_tuples(claim_ids)),
                    ),
                )
                .await?;
            } else {
                // no index mangling, update all matching claims
                db.execute(
                    backend.build(
                        Query::update()
                            .table(Claim::Table)
                            .value(ClaimNew::SelectivelyDisclosable, true)
                            .and_where(Expr::col(Claim::ClaimSchemaId).eq(claim_schema.id)),
                    ),
                )
                .await?;
            }
        }

        key_to_claim_schema_info.insert(
            claim_schema.key,
            ClaimSchemaInfo {
                array: claim_schema.array,
                selectively_disclosable,
            },
        );
    }
    Ok(())
}
