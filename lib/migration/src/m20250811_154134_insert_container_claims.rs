use std::collections::{HashMap, HashSet};
use std::vec;

use sea_orm::{DbBackend, EntityTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::m20240110_000001_initial::{
    Credential, CredentialSchema, CredentialSchemaClaimSchema, ProofClaim,
};
use crate::m20240611_110000_introduce_path_and_array::{Claim, ClaimSchema};
use crate::m20250811_154134_insert_container_claims::claim::ActiveModel;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(FromQueryResult)]
pub struct ClaimSchemaResult {
    pub id: String,
    pub key: String,
    pub array: bool,
    pub credential_schema_id: String,
}

#[derive(FromQueryResult)]
pub struct IdResult {
    pub id: String,
}

#[derive(FromQueryResult, Eq, PartialEq, Hash)]
pub struct ClaimIdPath {
    pub id: String,
    pub path: String,
}

mod claim {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "claim")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,

        pub claim_schema_id: String,
        pub credential_id: String,
        pub created_date: OffsetDateTime,
        pub last_modified: OffsetDateTime,
        pub path: String,
    }

    impl ActiveModelBehavior for ActiveModel {}

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
}

#[async_trait::async_trait]
#[allow(dead_code)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        let now = OffsetDateTime::now_utc();
        insert_intermediary_array_claims(db, backend, now).await?;
        insert_intermediary_object_claims(db, backend, now).await?;

        Ok(())
    }
}

async fn insert_intermediary_array_claims(
    db: &SchemaManagerConnection<'_>,
    backend: DbBackend,
    migration_start: OffsetDateTime,
) -> Result<(), DbErr> {
    let array_claim_schemas = ClaimSchemaResult::find_by_statement(
        backend.build(
            claim_schema_base_select()
                .and_where(Expr::col(ClaimSchema::Array).eq(true))
                // Objects are dealt with separately, because they do not exist yet in the claim
                // table at all.
                .and_where(Expr::col(ClaimSchema::Datatype).ne("OBJECT")),
        ),
    )
    .all(db)
    .await?;

    for array_claim_schema in &array_claim_schemas {
        let credential_ids =
            credential_ids_for_schema_id(db, backend, array_claim_schema, migration_start).await?;

        // check each credential
        for credential_id in credential_ids {
            // Find all the array elements.
            // All of these have an index in the path that must be dropped in order to create the
            // path of the parent claim.
            let child_claims = ClaimIdPath::find_by_statement(
                backend.build(
                    Query::select()
                        .columns([Claim::Id, Claim::Path])
                        .from(Claim::Table)
                        .and_where(Expr::col(Claim::CredentialId).eq(&credential_id))
                        .and_where(Expr::col(Claim::ClaimSchemaId).eq(&array_claim_schema.id)),
                ),
            )
            .all(db)
            .await?;

            if child_claims.is_empty() {
                continue;
            }

            // HashMap of parent path -> proof ids
            let mut paths_to_proofs = HashMap::<String, HashSet<String>>::new();

            // We deal with array claims, such as
            // - Array/1/Nested String Array/1
            for child_claim in child_claims {
                // We need to drop the array index
                // - Array/1/Nested String Array
                let Some((parent_path, _)) = child_claim.path.rsplit_once('/') else {
                    return Err(DbErr::Custom(format!(
                        "expected path '{}' of claim {} to point to an array element",
                        child_claim.path, child_claim.id
                    )));
                };

                // When we create the claim with the given path, we need to also attach it to all
                // these proofs via the proof_claim table.
                let proof_ids = proof_ids_for_claim(db, backend, &child_claim).await?;

                paths_to_proofs
                    .entry(parent_path.to_owned())
                    .or_default()
                    .extend(proof_ids);
            }

            insert_claims_with_proof_relation(
                db,
                backend,
                array_claim_schema,
                credential_id,
                paths_to_proofs,
            )
            .await?;
        }
    }
    Ok(())
}

async fn proof_ids_for_claim(
    db: &SchemaManagerConnection<'_>,
    backend: DbBackend,
    claim: &ClaimIdPath,
) -> Result<Vec<String>, DbErr> {
    let proof_ids = IdResult::find_by_statement(
        backend.build(
            Query::select()
                .expr_as(Expr::col(ProofClaim::ProofId), "id")
                .from(ProofClaim::Table)
                .and_where(Expr::col(ProofClaim::ClaimId).eq(&claim.id)),
        ),
    )
    .all(db)
    .await?;
    Ok(proof_ids.into_iter().map(|id| id.id).collect())
}

async fn insert_claims_with_proof_relation(
    db: &SchemaManagerConnection<'_>,
    backend: DbBackend,
    claim_schema: &ClaimSchemaResult,
    credential_id: String,
    mut paths_to_proofs: HashMap<String, HashSet<String>>,
) -> Result<(), DbErr> {
    let models = paths_to_claims(claim_schema, credential_id, paths_to_proofs.keys());
    claim::Entity::insert_many(models.clone().into_iter().map(ActiveModel::from))
        .exec(db)
        .await?;

    let mut proof_claim_insert = Query::insert()
        .into_table(ProofClaim::Table)
        .columns([ProofClaim::ProofId, ProofClaim::ClaimId])
        .to_owned();
    // There is no point in executing an empty insert, so we track if we ever called `values`
    let mut has_proof_ids = false;
    for model in models {
        let Some(proof_ids) = paths_to_proofs.remove(&model.path) else {
            continue;
        };

        proof_ids.into_iter().try_for_each(|proof_id| {
            has_proof_ids = true;
            proof_claim_insert
                .values(vec![
                    SimpleExpr::Value(Value::from(proof_id)),
                    SimpleExpr::Value(Value::from(model.id.clone())),
                ])
                .map_err(|e| {
                    DbErr::Custom(format!(
                        "failed to insert new claims into proof_claim table: {e}"
                    ))
                })?;
            Ok::<_, DbErr>(())
        })?;
    }

    if !has_proof_ids {
        // No proofs to attach claims to
        return Ok(());
    }

    db.execute(backend.build(&proof_claim_insert)).await?;
    Ok(())
}

async fn credential_ids_for_schema_id(
    db: &SchemaManagerConnection<'_>,
    backend: DbBackend,
    array_claim_schema: &ClaimSchemaResult,
    time_cutoff: OffsetDateTime,
) -> Result<Vec<String>, DbErr> {
    let credential_ids = IdResult::find_by_statement(
        backend.build(
            Query::select()
                .distinct()
                .column(Credential::Id)
                .from(Credential::Table)
                .and_where(
                    Expr::col(Credential::CredentialSchemaId)
                        .eq(&array_claim_schema.credential_schema_id),
                )
                // Ignore any credential that was created after the migration started.
                // This is here to counteract potential issues that might arise from the migration
                // taking a long time to complete.
                .and_where(Expr::col(Credential::CreatedDate).lte(time_cutoff)),
        ),
    )
    .all(db)
    .await?;
    Ok(credential_ids.into_iter().map(|id| id.id).collect())
}

async fn insert_intermediary_object_claims(
    db: &SchemaManagerConnection<'_>,
    backend: DbBackend,
    migration_start: OffsetDateTime,
) -> Result<(), DbErr> {
    let object_claim_schemas = ClaimSchemaResult::find_by_statement(backend.build(
        claim_schema_base_select().and_where(Expr::col(ClaimSchema::Datatype).eq("OBJECT")),
    ))
    .all(db)
    .await?;

    for object_claim_schema in &object_claim_schemas {
        // find schema ids of _direct_ child claims
        let statement = backend.build(
            Query::select()
                .column((ClaimSchema::Table, ClaimSchema::Id))
                .from(ClaimSchema::Table)
                .inner_join(
                    CredentialSchemaClaimSchema::Table,
                    Expr::col((
                        CredentialSchemaClaimSchema::Table,
                        CredentialSchemaClaimSchema::ClaimSchemaId,
                    ))
                    .equals((ClaimSchema::Table, ClaimSchema::Id)),
                )
                // must be claim schemas of the same credential schema
                .and_where(
                    Expr::col((
                        CredentialSchemaClaimSchema::Table,
                        CredentialSchemaClaimSchema::CredentialSchemaId,
                    ))
                    .eq(&object_claim_schema.credential_schema_id),
                )
                // We want _direct_ child claims, i.e. containing _exactly one_ additional `/` character
                .and_where(
                    Expr::col(ClaimSchema::Key).like(format!("{}/%", object_claim_schema.key)),
                )
                .and_where(
                    Expr::col(ClaimSchema::Key)
                        .like(format!("{}/%/%", object_claim_schema.key))
                        .not(),
                ),
        );
        let child_claim_schema_ids = IdResult::find_by_statement(statement).all(db).await?;

        let credential_ids =
            credential_ids_for_schema_id(db, backend, object_claim_schema, migration_start).await?;

        // check each credential
        for credential_id in credential_ids {
            // Find all the ids and paths for each claim that we need to create a parents for
            // (i.e. _direct_ child claim: non-array property or the array container claim).
            // Potentially some of these will share a newly created parent claim.
            let mut child_claims = HashSet::new();
            for child_claim_schema_id in child_claim_schema_ids.iter() {
                let select = Query::select()
                    .columns([Claim::Id, Claim::Path])
                    .from(Claim::Table)
                    .and_where(Expr::col(Claim::CredentialId).eq(&credential_id))
                    .and_where(Expr::col(Claim::ClaimSchemaId).eq(&child_claim_schema_id.id))
                    // Order by path ascending
                    // -> parent paths are sorted before child paths because they are a prefix of the other
                    // Because we have previously inserted the array container claims, we select
                    // these before the array element claims. That is important for the prefix
                    // check below.
                    .order_by(Claim::Path, Order::Asc)
                    .to_owned();
                let results = ClaimIdPath::find_by_statement(backend.build(&select))
                    .all(db)
                    .await?;
                // Only keep the ones where we have not already selected a child claim with a
                // shorter path.
                // I.e. out of
                // - foo/0/bar
                // - foo/0/bar/0
                // - foo/0/bar/1
                // - foo/1/bar
                // - foo/1/bar/0
                // - foo/1/bar/1
                // we want to keep exactly foo/0/bar and foo/1/bar.
                for direct_child_candidate in results {
                    if !child_claims.iter().any(|child: &ClaimIdPath| {
                        direct_child_candidate.path.starts_with(&child.path)
                    }) {
                        child_claims.insert(direct_child_candidate);
                    }
                }
            }

            if child_claims.is_empty() {
                continue;
            }

            // HashMap of parent path -> proof ids
            let mut paths_to_proofs = HashMap::<String, HashSet<String>>::new();

            // We deal with child properties of objects, potentially of object arrays, e.g.:
            // - Array List Object A/1/Child Array List object A/Nested object/1/Are you okay?
            for child_claim in child_claims {
                // First: drop property name, e.g.:
                // - Array List Object A/1/Child Array List object A/Nested object/1
                let Some((parent_path, _)) = child_claim.path.rsplit_once('/') else {
                    return Err(DbErr::Custom(format!(
                        "expected path '{}' of claim {} to point to an object property",
                        child_claim.path, child_claim.id
                    )));
                };

                // When we create the claim with the given path, we need to also attach it to all
                // these proofs via the proof_claim table.
                let proof_ids = proof_ids_for_claim(db, backend, &child_claim).await?;

                paths_to_proofs
                    .entry(parent_path.to_owned())
                    .or_default()
                    .extend(proof_ids.clone());

                // If it is an array, we need to drop the index component too
                // E.g:
                // - Array List Object A/1/Child Array List object A/Nested object
                if object_claim_schema.array {
                    let Some((array_parent_path, _)) = parent_path.rsplit_once('/') else {
                        return Err(DbErr::Custom(format!(
                            "expected path '{}' of claim {} to point to an object array element of an array of objects",
                            parent_path, child_claim.id
                        )));
                    };
                    paths_to_proofs
                        .entry(array_parent_path.to_owned())
                        .or_default()
                        .extend(proof_ids);
                }
            }

            insert_claims_with_proof_relation(
                db,
                backend,
                object_claim_schema,
                credential_id,
                paths_to_proofs,
            )
            .await?;
        }
    }
    Ok(())
}

fn claim_schema_base_select() -> SelectStatement {
    Query::select()
        .column((ClaimSchema::Table, ClaimSchema::Id))
        .columns([ClaimSchema::Key, ClaimSchema::Array])
        .expr_as(
            Expr::col((CredentialSchema::Table, CredentialSchema::Id)),
            "credential_schema_id",
        )
        .from(ClaimSchema::Table)
        .inner_join(
            CredentialSchemaClaimSchema::Table,
            Expr::col((
                CredentialSchemaClaimSchema::Table,
                CredentialSchemaClaimSchema::ClaimSchemaId,
            ))
            .equals((ClaimSchema::Table, ClaimSchema::Id)),
        )
        .inner_join(
            CredentialSchema::Table,
            Expr::col((
                CredentialSchemaClaimSchema::Table,
                CredentialSchemaClaimSchema::CredentialSchemaId,
            ))
            .equals((CredentialSchema::Table, CredentialSchema::Id)),
        )
        // Order descending so that we can build the tree from the leaves upwards
        .order_by(ClaimSchema::Key, Order::Desc)
        .to_owned()
}

fn paths_to_claims(
    array_claim_schema: &ClaimSchemaResult,
    credential_id: String,
    unique_paths: impl IntoIterator<Item = impl ToString>,
) -> Vec<claim::Model> {
    let now = OffsetDateTime::now_utc();
    let mut new_claims = vec![];
    for path in unique_paths.into_iter() {
        let model = claim::Model {
            id: Uuid::new_v4().into(),
            claim_schema_id: array_claim_schema.id.clone(),
            credential_id: credential_id.clone(),
            created_date: now,
            last_modified: now,
            path: path.to_string(),
        };
        new_claims.push(model);
    }
    new_claims
}
