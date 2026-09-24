use sea_orm::{DatabaseBackend, FromQueryResult, StatementBuilder};
use sea_orm_migration::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::legacy_migrations::batch_utils::{delete, get_ids};
use crate::migrations::m20260417_150300_initial::{
    Claim, ClaimSchema, CredentialSchema, Organisation, ProofClaim, ProofInputClaimSchema,
    ProofInputSchema, ProofSchema,
};
use crate::migrations::m20260429_120000_credential_schema_multiformat::{
    ClaimSchema as ClaimSchemaWithBusinessKey, CredentialSchemaFormat,
    CredentialSchemaFormatClaimSchema,
};
use crate::migrations::m20260512_062412_localized_text::LocalizedText;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        migrate_old_schemas(manager).await?;

        let backend = manager.get_database_backend();

        // "remove format and schemaId fields

        // Maria-DB complains: Cannot drop index: needed in a foreign key constraint
        // so temporarily removing the foreign key
        let organisation_foreign_key = Alias::new("fk-CredentialSchema-OrganisationId");
        if backend == DatabaseBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(CredentialSchema::Table)
                        .drop_foreign_key(organisation_foreign_key.to_owned())
                        .to_owned(),
                )
                .await?;
        }
        manager
            .drop_index(
                Index::drop()
                    .table(CredentialSchema::Table)
                    .name("index-Organisation-SchemaId-DeletedAt-Partial_Unique")
                    .to_owned(),
            )
            .await?;
        if backend == DatabaseBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(CredentialSchema::Table)
                        .add_foreign_key(
                            ForeignKey::create()
                                .name(organisation_foreign_key.to_string())
                                .from_tbl(CredentialSchema::Table)
                                .from_col(CredentialSchema::OrganisationId)
                                .to_tbl(Organisation::Table)
                                .to_col(Organisation::Id)
                                .get_foreign_key(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .drop_column(CredentialSchema::Format)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .drop_column(CredentialSchema::SchemaId)
                    .to_owned(),
            )
            .await?;

        // remove business_key field
        manager
            .alter_table(
                Table::alter()
                    .table(ClaimSchema::Table)
                    .drop_column(ClaimSchemaWithBusinessKey::BusinessKey)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

async fn migrate_old_schemas(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let old_schemas = find_old_schemas(manager).await?;
    tracing::debug!("Found {} old schemas", old_schemas.len());

    for schema in old_schemas {
        tracing::debug!("Migrating schema({}): {}", schema.format, schema.id);
        migrate_old_schema(manager, schema).await?;
    }

    Ok(())
}

#[derive(FromQueryResult)]
struct OldSchema {
    id: String,
    schema_id: String,
    format: String,
    layout_properties: Option<String>,
}

async fn find_old_schemas(manager: &SchemaManager<'_>) -> Result<Vec<OldSchema>, DbErr> {
    OldSchema::find_by_statement(
        manager.get_database_backend().build(
            Query::select()
                .columns([
                    CredentialSchema::Id,
                    CredentialSchema::SchemaId,
                    CredentialSchema::Format,
                    CredentialSchema::LayoutProperties,
                ])
                .from(CredentialSchema::Table)
                .and_where(Expr::col(CredentialSchema::Format).is_not_null()),
        ),
    )
    .all(manager.get_connection())
    .await
}

#[derive(FromQueryResult, Debug)]
pub(crate) struct ClaimSchemaEntry {
    pub id: String,
    pub key: String,
    pub metadata: bool,
}

async fn find_claim_schemas(
    manager: &SchemaManager<'_>,
    credential_schema_id: &str,
) -> Result<Vec<ClaimSchemaEntry>, DbErr> {
    ClaimSchemaEntry::find_by_statement(
        manager.get_database_backend().build(
            Query::select()
                .columns([ClaimSchema::Id, ClaimSchema::Key, ClaimSchema::Metadata])
                .from(ClaimSchema::Table)
                .and_where(Expr::col(ClaimSchema::CredentialSchemaId).eq(credential_schema_id)),
        ),
    )
    .all(manager.get_connection())
    .await
}

async fn migrate_old_schema(manager: &SchemaManager<'_>, schema: OldSchema) -> Result<(), DbErr> {
    // create new format entry
    let now = OffsetDateTime::now_utc();
    let format_id = Uuid::new_v4().to_string();
    execute(
        manager,
        Query::insert()
            .into_table(CredentialSchemaFormat::Table)
            .columns([
                CredentialSchemaFormat::Id,
                CredentialSchemaFormat::CreatedDate,
                CredentialSchemaFormat::LastModified,
                CredentialSchemaFormat::CredentialSchemaId,
                CredentialSchemaFormat::Format,
                CredentialSchemaFormat::SchemaId,
            ])
            .values([
                format_id.as_str().into(),
                now.into(),
                now.into(),
                schema.id.as_str().into(),
                schema.format.as_str().into(),
                schema.schema_id.into(),
            ])
            .map_err(|e| DbErr::Migration(e.to_string()))?,
    )
    .await?;

    let is_mdoc = schema.format.starts_with("MDOC");

    // create mappings
    let claim_schemas = find_claim_schemas(manager, &schema.id).await?;
    if is_mdoc {
        create_claim_mappings_for_mdoc(manager, claim_schemas, &format_id).await?;
    } else {
        create_claim_mappings_simple(manager, claim_schemas, &format_id).await?;
    }

    if is_mdoc && let Some(layout_properties) = schema.layout_properties {
        migrate_mdoc_layout_props(manager, layout_properties, &schema.id).await?;
    }

    // clear format and schemaId from the main table, so that subsequent migration retries skip this schema
    let null_expr = Expr::value(Option::<String>::None);
    execute(
        manager,
        Query::update()
            .table(CredentialSchema::Table)
            .value(CredentialSchema::Format, null_expr.clone())
            .value(CredentialSchema::SchemaId, null_expr)
            .and_where(Expr::col(CredentialSchema::Id).eq(&schema.id)),
    )
    .await
}

/// create CredentialSchemaFormatClaimSchema entries directly from claim_schema, copying key to technical_key
pub(crate) async fn create_claim_mappings_simple(
    manager: &SchemaManager<'_>,
    claim_schemas: Vec<ClaimSchemaEntry>,
    format_id: &str,
) -> Result<(), DbErr> {
    if claim_schemas.is_empty() {
        return Ok(());
    }

    let mut query = Query::insert()
        .into_table(CredentialSchemaFormatClaimSchema::Table)
        .columns([
            CredentialSchemaFormatClaimSchema::Id,
            CredentialSchemaFormatClaimSchema::CreatedDate,
            CredentialSchemaFormatClaimSchema::LastModified,
            CredentialSchemaFormatClaimSchema::CredentialSchemaFormatId,
            CredentialSchemaFormatClaimSchema::ClaimSchemaId,
            CredentialSchemaFormatClaimSchema::TechnicalKey,
        ])
        .to_owned();

    let now = OffsetDateTime::now_utc();
    for claim_schema in claim_schemas {
        query
            .values([
                Uuid::new_v4().to_string().into(),
                now.into(),
                now.into(),
                format_id.into(),
                claim_schema.id.into(),
                claim_schema.key.into(),
            ])
            .map_err(|e| DbErr::Migration(e.to_string()))?;
    }

    execute(manager, &query).await
}

pub(crate) async fn create_claim_mappings_for_mdoc(
    manager: &SchemaManager<'_>,
    claim_schemas: Vec<ClaimSchemaEntry>,
    format_id: &str,
) -> Result<(), DbErr> {
    let (metadata_claims, user_claims): (Vec<_>, Vec<_>) =
        claim_schemas.into_iter().partition(|s| s.metadata);
    // metadata claims need no modifications
    create_claim_mappings_simple(manager, metadata_claims, format_id).await?;

    let (elements_and_nested, namespaces): (Vec<_>, Vec<_>) =
        user_claims.into_iter().partition(|s| s.key.contains("/"));

    for claim_schema in elements_and_nested {
        modify_element_claim(manager, claim_schema, format_id).await?;
    }

    for namespace in &namespaces {
        remove_mdoc_namespace(manager, namespace).await?;
    }

    Ok(())
}

async fn modify_element_claim(
    manager: &SchemaManager<'_>,
    claim_schema: ClaimSchemaEntry,
    format_id: &str,
) -> Result<(), DbErr> {
    let (namespace, key) = claim_schema
        .key
        .split_once("/")
        .ok_or(DbErr::Custom(format!(
            "Invalid claim schema({}) key: {}",
            claim_schema.id, claim_schema.key
        )))?;

    #[derive(FromQueryResult)]
    struct ClaimEntry {
        id: String,
        path: String,
    }

    let claims = ClaimEntry::find_by_statement(
        manager.get_database_backend().build(
            Query::select()
                .columns([Claim::Id, Claim::Path])
                .from(Claim::Table)
                .and_where(Expr::col(Claim::ClaimSchemaId).eq(&claim_schema.id)),
        ),
    )
    .all(manager.get_connection())
    .await?;

    for claim in claims {
        let (claim_namespace, path) = claim.path.split_once("/").ok_or(DbErr::Custom(format!(
            "Invalid claim({}) path: {}",
            claim.id, claim.path
        )))?;

        if claim_namespace != namespace {
            return Err(DbErr::Custom(format!(
                "Invalid claim({}) namespace: {claim_namespace}, expected: {namespace}",
                claim.id,
            )));
        }

        execute(
            manager,
            Query::update()
                .table(Claim::Table)
                .value(Claim::Path, format!("{namespace}_{path}"))
                .and_where(Expr::col(Claim::Id).eq(&claim.id)),
        )
        .await?;
    }

    let now = OffsetDateTime::now_utc();
    execute(
        manager,
        Query::insert()
            .into_table(CredentialSchemaFormatClaimSchema::Table)
            .columns([
                CredentialSchemaFormatClaimSchema::Id,
                CredentialSchemaFormatClaimSchema::CreatedDate,
                CredentialSchemaFormatClaimSchema::LastModified,
                CredentialSchemaFormatClaimSchema::CredentialSchemaFormatId,
                CredentialSchemaFormatClaimSchema::ClaimSchemaId,
                CredentialSchemaFormatClaimSchema::TechnicalKey,
                CredentialSchemaFormatClaimSchema::Namespace,
            ])
            .values([
                Uuid::new_v4().to_string().into(),
                now.into(),
                now.into(),
                format_id.into(),
                claim_schema.id.as_str().into(),
                key.into(),
                namespace.into(),
            ])
            .map_err(|e| DbErr::Migration(e.to_string()))?,
    )
    .await?;

    execute(
        manager,
        Query::update()
            .table(ClaimSchema::Table)
            .value(ClaimSchema::Key, format!("{namespace}_{key}"))
            .and_where(Expr::col(ClaimSchema::Id).eq(&claim_schema.id)),
    )
    .await
}

async fn remove_mdoc_namespace(
    manager: &SchemaManager<'_>,
    claim_schema: &ClaimSchemaEntry,
) -> Result<(), DbErr> {
    let now = OffsetDateTime::now_utc();

    let proof_input_schema_ids: Vec<i64> = get_ids(
        manager,
        Query::select()
            .expr_as(Expr::col(ProofInputClaimSchema::ProofInputSchemaId), "id")
            .from(ProofInputClaimSchema::Table)
            .and_where(Expr::col(ProofInputClaimSchema::ClaimSchemaId).eq(&claim_schema.id)),
    )
    .await?;

    for proof_input_schema_id in &proof_input_schema_ids {
        let proof_schema_ids: Vec<String> = get_ids(
            manager,
            Query::select()
                .expr_as(Expr::col(ProofInputSchema::ProofSchema), "id")
                .from(ProofInputSchema::Table)
                .and_where(Expr::col(ProofInputSchema::Id).eq(*proof_input_schema_id)),
        )
        .await?;

        if proof_schema_ids.is_empty() {
            continue;
        }

        execute(
            manager,
            Query::update()
                .table(ProofSchema::Table)
                .value(ProofSchema::DeletedAt, now)
                .and_where(Expr::col(ProofSchema::DeletedAt).is_null())
                .and_where(Expr::col(ProofSchema::Id).is_in(&proof_schema_ids)),
        )
        .await?;
    }

    delete(
        ProofInputClaimSchema::Table,
        ProofInputClaimSchema::ClaimSchemaId,
        &[&claim_schema.id],
        manager,
    )
    .await?;

    let claim_ids: Vec<String> = get_ids(
        manager,
        Query::select()
            .column(Claim::Id)
            .from(Claim::Table)
            .and_where(Expr::col(Claim::ClaimSchemaId).eq(&claim_schema.id)),
    )
    .await?;

    delete(ProofClaim::Table, ProofClaim::ClaimId, &claim_ids, manager).await?;

    delete(
        Claim::Table,
        Claim::ClaimSchemaId,
        &[&claim_schema.id],
        manager,
    )
    .await?;

    execute(
        manager,
        Query::delete()
            .from_table(LocalizedText::Table)
            .and_where(Expr::col(LocalizedText::EntityType).eq("CLAIM_SCHEMA"))
            .and_where(Expr::col(LocalizedText::EntityId).eq(&claim_schema.id)),
    )
    .await?;

    delete(
        ClaimSchema::Table,
        ClaimSchema::Id,
        &[&claim_schema.id],
        manager,
    )
    .await
}

pub(crate) async fn migrate_mdoc_layout_props(
    manager: &SchemaManager<'_>,
    layout_properties: String,
    credential_schema_id: &str,
) -> Result<(), DbErr> {
    use serde_json::Value;

    let mut props: Value =
        serde_json::from_str(&layout_properties).map_err(|e| DbErr::Migration(e.to_string()))?;

    let mut modified = false;
    let mut adjust_path = |value: Option<&mut Value>| {
        if let Some(Value::String(value)) = value {
            match value.split_once("/") {
                Some((namespace, path)) => {
                    *value = format!("{namespace}_{path}");
                    modified = true;
                }
                None => {
                    tracing::warn!("Unexpected layout props attribute path: {value}")
                }
            }
        }
    };

    adjust_path(props.get_mut("primary_attribute"));
    adjust_path(props.get_mut("secondary_attribute"));
    adjust_path(props.get_mut("picture_attribute"));
    adjust_path(
        props
            .get_mut("code")
            .and_then(|code| code.get_mut("attribute")),
    );

    if modified {
        tracing::debug!("Modifying schema({credential_schema_id}) layout properties");
        let props = serde_json::to_string(&props).map_err(|e| DbErr::Migration(e.to_string()))?;
        execute(
            manager,
            Query::update()
                .table(CredentialSchema::Table)
                .value(CredentialSchema::LayoutProperties, props)
                .and_where(Expr::col(CredentialSchema::Id).eq(credential_schema_id)),
        )
        .await?;
    }

    Ok(())
}

async fn execute<S: StatementBuilder>(
    manager: &SchemaManager<'_>,
    statement: &S,
) -> Result<(), DbErr> {
    manager.get_connection().execute(statement).await?;
    Ok(())
}
