use std::path::Path;

use anyhow::Context;
use autometrics::autometrics;
use one_core::model::backup::{Metadata, UnexportableEntities};
use one_core::model::history::History;
use one_core::repository::backup_repository::BackupRepository;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::{convert_inner, try_convert_inner, Into};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{Alias, Func, Query};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait,
    FromQueryResult, Iterable, JoinType, PaginatorTrait, QueryFilter, QuerySelect, QueryTrait,
    RelationTrait, Statement, Values,
};
use time::OffsetDateTime;

use super::BackupProvider;
use crate::backup::helpers::{
    coalesce_to_empty_array, json_object_columns, open_sqlite_on_path, JsonAgg, JsonObject,
};
use crate::backup::models::UnexportableCredentialModel;
use crate::entity::{
    claim, claim_schema, credential, credential_schema, credential_schema_claim_schema, did,
    history, key, key_did, organisation,
};
use crate::mapper::to_data_layer_error;

impl BackupProvider {
    pub fn new(db: DatabaseConnection, exportable_storages: Vec<String>) -> Self {
        Self {
            db,
            exportable_storages,
        }
    }
}

#[autometrics]
#[async_trait::async_trait]
impl BackupRepository for BackupProvider {
    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn copy_db_to(&self, path: &Path) -> Result<Metadata, DataLayerError> {
        self.db
            .execute(Statement {
                sql: "VACUUM INTO ?;".into(),
                values: Values(vec![path.to_string_lossy().into()]).into(),
                db_backend: DbBackend::Sqlite,
            })
            .await
            .map_err(to_data_layer_error)?;

        let db_copy = open_sqlite_on_path(path).await?;

        let select = Query::select()
            .expr_as(
                Expr::col(Alias::new("version")).max(),
                Alias::new("version"),
            )
            .from(Alias::new("seaql_migrations"))
            .to_owned();

        Ok(
            VersionModel::find_by_statement(db_copy.get_database_backend().build(&select))
                .one(&db_copy)
                .await
                .map_err(to_data_layer_error)?
                .context("No version record found")?
                .into(),
        )
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn fetch_unexportable<'a>(
        &self,
        path: Option<&'a Path>,
    ) -> Result<UnexportableEntities, DataLayerError> {
        let db = match path {
            Some(path) => open_sqlite_on_path(path).await?,
            None => self.db.clone(),
        };

        let select_keys = key::Entity::find()
            .filter(
                key::Column::StorageType
                    .is_not_in(&self.exportable_storages)
                    .and(key::Column::DeletedAt.is_null()),
            )
            .all(&db);

        let select_credentials = credential::Entity::find()
            .select_only()
            .columns([
                credential::Column::Id,
                credential::Column::CreatedDate,
                credential::Column::IssuanceDate,
                credential::Column::LastModified,
                credential::Column::DeletedAt,
                credential::Column::Credential,
                credential::Column::RedirectUri,
                credential::Column::Role,
                credential::Column::State,
                credential::Column::SuspendEndDate,
            ])
            .column_as(credential::Column::Exchange, "exchange")
            .column_as(credential_schema::Column::Id, "credential_schema_id")
            .column_as(
                credential_schema::Column::DeletedAt,
                "credential_deleted_at",
            )
            .column_as(
                credential_schema::Column::CreatedDate,
                "credential_schema_created_date",
            )
            .column_as(
                credential_schema::Column::LastModified,
                "credential_schema_last_modified",
            )
            .column_as(
                credential_schema::Column::ImportedSourceUrl,
                "credential_schema_imported_source_url",
            )
            .column_as(
                credential_schema::Column::ExternalSchema,
                "credential_schema_external_schema",
            )
            .column_as(credential_schema::Column::Name, "credential_schema_name")
            .column_as(
                credential_schema::Column::Format,
                "credential_schema_format",
            )
            .column_as(
                credential_schema::Column::RevocationMethod,
                "credential_schema_revocation_method",
            )
            .column_as(
                credential_schema::Column::AllowSuspension,
                "credential_schema_allow_suspension",
            )
            .column_as(organisation::Column::Id, "organisation_id")
            .column_as(organisation::Column::Name, "organisation_name")
            .column_as(
                organisation::Column::CreatedDate,
                "organisation_created_date",
            )
            .column_as(
                organisation::Column::LastModified,
                "organisation_last_modified",
            )
            .expr_as_(
                coalesce_to_empty_array(
                    credential_schema_claim_schema::Entity::find()
                        .select_only()
                        .expr(
                            Func::cust(JsonAgg).arg(
                                Func::cust(JsonObject)
                                    .arg("credential_schema_claim_schema")
                                    .arg(json_object_columns(
                                        credential_schema_claim_schema::Column::iter(),
                                    ))
                                    .arg("claim_schema")
                                    .arg(json_object_columns(claim_schema::Column::iter())),
                            ),
                        )
                        .join(
                            JoinType::InnerJoin,
                            credential_schema_claim_schema::Relation::ClaimSchema.def(),
                        )
                        .filter(
                            Expr::col((
                                credential_schema_claim_schema::Entity,
                                credential_schema_claim_schema::Column::CredentialSchemaId,
                            ))
                            .equals((credential_schema::Entity, credential_schema::Column::Id)),
                        )
                        .into_query(),
                ),
                "credential_schema_claim_schemas",
            )
            .expr_as_(
                coalesce_to_empty_array(
                    claim::Entity::find()
                        .select_only()
                        .expr(
                            Func::cust(JsonAgg).arg(
                                Func::cust(JsonObject)
                                    .arg("claim")
                                    .arg(json_object_columns(claim::Column::iter()))
                                    .arg("claim_schema")
                                    .arg(json_object_columns(claim_schema::Column::iter())),
                            ),
                        )
                        .join(JoinType::InnerJoin, claim::Relation::ClaimSchema.def())
                        .filter(
                            Expr::col((claim::Entity, claim::Column::CredentialId))
                                .equals((credential::Entity, credential::Column::Id)),
                        )
                        .into_query(),
                ),
                "claims",
            )
            .join(
                JoinType::InnerJoin,
                credential::Relation::CredentialSchema.def(),
            )
            .join(
                JoinType::InnerJoin,
                credential_schema::Relation::Organisation.def(),
            )
            .filter(
                credential::Column::KeyId
                    .in_subquery(
                        Query::select()
                            .column(key::Column::Id)
                            .from(key::Entity)
                            .and_where(
                                key::Column::StorageType
                                    .is_not_in(&self.exportable_storages)
                                    .and(key::Column::DeletedAt.is_null()),
                            )
                            .to_owned(),
                    )
                    .and(credential::Column::DeletedAt.is_null()),
            )
            .into_model::<UnexportableCredentialModel>()
            .all(&db);

        let select_dids = did::Entity::find()
            .filter(
                did::Column::Id
                    .in_subquery(
                        Query::select()
                            .column(key_did::Column::DidId)
                            .from(key_did::Entity)
                            .join(
                                sea_orm::JoinType::LeftJoin,
                                key::Entity,
                                Expr::col((key_did::Entity, key_did::Column::KeyId))
                                    .equals((key::Entity, key::Column::Id)),
                            )
                            .and_where(
                                key::Column::StorageType
                                    .is_not_in(&self.exportable_storages)
                                    .and(key::Column::DeletedAt.is_null()),
                            )
                            .to_owned(),
                    )
                    .and(did::Column::DeletedAt.is_null()),
            )
            .all(&db);

        let (total_keys, keys, total_credentials, credentials, total_dids, dids) =
            tokio::try_join!(
                key::Entity::find()
                    .filter(key::Column::DeletedAt.is_null())
                    .count(&db),
                select_keys,
                credential::Entity::find()
                    .filter(credential::Column::DeletedAt.is_null())
                    .count(&db),
                select_credentials,
                did::Entity::find()
                    .filter(did::Column::DeletedAt.is_null())
                    .count(&db),
                select_dids,
            )
            .map_err(to_data_layer_error)?;

        Ok(UnexportableEntities {
            credentials: try_convert_inner(credentials)?,
            keys: convert_inner(keys),
            dids: convert_inner(dids),
            total_credentials,
            total_keys,
            total_dids,
        })
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn delete_unexportable(&self, path: &Path) -> Result<(), DataLayerError> {
        let db = open_sqlite_on_path(path).await?;
        let now = OffsetDateTime::now_utc();

        let update_credentials = credential::Entity::update_many()
            .col_expr(credential::Column::DeletedAt, now.into())
            .filter(
                credential::Column::KeyId
                    .in_subquery(
                        Query::select()
                            .column(key::Column::Id)
                            .from(key::Entity)
                            .and_where(
                                key::Column::StorageType
                                    .is_not_in(&self.exportable_storages)
                                    .and(key::Column::DeletedAt.is_null()),
                            )
                            .to_owned(),
                    )
                    .and(credential::Column::DeletedAt.is_null()),
            )
            .exec(&db);

        let update_dids = did::Entity::update_many()
            .col_expr(did::Column::DeletedAt, now.into())
            .filter(
                did::Column::Id
                    .in_subquery(
                        Query::select()
                            .column(key_did::Column::DidId)
                            .from(key_did::Entity)
                            .join(
                                sea_orm::JoinType::LeftJoin,
                                key::Entity,
                                Expr::col((key_did::Entity, key_did::Column::KeyId))
                                    .equals((key::Entity, key::Column::Id)),
                            )
                            .and_where(
                                key::Column::StorageType
                                    .is_not_in(&self.exportable_storages)
                                    .and(key::Column::DeletedAt.is_null()),
                            )
                            .to_owned(),
                    )
                    .and(did::Column::DeletedAt.is_null()),
            )
            .exec(&db);

        tokio::try_join!(update_credentials, update_dids).map_err(to_data_layer_error)?;

        key::Entity::update_many()
            .col_expr(key::Column::DeletedAt, now.into())
            .filter(
                key::Column::StorageType
                    .is_not_in(&self.exportable_storages)
                    .and(key::Column::DeletedAt.is_null()),
            )
            .exec(&db)
            .await
            .map(|_| ())
            .map_err(to_data_layer_error)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn add_history_event(&self, path: &Path, history: History) -> Result<(), DataLayerError> {
        let db = open_sqlite_on_path(path).await?;

        history::ActiveModel::try_from(history)?
            .insert(&db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }
}

#[derive(Debug, FromQueryResult, Into)]
#[into(Metadata)]
struct VersionModel {
    version: String,
}
