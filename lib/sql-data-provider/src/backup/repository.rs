use std::path::Path;

use anyhow::Context;
use autometrics::autometrics;
use dto_mapper::{convert_inner, try_convert_inner, Into};
use migration::{Alias, Expr, Func, Query, SimpleExpr};
use one_core::{
    model::backup::{Metadata, UnexportableEntities},
    repository::{backup_repository::BackupRepository, error::DataLayerError},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait, FromQueryResult,
    Iterable, JoinType, Order, PaginatorTrait, QueryFilter, QuerySelect, RelationTrait, Statement,
    Values,
};
use time::OffsetDateTime;

use crate::{
    backup::{
        helpers::{json_agg, open_sqlite_on_path, JsonArray},
        models::UnexportableCredentialModel,
    },
    entity::{
        claim, credential, credential_schema, credential_state, did, key, key_did, organisation,
    },
    mapper::to_data_layer_error,
};

use super::BackupProvider;

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
                credential::Column::Transport,
                credential::Column::RedirectUri,
                credential::Column::Role,
            ])
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
            .column_as(credential_schema::Column::Name, "credential_schema_name")
            .column_as(
                credential_schema::Column::Format,
                "credential_schema_format",
            )
            .column_as(
                credential_schema::Column::RevocationMethod,
                "credential_schema_revocation_method",
            )
            .column_as(organisation::Column::Id, "organisation_id")
            .column_as(
                organisation::Column::CreatedDate,
                "organisation_created_date",
            )
            .column_as(
                organisation::Column::LastModified,
                "organisation_last_modified",
            )
            .expr_as_(
                Func::coalesce([
                    SimpleExpr::SubQuery(
                        None,
                        Box::new(
                            Query::select()
                                .expr(json_agg(credential_state::Column::iter()))
                                .from(credential_state::Entity)
                                .and_where(
                                    Expr::col((
                                        credential_state::Entity,
                                        credential_state::Column::CredentialId,
                                    ))
                                    .equals((credential::Entity, credential::Column::Id)),
                                )
                                .order_by(credential_state::Column::CreatedDate, Order::Desc)
                                .to_owned()
                                .into_sub_query_statement(),
                        ),
                    ),
                    Func::cust(JsonArray).into(),
                ]),
                "credential_states",
            )
            .expr_as_(
                Func::coalesce([
                    SimpleExpr::SubQuery(
                        None,
                        Box::new(
                            Query::select()
                                .expr(json_agg(claim::Column::iter()))
                                .from(claim::Entity)
                                .and_where(
                                    Expr::col((claim::Entity, claim::Column::CredentialId))
                                        .equals((credential::Entity, credential::Column::Id)),
                                )
                                .to_owned()
                                .into_sub_query_statement(),
                        ),
                    ),
                    Func::cust(JsonArray).into(),
                ]),
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
}

#[derive(Debug, FromQueryResult, Into)]
#[into(Metadata)]
struct VersionModel {
    version: String,
}