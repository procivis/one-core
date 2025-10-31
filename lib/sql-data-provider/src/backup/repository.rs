use std::path::Path;

use anyhow::Context;
use autometrics::autometrics;
use one_core::model::backup::{Metadata, UnexportableEntities};
use one_core::model::history::History;
use one_core::repository::backup_repository::BackupRepository;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::{Into, convert_inner, try_convert_inner};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{Alias, Func, Query, SelectStatement, SimpleExpr};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DbBackend, EntityTrait,
    FromQueryResult, Iterable, JoinType, PaginatorTrait, QueryFilter, QuerySelect, QueryTrait,
    RelationTrait, Statement, UpdateResult, Values,
};
use time::OffsetDateTime;

use super::BackupProvider;
use crate::backup::helpers::{
    JsonAgg, JsonObject, coalesce_to_empty_array, json_object_columns, open_sqlite_on_path,
};
use crate::backup::models::UnexportableCredentialModel;
use crate::entity::{
    certificate, claim, claim_schema, credential, credential_schema,
    credential_schema_claim_schema, did, history, holder_wallet_unit, identifier, key, key_did,
    organisation, wallet_unit_attestation,
};
use crate::mapper::to_data_layer_error;
use crate::transaction_context::TransactionManagerImpl;

impl BackupProvider {
    pub fn new(db: TransactionManagerImpl, exportable_storages: Vec<String>) -> Self {
        Self {
            db,
            exportable_storages,
        }
    }

    fn non_exportable_keys_filter(&self) -> SimpleExpr {
        key::Column::StorageType
            .is_not_in(&self.exportable_storages)
            .and(key::Column::DeletedAt.is_null())
    }

    fn select_non_exportable_did_ids(&self) -> SelectStatement {
        Query::select()
            .distinct()
            .column(key_did::Column::DidId)
            .from(key_did::Entity)
            .join(
                JoinType::LeftJoin,
                key::Entity,
                Expr::col((key_did::Entity, key_did::Column::KeyId))
                    .equals((key::Entity, key::Column::Id)),
            )
            .and_where(
                key::Column::StorageType
                    .is_not_in(&self.exportable_storages)
                    .and(key::Column::DeletedAt.is_null()),
            )
            .to_owned()
    }

    fn identifiers_with_non_exportable_keys(&self) -> SelectStatement {
        Query::select()
            .column((identifier::Entity, identifier::Column::Id))
            .from(identifier::Entity)
            .join(
                JoinType::LeftJoin,
                key::Entity,
                Expr::col((identifier::Entity, identifier::Column::KeyId))
                    .equals((key::Entity, key::Column::Id)),
            )
            .and_where(
                identifier::Column::Type
                    .eq(identifier::IdentifierType::Key)
                    .and(self.non_exportable_keys_filter()),
            )
            .to_owned()
    }

    fn identifiers_with_non_exportable_certs(&self) -> SelectStatement {
        Query::select()
            .column((identifier::Entity, identifier::Column::Id))
            .distinct()
            .from(identifier::Entity)
            .join(
                JoinType::LeftJoin,
                certificate::Entity,
                Expr::col((identifier::Entity, identifier::Column::Id))
                    .equals((certificate::Entity, certificate::Column::IdentifierId)),
            )
            .join(
                JoinType::LeftJoin,
                key::Entity,
                Expr::col((certificate::Entity, certificate::Column::KeyId))
                    .equals((key::Entity, key::Column::Id)),
            )
            .and_where(
                identifier::Column::Type
                    .eq(identifier::IdentifierType::Certificate)
                    .and(self.non_exportable_keys_filter()),
            )
            .to_owned()
    }

    fn identifiers_with_non_exportable_dids(&self) -> SelectStatement {
        Query::select()
            .column((identifier::Entity, identifier::Column::Id))
            .from(identifier::Entity)
            .join(
                JoinType::LeftJoin,
                did::Entity,
                Expr::col((identifier::Entity, identifier::Column::DidId))
                    .equals((did::Entity, did::Column::Id)),
            )
            .and_where(
                identifier::Column::Type
                    .eq(identifier::IdentifierType::Did)
                    .and(did::Column::Id.in_subquery(self.select_non_exportable_did_ids())),
            )
            .to_owned()
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
                credential::Column::RedirectUri,
                credential::Column::Role,
                credential::Column::State,
                credential::Column::SuspendEndDate,
                credential::Column::CreatedDate,
                credential::Column::CredentialBlobId,
            ])
            .column_as(credential::Column::Protocol, "protocol")
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
            .column_as(
                organisation::Column::DeactivatedAt,
                "organisation_deactivated_at",
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
                Condition::any()
                    .add(
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
                    .add(
                        credential::Column::CredentialSchemaId.in_subquery(
                            Query::select()
                                .column(credential_schema::Column::Id)
                                .from(credential_schema::Entity)
                                .and_where(
                                    credential_schema::Column::WalletStorageType
                                        .eq(credential_schema::WalletStorageType::EudiCompliant),
                                )
                                .to_owned(),
                        ),
                    ),
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
                                JoinType::LeftJoin,
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

        let select_identifiers = identifier::Entity::find()
            .filter(
                identifier::Column::DeletedAt.is_null().and(
                    identifier::Column::Id
                        .in_subquery(self.identifiers_with_non_exportable_certs())
                        .or(identifier::Column::Id
                            .in_subquery(self.identifiers_with_non_exportable_dids()))
                        .or(identifier::Column::Id
                            .in_subquery(self.identifiers_with_non_exportable_keys())),
                ),
            )
            .all(&db);

        let select_history = history::Entity::find()
            .filter(
                history::Column::EntityType.eq(history::HistoryEntityType::WalletUnitAttestation),
            )
            .all(&db);

        let (
            total_keys,
            keys,
            total_credentials,
            credentials,
            total_dids,
            dids,
            total_identifiers,
            identifiers,
            total_histories,
            histories,
        ) = tokio::try_join!(
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
            identifier::Entity::find()
                .filter(identifier::Column::DeletedAt.is_null())
                .count(&db),
            select_identifiers,
            history::Entity::find().count(&db),
            select_history
        )
        .map_err(to_data_layer_error)?;

        Ok(UnexportableEntities {
            credentials: try_convert_inner(credentials)?,
            keys: convert_inner(keys),
            dids: convert_inner(dids),
            identifiers: convert_inner(identifiers),
            histories: try_convert_inner(histories)?,
            total_credentials,
            total_keys,
            total_dids,
            total_identifiers,
            total_histories,
        })
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn delete_unexportable(&self, path: &Path) -> Result<(), DataLayerError> {
        let db = open_sqlite_on_path(path).await?;
        let now = OffsetDateTime::now_utc();

        let update_credentials = credential::Entity::update_many()
            .col_expr(credential::Column::DeletedAt, now.into())
            .filter(
                Condition::any()
                    .add(
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
                            .and(credential::Column::Role.eq(credential::CredentialRole::Holder))
                            .and(credential::Column::DeletedAt.is_null()),
                    )
                    .add(
                        credential::Column::CredentialSchemaId.in_subquery(
                            Query::select()
                                .column(credential_schema::Column::Id)
                                .from(credential_schema::Entity)
                                .and_where(
                                    credential_schema::Column::WalletStorageType
                                        .eq(credential_schema::WalletStorageType::EudiCompliant),
                                )
                                .to_owned(),
                        ),
                    ),
            )
            .exec(&db);

        let update_dids = did::Entity::update_many()
            .col_expr(did::Column::DeletedAt, now.into())
            .filter(
                did::Column::Id
                    .in_subquery(self.select_non_exportable_did_ids())
                    .and(did::Column::DeletedAt.is_null()),
            )
            .exec(&db);

        tokio::try_join!(
            update_credentials,
            update_dids,
            update_identifiers_matching_subquery(
                &db,
                now,
                self.identifiers_with_non_exportable_dids()
            ),
            update_identifiers_matching_subquery(
                &db,
                now,
                self.identifiers_with_non_exportable_certs()
            ),
            update_identifiers_matching_subquery(
                &db,
                now,
                self.identifiers_with_non_exportable_keys()
            ),
            delete_wallet_unit_attestations(&db),
            delete_holder_wallet_units(&db),
            delete_history_related_to_wallet_unit_attestations(&db),
        )
        .map_err(to_data_layer_error)?;

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

fn update_identifiers_matching_subquery(
    db: &TransactionManagerImpl,
    now: OffsetDateTime,
    subquery: SelectStatement,
) -> impl Future<Output = Result<UpdateResult, sea_orm::DbErr>> {
    identifier::Entity::update_many()
        .col_expr(identifier::Column::DeletedAt, now.into())
        .filter(
            identifier::Column::Id
                .in_subquery(subquery)
                .and(identifier::Column::IsRemote.eq(false))
                .and(identifier::Column::DeletedAt.is_null()),
        )
        .exec(db)
}

async fn delete_wallet_unit_attestations(
    db: &TransactionManagerImpl,
) -> Result<(), sea_orm::DbErr> {
    wallet_unit_attestation::Entity::delete_many()
        .exec(db)
        .await?;
    Ok(())
}

async fn delete_holder_wallet_units(db: &TransactionManagerImpl) -> Result<(), sea_orm::DbErr> {
    holder_wallet_unit::Entity::delete_many().exec(db).await?;
    Ok(())
}

async fn delete_history_related_to_wallet_unit_attestations(
    db: &TransactionManagerImpl,
) -> Result<(), sea_orm::DbErr> {
    history::Entity::delete_many()
        .filter(history::Column::EntityType.eq(history::HistoryEntityType::WalletUnitAttestation))
        .exec(db)
        .await?;
    Ok(())
}

#[derive(Debug, FromQueryResult, Into)]
#[into(Metadata)]
struct VersionModel {
    version: String,
}
