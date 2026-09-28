use std::collections::{HashMap, HashSet};

use autometrics::autometrics;
use futures::FutureExt;
use migration::supported_db_type::{SupportedDbType, WithSupportedDbType};
use one_core::model::credential::{
    Credential, CredentialFilterValue, CredentialListIncludeEntityTypeEnum, CredentialListQuery,
    GetCredentialList, SortableCredentialColumn, UpdateCredentialRequest,
};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::identifier::Identifier;
use one_core::model::relation::{AsyncModelLoader, BatchModelLoader, Related};
use one_core::proto::transaction_manager::IsolationLevel;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::error::{DataLayerError, EntityKind};
use sea_orm::ActiveValue::NotSet;
use sea_orm::sea_query::{Alias, Expr, Func, IntoCondition, SimpleExpr};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ExprTrait, FromQueryResult, JoinType, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait, RelationTrait, Select, Set, Unchanged,
};
use shared_types::{CredentialId, InteractionId};

use super::CredentialProvider;
use super::creation::{insert_credentials_with_claims, prepare_credentials};
use super::mapper::{CredentialSchemaFormatLoader, credential_claims, from_clearable};
use crate::common::calculate_pages_count;
use crate::credential_schema::mapper::CredentialSchemasLoader;
use crate::entity::{claim, claim_schema, credential, credential_claim};
use crate::list_query_generic::{IntoSortingColumn, SelectWithFilterJoin, SelectWithListQuery};
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::transaction_context::TransactionManagerImpl;

impl CredentialProvider {
    fn credential_from_model(
        &self,
        credential: credential::Model,
        schema: impl AsyncModelLoader<CredentialSchema> + 'static,
        issuer: impl AsyncModelLoader<Identifier> + 'static,
        format: impl AsyncModelLoader<CredentialSchemaFormat> + 'static,
    ) -> Credential {
        Credential {
            claims: credential_claims(credential.id, &self.claim_repository),
            id: credential.id,
            created_date: credential.created_date,
            issuance_date: credential.issuance_date,
            expires_at: credential.expires_at,
            last_modified: credential.last_modified,
            deleted_at: credential.deleted_at,
            consumed_at: credential.consumed_at,
            protocol: credential.protocol,
            redirect_uri: credential.redirect_uri,
            role: credential.role.into(),
            r#type: credential.r#type.into(),
            state: credential.state.into(),
            suspend_end_date: credential.suspend_end_date,
            profile: credential.profile,
            issuer_identifier: credential
                .issuer_identifier_id
                .map(|id| Related::new(id, issuer)),
            issuer_certificate: credential
                .issuer_certificate_id
                .map(|id| Related::new(id, self.certificate_repository.clone())),
            holder_identifier: credential
                .holder_identifier_id
                .map(|id| Related::new(id, self.identifier_repository.clone())),
            schema: Related::new(credential.credential_schema_id, schema),
            interaction: credential
                .interaction_id
                .map(|id| Related::new(id, self.interaction_repository.clone())),
            key: credential
                .key_id
                .map(|id| Related::new(id, self.key_repository.clone())),
            credential_blob_id: credential.credential_blob_id,
            wallet_key_attestation_blob_id: credential.wallet_key_attestation_blob_id,
            wallet_instance_attestation_blob_id: credential.wallet_instance_attestation_blob_id,
            webhook_url: credential.webhook_url,
            embedded_disclosure_policy: credential.embedded_disclosure_policy,
            subscriber_information: credential.subscriber_information,
            ecosystem: credential.ecosystem,
            parent: credential
                .parent_id
                .map(|id| Related::new(id, self.cloned())),
            format: credential.format.map(|id| Related::new(id, format)),
        }
    }

    fn credential_model_to_repository_model(&self, credential: credential::Model) -> Credential {
        let format = BatchModelLoader::new(
            credential.format,
            CredentialSchemaFormatLoader {
                db: self.db.clone(),
            },
        );
        self.credential_from_model(
            credential,
            self.credential_schema_repository.clone(),
            self.identifier_repository.clone(),
            format,
        )
    }

    /// We batch the requests, 3 queries fetch all schemas, issuers and formats
    fn credentials_to_repository(
        &self,
        credentials: Vec<credential::Model>,
        skip_layout_properties: bool,
    ) -> Vec<Credential> {
        let schemas = BatchModelLoader::new(
            credentials
                .iter()
                .map(|credential| credential.credential_schema_id),
            CredentialSchemasLoader {
                db: self.db.clone(),
                organisation_repository: self.organisation_repository.clone(),
                skip_layout_properties,
            },
        );
        let issuers = BatchModelLoader::new(
            credentials
                .iter()
                .filter_map(|credential| credential.issuer_identifier_id),
            self.identifier_repository.clone(),
        );
        let formats = BatchModelLoader::new(
            credentials
                .iter()
                .filter_map(|credential| credential.format),
            CredentialSchemaFormatLoader {
                db: self.db.clone(),
            },
        );
        credentials
            .into_iter()
            .map(|credential| {
                self.credential_from_model(
                    credential,
                    schemas.clone(),
                    issuers.clone(),
                    formats.clone(),
                )
            })
            .collect()
    }

    /// Rows in the order of `ids`
    async fn get_credentials_in_order(
        &self,
        ids: &[CredentialId],
    ) -> Result<Vec<credential::Model>, DataLayerError> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let rows = credential::Entity::find()
            .filter(credential::Column::Id.is_in(ids))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let mut by_id: HashMap<CredentialId, credential::Model> =
            rows.into_iter().map(|row| (row.id, row)).collect();
        Ok(ids.iter().filter_map(|id| by_id.remove(id)).collect())
    }
}

/// `COUNT` over the rows of `page_query`. Not `count_if_requested`: it wraps the query as a
/// subquery, and MariaDB then scans the whole table instead of using the index
async fn count_credentials(
    include_count: bool,
    mut page_query: Select<credential::Entity>,
    db: &TransactionManagerImpl,
) -> Result<Option<u64>, DataLayerError> {
    if !include_count {
        return Ok(None);
    }
    QueryTrait::query(&mut page_query)
        .clear_selects()
        .clear_order_by()
        .reset_limit()
        .reset_offset()
        .expr_as(
            Func::count_distinct(Expr::col((credential::Entity, credential::Column::Id))),
            Alias::new("num_items"),
        );
    let count: Option<i64> = page_query
        .into_tuple()
        .one(db)
        .await
        .map_err(to_data_layer_error)?;
    Ok(Some(count.unwrap_or_default() as u64))
}

#[derive(FromQueryResult)]
struct CredentialIdModel {
    id: CredentialId,
}

/// Joins for the sort column. `credential_schema` is joined here and not by the schema name filter
/// in `IntoJoinRelations` since it's needed for the sort and a table can be joined only once.
fn with_list_joins(
    mut query: Select<credential::Entity>,
    query_params: &CredentialListQuery,
) -> Select<credential::Entity> {
    let sorted_by = |column| {
        query_params
            .sorting
            .as_ref()
            .is_some_and(|sorting| sorting.column == column)
    };
    let filtered_by_schema_name = query_params.filtering.as_ref().is_some_and(|filter| {
        filter.contains(&|value| matches!(value, CredentialFilterValue::CredentialSchemaName(_)))
    });
    if sorted_by(SortableCredentialColumn::SchemaName) || filtered_by_schema_name {
        query = query.join(
            JoinType::InnerJoin,
            credential::Relation::CredentialSchema.def(),
        );
    }
    if sorted_by(SortableCredentialColumn::Issuer) {
        query = query.join(
            JoinType::LeftJoin,
            credential::Relation::IssuerIdentifier.def(),
        );
    }
    query
}

fn with_credential_list_query(
    query: Select<credential::Entity>,
    query_params: &CredentialListQuery,
    db_backend: SupportedDbType,
) -> Select<credential::Entity> {
    let mut query = with_list_joins(query, query_params)
        .with_filter_join(query_params)
        .with_list_query(query_params, db_backend);

    if query_params.filtering.as_ref().is_some_and(|filter| {
        filter.contains(&|value| {
            matches!(
                value,
                CredentialFilterValue::ClaimName(_) | CredentialFilterValue::ClaimValue(_)
            )
        })
    }) {
        QueryTrait::query(&mut query)
            .join(
                JoinType::LeftJoin,
                credential_claim::Entity,
                Expr::col((
                    credential_claim::Entity,
                    credential_claim::Column::CredentialId,
                ))
                .eq(super::mapper::effective_claim_owner()),
            )
            .join(
                JoinType::LeftJoin,
                claim::Entity,
                Expr::col((claim::Entity, claim::Column::Id))
                    .equals((credential_claim::Entity, credential_claim::Column::ClaimId)),
            );
        query = query.distinct();
    }

    if query_params.sorting.is_some() || query_params.pagination.is_some() {
        // fallback ordering
        query = query
            .order_by_desc(credential::Column::CreatedDate)
            .order_by_desc(credential::Column::Id);
    }

    // With DISTINCT (claim filters), Postgres and MySQL reject an ORDER BY column unless selected
    if let Some(sorting) = &query_params.sorting {
        let (column, _) = sorting.column.get_column();
        query = query.column_as(SimpleExpr::Column(column), "sort_key");
    }

    query
}

#[autometrics]
#[async_trait::async_trait]
impl CredentialRepository for CredentialProvider {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        let id = request.id;
        self.create_credentials(vec![request]).await?;
        Ok(id)
    }

    async fn create_credentials(
        &self,
        requests: Vec<Credential>,
    ) -> Result<Vec<CredentialId>, DataLayerError> {
        if requests.is_empty() {
            return Ok(vec![]);
        }
        let ids = requests.iter().map(|request| request.id).collect();
        let credentials = prepare_credentials(requests).await?;
        self.db
            .tx_with_config(
                insert_credentials_with_claims(&self.db, credentials).boxed(),
                // READ COMMITTED avoids InnoDB gap locks during parallel inserts.
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??;
        Ok(ids)
    }

    async fn delete_credentials(&self, credentials: &[Credential]) -> Result<(), DataLayerError> {
        let ids: Vec<_> = credentials.iter().map(|c| c.id).collect();
        credential::Entity::update_many()
            .filter(credential::Column::Id.is_in(ids))
            .set(credential::ActiveModel {
                deleted_at: Set(Some(one_core::clock::now_utc())),
                ..Default::default()
            })
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        Ok(())
    }

    async fn get_credential(&self, id: &CredentialId) -> Result<Credential, DataLayerError> {
        let credential = credential::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::Credential,
                id: (*id).into(),
            })?;

        Ok(self.credential_model_to_repository_model(credential))
    }

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .filter(credential::Column::InteractionId.eq(interaction_id.to_string()))
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(self.credentials_to_repository(credentials, false))
    }

    async fn get_credential_list(
        &self,
        query_params: CredentialListQuery,
    ) -> Result<GetCredentialList, DataLayerError> {
        let db_backend = self.db.supported_db_type();
        let skip_layout_properties = !query_params.include.as_ref().is_some_and(|include| {
            include.contains(&CredentialListIncludeEntityTypeEnum::LayoutProperties)
        });

        let (total_items, total_pages, credentials) = match &query_params.pagination {
            Some(pagination) => {
                // page of ids first, then the rows by id
                let page_query = with_credential_list_query(
                    credential::Entity::find()
                        .select_only()
                        .column(credential::Column::Id)
                        .column(credential::Column::CreatedDate),
                    &query_params,
                    db_backend,
                );
                let (items_count, page) = tokio::join!(
                    count_credentials(query_params.include_count, page_query.clone(), &self.db),
                    page_query.into_model::<CredentialIdModel>().all(&self.db)
                );
                let items_count = items_count?;
                let ids: Vec<CredentialId> = page
                    .map_err(to_data_layer_error)?
                    .into_iter()
                    .map(|row| row.id)
                    .collect();
                (
                    items_count,
                    items_count
                        .map(|count| calculate_pages_count(count, pagination.page_size as _)),
                    self.get_credentials_in_order(&ids).await?,
                )
            }
            None => {
                // no pagination: all rows, no pages
                let credentials = with_credential_list_query(
                    credential::Entity::find(),
                    &query_params,
                    db_backend,
                )
                .all(&self.db)
                .await
                .map_err(to_data_layer_error)?;
                (
                    query_params
                        .include_count
                        .then_some(credentials.len() as u64),
                    query_params.include_count.then_some(0),
                    credentials,
                )
            }
        };

        Ok(GetCredentialList {
            values: self.credentials_to_repository(credentials, skip_layout_properties),
            total_pages,
            total_items,
        })
    }

    async fn update_credential(
        &self,
        credential_id: CredentialId,
        request: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        let holder_identifier_id = match request.holder_identifier_id {
            None => Unchanged(Default::default()),
            Some(identifier_id) => Set(Some(identifier_id)),
        };

        let issuer_identifier_id = match request.issuer_identifier_id {
            None => Unchanged(Default::default()),
            Some(identifier_id) => Set(Some(identifier_id)),
        };

        let issuer_certificate_id = match request.issuer_certificate_id {
            None => Unchanged(Default::default()),
            Some(certificate_id) => Set(Some(certificate_id)),
        };

        let credential_blob_id = match request.credential_blob_id {
            None => Unchanged(Default::default()),
            Some(blob_id) => Set(Some(blob_id)),
        };

        let interaction_id = match request.interaction {
            None => Unchanged(Default::default()),
            Some(interaction_id) => Set(Some(interaction_id)),
        };

        let key_id = match request.key {
            None => Unchanged(Default::default()),
            Some(key_id) => Set(Some(key_id)),
        };

        let redirect_uri = match request.redirect_uri {
            None => Unchanged(Default::default()),
            Some(redirect_uri) => Set(redirect_uri),
        };

        let suspend_end_date = from_clearable(request.suspend_end_date);
        let consumed_at = from_clearable(request.consumed_at);

        let state = match request.state {
            None => NotSet,
            Some(state) => Set(state.into()),
        };

        let issuance_date = match request.issuance_date {
            None => Unchanged(Default::default()),
            Some(issuance_date) => Set(issuance_date.into()),
        };

        let expires_at = match request.expires_at {
            None => Unchanged(Default::default()),
            Some(expires_at) => Set(Some(expires_at)),
        };

        let wallet_key_attestation_blob_id = match request.wallet_key_attestation_blob_id {
            None => Unchanged(Default::default()),
            Some(blob_id) => Set(Some(blob_id)),
        };

        let wallet_instance_attestation_blob_id = match request.wallet_instance_attestation_blob_id
        {
            None => Unchanged(Default::default()),
            Some(blob_id) => Set(Some(blob_id)),
        };

        let format = match request.format {
            None => Unchanged(Default::default()),
            Some(format_id) => Set(Some(format_id)),
        };

        let update_model = credential::ActiveModel {
            id: Unchanged(credential_id),
            last_modified: Set(one_core::clock::now_utc()),
            issuance_date,
            expires_at,
            holder_identifier_id,
            issuer_identifier_id,
            issuer_certificate_id,
            interaction_id,
            key_id,
            redirect_uri,
            suspend_end_date,
            consumed_at,
            state,
            credential_blob_id,
            wallet_key_attestation_blob_id,
            wallet_instance_attestation_blob_id,
            format,
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn get_credentials_by_claim_names(
        &self,
        claim_names: Vec<String>,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .join(
                JoinType::InnerJoin,
                credential::Relation::CredentialClaim.def(),
            )
            .join(JoinType::InnerJoin, credential_claim::Relation::Claim.def())
            .join(
                JoinType::InnerJoin,
                claim::Relation::ClaimSchema
                    .def()
                    .on_condition(move |_left, _right| {
                        Expr::col((claim_schema::Entity, claim_schema::Column::Key))
                            .is_in(&claim_names)
                            .into_condition()
                    }),
            )
            .distinct()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(self.credentials_to_repository(credentials, false))
    }

    async fn delete_credential_blobs(
        &self,
        request: HashSet<CredentialId>,
    ) -> Result<(), DataLayerError> {
        credential::Entity::update_many()
            .filter(credential::Column::Id.is_in(request))
            .set(credential::ActiveModel {
                credential_blob_id: Set(None),
                ..Default::default()
            })
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }
}
