use autometrics::autometrics;
use futures::FutureExt;
use migration::supported_db_type::WithSupportedDbType;
use one_core::model::did::{Did, DidListQuery, GetDidList, UpdateDidRequest};
use one_core::proto::transaction_manager::IsolationLevel;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::error::{DataLayerError, EntityKind};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, Unchanged,
};
use shared_types::{DidId, DidValue, OrganisationId};

use super::DidProvider;
use super::mapper::did_from_model;
use crate::common::list_query_with_custom_model;
use crate::entity::{did, key_did};
use crate::list_query_generic::{SelectWithFilterJoin, SelectWithListQuery};
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl DidRepository for DidProvider {
    async fn get_did(&self, id: &DidId) -> Result<Did, DataLayerError> {
        let did = did::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::Did,
                id: (*id).into(),
            })?;

        Ok(did_from_model(
            did,
            &self.db,
            &self.organisation_repository,
            &self.key_repository,
        ))
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        organisation: Option<Option<OrganisationId>>,
    ) -> Result<Option<Did>, DataLayerError> {
        let mut query = did::Entity::find()
            .filter(did::Column::Did.eq(value))
            .filter(did::Column::DeletedAt.is_null());

        if let Some(organisation_filter) = organisation {
            query = match organisation_filter {
                Some(organisation_id) => {
                    query.filter(did::Column::OrganisationId.eq(organisation_id))
                }
                None => query.filter(did::Column::OrganisationId.is_null()),
            }
        }

        let did = query
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(did.map(|did| {
            did_from_model(
                did,
                &self.db,
                &self.organisation_repository,
                &self.key_repository,
            )
        }))
    }

    async fn get_did_list(&self, query_params: DidListQuery) -> Result<GetDidList, DataLayerError> {
        let query = did::Entity::find()
            .filter(did::Column::DeletedAt.is_null())
            .with_filter_join(&query_params)
            .with_list_query(&query_params, self.db.supported_db_type())
            .order_by_desc(did::Column::CreatedDate)
            .order_by_desc(did::Column::Id);

        list_query_with_custom_model(query, query_params, &self.db, |did| {
            Ok(did_from_model(
                did,
                &self.db,
                &self.organisation_repository,
                &self.key_repository,
            ))
        })
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError> {
        let keys = request.keys.to_owned();

        let did = self
            .db
            .tx_with_config(
                async {
                    let did = did::ActiveModel::from(request)
                        .insert(&self.db)
                        .await
                        .map_err(to_data_layer_error)?;

                    let keys = keys.as_ref().await?;
                    if !keys.is_empty() {
                        key_did::Entity::insert_many(
                            keys.into_iter()
                                .map(|key| key_did::ActiveModel {
                                    did_id: Set(did.id),
                                    key_id: Set(key.key.id),
                                    role: Set(key.role.into()),
                                    reference: Set(key.reference.to_owned()),
                                })
                                .collect::<Vec<_>>(),
                        )
                        .exec(&self.db)
                        .await
                        .map_err(to_data_layer_error)?;
                    }

                    Ok::<_, DataLayerError>(did)
                }
                .boxed(),
                // In isolation mode "read committed" InnoDB will _not_ create gap locks. Given there
                // are multiple unique indexes, this is necessary to avoid deadlocks during parallel
                // inserts.
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??;

        Ok(did.id)
    }

    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn update_did(
        &self,
        id: &DidId,
        request: UpdateDidRequest,
    ) -> Result<(), DataLayerError> {
        let UpdateDidRequest { deactivated, log } = request;

        let did: did::ActiveModel = did::ActiveModel {
            id: Unchanged(*id),
            deactivated: deactivated.map(Set).unwrap_or_default(),
            log: log.map(Set).unwrap_or_default(),
            ..Default::default()
        };

        did.update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn delete_did(&self, did: &Did) -> Result<(), DataLayerError> {
        let now = one_core::clock::now_utc();

        let update_model = did::ActiveModel {
            id: Unchanged(did.id),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        did::Entity::update(update_model)
            .validate()
            .map_err(to_update_data_layer_error)?
            .filter(did::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map(|_| ())
            .map_err(to_update_data_layer_error)
    }

    async fn hard_delete(&self, id: &DidId) -> Result<(), DataLayerError> {
        self.db
            .tx(async {
                key_did::Entity::delete_many()
                    .filter(key_did::Column::DidId.eq(*id))
                    .exec(&self.db)
                    .await
                    .map_err(to_update_data_layer_error)?;
                did::Entity::delete_by_id(*id)
                    .exec(&self.db)
                    .await
                    .map_err(to_update_data_layer_error)?;
                Ok::<_, DataLayerError>(())
            })
            .await?
    }
}
