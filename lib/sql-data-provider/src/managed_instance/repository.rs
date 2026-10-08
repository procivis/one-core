use autometrics::autometrics;
use futures::FutureExt;
use migration::supported_db_type::WithSupportedDbType;
use one_core::model::managed_instance::{
    ManagedInstance, ManagedInstanceList, ManagedInstanceListQuery, UpdateManagedInstanceRequest,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::managed_instance_repository::ManagedInstanceRepository;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, Set, Unchanged};
use shared_types::ManagedInstanceId;

use super::ManagedInstanceProvider;
use super::mapper::managed_instance_from_model;
use crate::common::list_query_with_custom_model;
use crate::entity::managed_instance;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl ManagedInstanceRepository for ManagedInstanceProvider {
    async fn create(&self, request: ManagedInstance) -> Result<ManagedInstanceId, DataLayerError> {
        let attestations = request.attestations.clone();
        self.db
            .tx(async {
                let wallet_unit = managed_instance::ActiveModel::try_from(request)?
                    .insert(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;

                for attestation in &attestations.as_ref().await? {
                    self.managed_instance_attestation_repository
                        .create_attestation(attestation.clone())
                        .await?;
                }

                Ok(wallet_unit.id)
            }
            .boxed())
            .await?
    }

    async fn get(&self, id: &ManagedInstanceId) -> Result<ManagedInstance, DataLayerError> {
        let wallet_unit = managed_instance::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::ManagedInstance,
                id: (*id).into(),
            })?;

        managed_instance_from_model(
            wallet_unit,
            &self.organisation_repository,
            &self.managed_instance_attestation_repository,
        )
    }

    async fn get_list(
        &self,
        query_params: ManagedInstanceListQuery,
    ) -> Result<ManagedInstanceList, DataLayerError> {
        let mut query = managed_instance::Entity::find()
            .with_list_query(&query_params, self.db.supported_db_type());

        if query_params.sorting.is_some() || query_params.pagination.is_some() {
            // fallback ordering
            query = query
                .order_by_desc(managed_instance::Column::CreatedDate)
                .order_by_desc(managed_instance::Column::Id);
        }

        list_query_with_custom_model(query, query_params, &self.db, |model| {
            managed_instance_from_model(
                model,
                &self.organisation_repository,
                &self.managed_instance_attestation_repository,
            )
        })
        .await
    }

    async fn update(
        &self,
        id: &ManagedInstanceId,
        request: UpdateManagedInstanceRequest,
    ) -> Result<(), DataLayerError> {
        let authentication_key_jwk = request
            .authentication_key_jwk
            .map(|pk| serde_json::to_string(&pk))
            .transpose()
            .map_err(|e| DataLayerError::MappingError(e.into()))?;
        let update_model = managed_instance::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(one_core::clock::now_utc()),
            status: request
                .status
                .map(|status| Set(status.into()))
                .unwrap_or_default(),
            last_issuance: request
                .last_issuance
                .map(|last_issuance| Set(last_issuance.into()))
                .unwrap_or_default(),
            authentication_key_jwk: authentication_key_jwk
                .map(|key| Set(Some(key)))
                .unwrap_or_default(),
            user_sub: request
                .user_sub
                .map(|sub| Set(Some(sub)))
                .unwrap_or_default(),
            verifier_csr: request.verifier_csr.map(Set).unwrap_or_default(),
            verifier_signature_ids: request
                .verifier_signature_ids
                .map(|ids| Set(Some(ids.into())))
                .unwrap_or_default(),
            version: request
                .version
                .map(|version| Set(Some(version)))
                .unwrap_or_default(),
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn delete(&self, id: &ManagedInstanceId) -> Result<(), DataLayerError> {
        managed_instance::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }
}
