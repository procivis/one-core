use async_trait::async_trait;
use one_core::model::managed_instance_attestation::{
    ManagedInstanceAttestation, UpdateManagedInstanceAttestationRequest,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::managed_instance_attestation_repository::ManagedInstanceAttestationRepository;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Unchanged};
use shared_types::{ManagedInstanceAttestationId, ManagedInstanceId};

use super::ManagedInstanceAttestationProvider;
use super::mapper::attested_key_from_model;
use crate::entity::managed_instance_attestation;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[async_trait]
impl ManagedInstanceAttestationRepository for ManagedInstanceAttestationProvider {
    async fn create_attestation(
        &self,
        request: ManagedInstanceAttestation,
    ) -> Result<ManagedInstanceAttestationId, DataLayerError> {
        let model: managed_instance_attestation::ActiveModel = request.into();
        let result = model.insert(&self.db).await.map_err(to_data_layer_error)?;
        Ok(result.id)
    }

    async fn update_attestation(
        &self,
        id: &ManagedInstanceAttestationId,
        request: UpdateManagedInstanceAttestationRequest,
    ) -> Result<(), DataLayerError> {
        let attestation_content_hash = match request.attestation_content_hash {
            Some(value) => Set(value),
            None => Default::default(),
        };
        let model = managed_instance_attestation::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(one_core::clock::now_utc()),
            attestation_content_hash,
            ..Default::default()
        };
        managed_instance_attestation::Entity::update(model)
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get_attestation(
        &self,
        id: &ManagedInstanceAttestationId,
    ) -> Result<ManagedInstanceAttestation, DataLayerError> {
        let model = managed_instance_attestation::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::ManagedInstanceAttestation,
                id: (*id).into(),
            })?;

        Ok(attested_key_from_model(
            model,
            &self.db,
            &self.revocation_list_repository,
        ))
    }

    async fn get_by_instance_id(
        &self,
        id: &ManagedInstanceId,
    ) -> Result<Vec<ManagedInstanceAttestation>, DataLayerError> {
        let models = managed_instance_attestation::Entity::find()
            .filter(managed_instance_attestation::Column::ManagedInstanceId.eq(id))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let mut results = vec![];
        for model in models {
            results.push(attested_key_from_model(
                model,
                &self.db,
                &self.revocation_list_repository,
            ));
        }
        Ok(results)
    }
}
