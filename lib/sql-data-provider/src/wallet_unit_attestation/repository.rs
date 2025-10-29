use std::collections::HashMap;

use one_core::model::wallet_unit_attestation::{
    UpdateWalletUnitAttestationRequest, WalletUnitAttestation, WalletUnitAttestationRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use sea_orm::sea_query::IntoCondition;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Unchanged};
use shared_types::{HolderWalletUnitId, KeyId, WalletUnitAttestationId};
use time::OffsetDateTime;

use crate::entity::wallet_unit_attestation;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::wallet_unit_attestation::WalletUnitAttestationProvider;

#[async_trait::async_trait]
impl WalletUnitAttestationRepository for WalletUnitAttestationProvider {
    async fn create_wallet_unit_attestation(
        &self,
        request: WalletUnitAttestation,
    ) -> Result<WalletUnitAttestationId, DataLayerError> {
        let wallet_unit_attestation = wallet_unit_attestation::ActiveModel::try_from(request)?
            .insert(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;

        Ok(wallet_unit_attestation.id)
    }

    async fn get_wallet_unit_attestation_by_key_id(
        &self,
        key_id: &KeyId,
    ) -> Result<Option<WalletUnitAttestation>, DataLayerError> {
        Ok(wallet_unit_attestation::Entity::find()
            .filter(
                wallet_unit_attestation::Column::AttestedKeyId
                    .eq(key_id)
                    .into_condition(),
            )
            .one(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?
            .map(Into::into))
    }

    async fn get_wallet_unit_attestations_by_holder_wallet_unit(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
        relations: &WalletUnitAttestationRelations,
    ) -> Result<Vec<WalletUnitAttestation>, DataLayerError> {
        let entity_models: Vec<wallet_unit_attestation::Model> =
            wallet_unit_attestation::Entity::find()
                .filter(
                    wallet_unit_attestation::Column::HolderWalletUnitId
                        .eq(holder_wallet_unit_id)
                        .into_condition(),
                )
                .all(&self.db.tx())
                .await
                .map_err(to_data_layer_error)?;

        if entity_models.is_empty() {
            return Ok(vec![]);
        };

        let key_id_map = entity_models
            .iter()
            .map(|model| (model.id, model.attested_key_id))
            .collect::<HashMap<_, _>>();
        let mut wallet_unit_attestations: Vec<_> = entity_models
            .into_iter()
            .map(WalletUnitAttestation::from)
            .collect();

        if relations.attested_key.is_some() {
            let keys = self
                .key_repository
                .get_keys(&key_id_map.values().cloned().collect::<Vec<_>>())
                .await?;
            for attestation in wallet_unit_attestations.iter_mut() {
                let key_id = key_id_map.get(&attestation.id).ok_or(
                    DataLayerError::MissingRequiredRelation {
                        relation: "walletUnitAttestation-key",
                        id: attestation.id.to_string(),
                    },
                )?;
                let key = keys.iter().find(|key| key.id == *key_id).ok_or(
                    DataLayerError::MissingRequiredRelation {
                        relation: "walletUnitAttestation-key",
                        id: attestation.id.to_string(),
                    },
                )?;
                attestation.attested_key = Some(key.clone());
            }
        }
        Ok(wallet_unit_attestations)
    }

    async fn update_wallet_attestation(
        &self,
        id: &WalletUnitAttestationId,
        request: UpdateWalletUnitAttestationRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = wallet_unit_attestation::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            expiration_date: request.expiration_date.map(Set).unwrap_or_default(),
            attestation: request
                .attestation
                .map(String::into_bytes)
                .map(Set)
                .unwrap_or_default(),
            ..Default::default()
        };

        update_model
            .update(&self.db.tx())
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }
}
