use one_core::model::wallet_unit_attestation::{
    UpdateWalletUnitAttestationRequest, WalletUnitAttestation, WalletUnitAttestationRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use sea_orm::sea_query::IntoCondition;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Unchanged};
use shared_types::{OrganisationId, WalletUnitAttestationId};
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
        let wallet_unit_attestation = wallet_unit_attestation::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(wallet_unit_attestation.id)
    }

    async fn get_wallet_unit_attestation_by_organisation(
        &self,
        organisation_id: &OrganisationId,
        relations: &WalletUnitAttestationRelations,
    ) -> Result<Option<WalletUnitAttestation>, DataLayerError> {
        let entity_model: Vec<wallet_unit_attestation::Model> =
            wallet_unit_attestation::Entity::find()
                .filter(
                    wallet_unit_attestation::Column::OrganisationId
                        .eq(organisation_id)
                        .into_condition(),
                )
                .all(&self.db)
                .await
                .map_err(to_data_layer_error)?;

        let Some(entity_model) = entity_model.into_iter().next() else {
            return Ok(None);
        };

        let wallet_unit_attestation_id = entity_model.id;
        let key_id = entity_model.key_id.to_owned();
        let organisation_id = entity_model.organisation_id.to_owned();

        let mut wallet_unit_attestation = WalletUnitAttestation::from(entity_model);

        if let Some(key_id) = key_id {
            if let Some(key_relations) = &relations.key {
                wallet_unit_attestation.key = Some(
                    self.key_repository
                        .get_key(&key_id, key_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "wallet_unit_attestation-key",
                            id: wallet_unit_attestation_id.to_string(),
                        })?,
                );
            }
        }

        if let Some(organisation_id) = organisation_id {
            if let Some(organisation_relations) = &relations.organisation {
                wallet_unit_attestation.organisation = Some(
                    self.organisation_repository
                        .get_organisation(&organisation_id, organisation_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "wallet_unit_attestation-organisation",
                            id: wallet_unit_attestation_id.to_string(),
                        })?,
                );
            }
        }
        Ok(Some(wallet_unit_attestation))
    }

    async fn update_wallet_attestation(
        &self,
        id: &WalletUnitAttestationId,
        request: UpdateWalletUnitAttestationRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = wallet_unit_attestation::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            status: request
                .status
                .map(|status| Set(status.into()))
                .unwrap_or_default(),
            expiration_date: request.expiration_date.map(Set).unwrap_or_default(),
            attestation: request
                .attestation
                .map(String::into_bytes)
                .map(Set)
                .unwrap_or_default(),
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }
}
