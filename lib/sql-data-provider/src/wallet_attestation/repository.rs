use autometrics::autometrics;
use migration::supported_db_type::WithSupportedDbType;
use one_core::model::wallet_attestation::{
    WalletAttestation, WalletAttestationList, WalletAttestationListQuery,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::wallet_attestation_repository::WalletAttestationRepository;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder};
use shared_types::WalletAttestationId;

use super::mapper::wallet_instance_attestation_from_model;
use crate::common::list_query_with_custom_model;
use crate::entity::wallet_attestation;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::to_data_layer_error;
use crate::wallet_attestation::WalletAttestationProvider;

#[autometrics]
#[async_trait::async_trait]
impl WalletAttestationRepository for WalletAttestationProvider {
    async fn create(
        &self,
        request: WalletAttestation,
    ) -> Result<WalletAttestationId, DataLayerError> {
        let wallet_attestation = wallet_attestation::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(wallet_attestation.id)
    }

    async fn get_attestations(
        &self,
        query_params: WalletAttestationListQuery,
    ) -> Result<WalletAttestationList, DataLayerError> {
        let query = wallet_attestation::Entity::find()
            .with_list_query(&query_params, self.db.supported_db_type())
            .order_by_desc(wallet_attestation::Column::CreatedDate)
            .order_by_desc(wallet_attestation::Column::Id);

        list_query_with_custom_model(query, query_params, &self.db, |model| {
            Ok(wallet_instance_attestation_from_model(
                model,
                &self.key_repository,
            ))
        })
        .await
    }
}
