use autometrics::autometrics;
use one_core::model::identifier_trust_information::IdentifierTrustInformation;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use one_dto_mapper::try_convert_inner;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use shared_types::{IdentifierId, IdentifierTrustInformationId};

use crate::entity::identifier_trust_information;
use crate::identifier_trust_information::IdentifierTrustInformationProvider;
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl IdentifierTrustInformationRepository for IdentifierTrustInformationProvider {
    async fn create(
        &self,
        trust_information: IdentifierTrustInformation,
    ) -> Result<IdentifierTrustInformationId, DataLayerError> {
        let model = identifier_trust_information::ActiveModel::from(trust_information)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(model.id)
    }

    async fn get_by_identifier_id(
        &self,
        identifier_id: &IdentifierId,
    ) -> Result<Vec<IdentifierTrustInformation>, DataLayerError> {
        let models = identifier_trust_information::Entity::find()
            .filter(identifier_trust_information::Column::IdentifierId.eq(identifier_id))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        try_convert_inner(models)
    }
}
