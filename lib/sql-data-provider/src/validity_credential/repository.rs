use one_core::{
    model::lvvc::Lvvc,
    repository::{error::DataLayerError, lvvc_repository::LvvcRepository},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
};
use shared_types::CredentialId;

use crate::entity::validity_credential::{self, ValidityCredentialType};

use super::ValidityCredentialProvider;

#[async_trait::async_trait]
impl LvvcRepository for ValidityCredentialProvider {
    async fn insert(&self, lvvc: Lvvc) -> Result<(), DataLayerError> {
        validity_credential::Model::from(lvvc)
            .into_active_model()
            .insert(&self.db_conn)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        Ok(())
    }

    async fn get_latest_by_credential_id(
        &self,
        credential_id: CredentialId,
    ) -> Result<Option<Lvvc>, DataLayerError> {
        let model = validity_credential::Entity::find()
            .filter(
                validity_credential::Column::CredentialId
                    .eq(credential_id)
                    .and(validity_credential::Column::Type.eq(ValidityCredentialType::Lvvc)),
            )
            .order_by_desc(validity_credential::Column::CreatedDate)
            .one(&self.db_conn)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        model.map(Lvvc::try_from).transpose()
    }

    async fn get_all_by_credential_id(
        &self,
        credential_id: CredentialId,
    ) -> Result<Vec<Lvvc>, DataLayerError> {
        let model = validity_credential::Entity::find()
            .filter(
                validity_credential::Column::CredentialId
                    .eq(credential_id)
                    .and(validity_credential::Column::Type.eq(ValidityCredentialType::Lvvc)),
            )
            .all(&self.db_conn)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        model
            .into_iter()
            .map(Lvvc::try_from)
            .collect::<Result<_, _>>()
    }
}
