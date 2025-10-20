use one_core::model::validity_credential::{ValidityCredential, ValidityCredentialType};
use one_core::repository::error::DataLayerError;
use one_core::repository::validity_credential_repository::ValidityCredentialRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
};
use shared_types::CredentialId;

use super::ValidityCredentialProvider;
use crate::entity::validity_credential;

#[async_trait::async_trait]
impl ValidityCredentialRepository for ValidityCredentialProvider {
    async fn insert(&self, credential: ValidityCredential) -> Result<(), DataLayerError> {
        validity_credential::Model::from(credential)
            .into_active_model()
            .insert(&self.db_conn.tx())
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        Ok(())
    }

    async fn get_latest_by_credential_id(
        &self,
        credential_id: CredentialId,
        credential_type: ValidityCredentialType,
    ) -> Result<Option<ValidityCredential>, DataLayerError> {
        let credential_type = validity_credential::ValidityCredentialType::from(credential_type);

        let model = validity_credential::Entity::find()
            .filter(
                validity_credential::Column::CredentialId
                    .eq(credential_id)
                    .and(validity_credential::Column::Type.eq(credential_type)),
            )
            .order_by_desc(validity_credential::Column::CreatedDate)
            .one(&self.db_conn.tx())
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        model.map(ValidityCredential::try_from).transpose()
    }

    async fn get_all_by_credential_id(
        &self,
        credential_id: CredentialId,
        credential_type: ValidityCredentialType,
    ) -> Result<Vec<ValidityCredential>, DataLayerError> {
        let credential_type = validity_credential::ValidityCredentialType::from(credential_type);

        let model = validity_credential::Entity::find()
            .filter(
                validity_credential::Column::CredentialId
                    .eq(credential_id)
                    .and(validity_credential::Column::Type.eq(credential_type)),
            )
            .all(&self.db_conn.tx())
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        model
            .into_iter()
            .map(ValidityCredential::try_from)
            .collect::<Result<_, _>>()
    }

    async fn remove_all_by_credential_id(
        &self,
        credential_id: CredentialId,
        credential_type: ValidityCredentialType,
    ) -> Result<(), DataLayerError> {
        let credential_type = validity_credential::ValidityCredentialType::from(credential_type);

        validity_credential::Entity::delete_many()
            .filter(
                validity_credential::Column::CredentialId
                    .eq(credential_id)
                    .and(validity_credential::Column::Type.eq(credential_type)),
            )
            .exec(&self.db_conn.tx())
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        Ok(())
    }
}
