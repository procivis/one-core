use one_core::{
    model::{credential::CredentialId, lvvc::Lvvc},
    repository::{error::DataLayerError, lvvc_repository::LvvcRepository},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
};

use crate::entity::lvvc;

use super::LvvcProvider;

#[async_trait::async_trait]
impl LvvcRepository for LvvcProvider {
    async fn insert(&self, lvvc: Lvvc) -> Result<(), DataLayerError> {
        lvvc::Model::from(lvvc)
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
        let model = lvvc::Entity::find()
            .filter(lvvc::Column::CredentialId.eq(credential_id.to_string()))
            .order_by_desc(lvvc::Column::CreatedDate)
            .one(&self.db_conn)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        model.map(Lvvc::try_from).transpose()
    }

    async fn get_all_by_credential_id(
        &self,
        credential_id: CredentialId,
    ) -> Result<Vec<Lvvc>, DataLayerError> {
        let model = lvvc::Entity::find()
            .filter(lvvc::Column::CredentialId.eq(credential_id.to_string()))
            .all(&self.db_conn)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        model
            .into_iter()
            .map(Lvvc::try_from)
            .collect::<Result<_, _>>()
    }
}
