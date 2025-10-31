use std::collections::HashSet;

use async_trait::async_trait;
use one_core::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::wallet_unit_attested_key_repository::WalletUnitAttestedKeyRepository;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Unchanged};
use shared_types::{WalletUnitAttestedKeyId, WalletUnitId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::entity::wallet_unit_attested_key;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::wallet_unit_attested_key::WalletUnitAttestedKeyProvider;
use crate::wallet_unit_attested_key::mapper::model_to_attested_key;

#[async_trait]
impl WalletUnitAttestedKeyRepository for WalletUnitAttestedKeyProvider {
    async fn create_attested_key(
        &self,
        request: WalletUnitAttestedKey,
    ) -> Result<WalletUnitAttestedKeyId, DataLayerError> {
        let model: wallet_unit_attested_key::ActiveModel = request.try_into()?;
        let result = model.insert(&self.db).await.map_err(to_data_layer_error)?;
        Ok(result.id)
    }

    async fn update_attested_key(
        &self,
        request: WalletUnitAttestedKey,
    ) -> Result<(), DataLayerError> {
        let id = request.id;
        let mut model = wallet_unit_attested_key::ActiveModel::try_from(request)?;
        model.id = Unchanged(id);
        model.last_modified = Set(OffsetDateTime::now_utc());
        wallet_unit_attested_key::Entity::update(model)
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get_attested_key(
        &self,
        id: &WalletUnitAttestedKeyId,
        relations: &WalletUnitAttestedKeyRelations,
    ) -> Result<Option<WalletUnitAttestedKey>, DataLayerError> {
        let model = wallet_unit_attested_key::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let revocation_list_id = model.as_ref().and_then(|v| v.revocation_list_id);
        let mut attested_key = model.map(WalletUnitAttestedKey::try_from).transpose()?;

        if let Some(attested_key) = &mut attested_key
            && let Some(revocation_list_relations) = &relations.revocation_list
            && let Some(revocation_list_id) = revocation_list_id
        {
            attested_key.revocation_list = Some(
                self.revocation_list_repository
                    .get_revocation_list(&revocation_list_id, revocation_list_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "wallet_unit_attested_key-revocation_list",
                        id: revocation_list_id.to_string(),
                    })?,
            );
        }

        Ok(attested_key)
    }

    async fn get_by_wallet_unit_id(
        &self,
        id: WalletUnitId,
        relations: &WalletUnitAttestedKeyRelations,
    ) -> Result<Vec<WalletUnitAttestedKey>, DataLayerError> {
        let models = wallet_unit_attested_key::Entity::find()
            .filter(wallet_unit_attested_key::Column::WalletUnitId.eq(id))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        let revocation_lists = if let Some(revocation_list_relation) = &relations.revocation_list {
            // Use hashset to filter out duplicates
            let set =
                HashSet::<Uuid>::from_iter(models.iter().filter_map(|m| m.revocation_list_id));
            let revocation_list_ids = Vec::from_iter(set);
            self.revocation_list_repository
                .get_revocation_lists(&revocation_list_ids, revocation_list_relation)
                .await?
        } else {
            vec![]
        };
        models
            .into_iter()
            .map(|model| model_to_attested_key(model, &revocation_lists))
            .collect()
    }
}
