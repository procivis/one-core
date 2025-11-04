use async_trait::async_trait;
use one_core::model::revocation_list::RevocationListRelations;
use one_core::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRelations, WalletUnitAttestedKeyRevocationInfo,
    WalletUnitAttestedKeyUpsertRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::wallet_unit_attested_key_repository::WalletUnitAttestedKeyRepository;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryTrait, Set,
    Unchanged,
};
use shared_types::{WalletUnitAttestedKeyId, WalletUnitId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::entity::{revocation_list_entry, wallet_unit_attested_key};
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::wallet_unit_attested_key::WalletUnitAttestedKeyProvider;

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

    async fn upsert_attested_key(
        &self,
        request: WalletUnitAttestedKeyUpsertRequest,
    ) -> Result<WalletUnitAttestedKeyId, DataLayerError> {
        let id = request.id;
        let model = wallet_unit_attested_key::ActiveModel::try_from(request)?;
        let stmt = wallet_unit_attested_key::Entity::insert(model)
            .on_conflict(
                OnConflict::column(wallet_unit_attested_key::Column::Id)
                    .update_column(wallet_unit_attested_key::Column::LastModified)
                    .update_column(wallet_unit_attested_key::Column::ExpirationDate)
                    .update_column(wallet_unit_attested_key::Column::PublicKeyJwk)
                    .update_column(wallet_unit_attested_key::Column::WalletUnitId)
                    .to_owned(),
            )
            .build(self.db.get_database_backend());
        self.db
            .execute(stmt)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(id)
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

        Ok(match model {
            Some(model) => Some(self.convert_model(model, relations).await?),
            None => None,
        })
    }

    async fn get_by_wallet_unit_id(
        &self,
        id: &WalletUnitId,
        relations: &WalletUnitAttestedKeyRelations,
    ) -> Result<Vec<WalletUnitAttestedKey>, DataLayerError> {
        let models = wallet_unit_attested_key::Entity::find()
            .filter(wallet_unit_attested_key::Column::WalletUnitId.eq(id))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let mut results = vec![];
        for model in models {
            results.push(self.convert_model(model, relations).await?);
        }
        Ok(results)
    }
}

impl WalletUnitAttestedKeyProvider {
    async fn convert_model(
        &self,
        model: wallet_unit_attested_key::Model,
        relations: &WalletUnitAttestedKeyRelations,
    ) -> Result<WalletUnitAttestedKey, DataLayerError> {
        let revocation = if let Some(revocation_relations) = &relations.revocation {
            self.get_revocation(&model, revocation_relations).await?
        } else {
            None
        };

        let mut result = WalletUnitAttestedKey::try_from(model)?;
        result.revocation = revocation;

        Ok(result)
    }

    async fn get_revocation(
        &self,
        model: &wallet_unit_attested_key::Model,
        relations: &RevocationListRelations,
    ) -> Result<Option<WalletUnitAttestedKeyRevocationInfo>, DataLayerError> {
        let Some(revocation_list_entry_id) = model.revocation_list_entry_id else {
            return Ok(None);
        };

        let revocation_list_entry =
            revocation_list_entry::Entity::find_by_id(revocation_list_entry_id)
                .one(&self.db)
                .await
                .map_err(to_data_layer_error)?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "wallet_unit_attested_key-revocation_list_entry",
                    id: revocation_list_entry_id.to_string(),
                })?;

        let revocation_list = self
            .revocation_list_repository
            .get_revocation_list(
                &Uuid::parse_str(&revocation_list_entry.revocation_list_id)
                    .map_err(|_| DataLayerError::MappingError)?,
                relations,
            )
            .await?
            .ok_or(DataLayerError::MissingRequiredRelation {
                relation: "wallet_unit_attested_key-revocation_list",
                id: revocation_list_entry.revocation_list_id.to_string(),
            })?;

        Ok(Some(WalletUnitAttestedKeyRevocationInfo {
            revocation_list,
            revocation_list_index: revocation_list_entry.index as _,
        }))
    }
}
