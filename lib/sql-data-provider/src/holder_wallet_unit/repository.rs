use async_trait::async_trait;
use futures::FutureExt;
use one_core::model::holder_wallet_unit::{
    CreateHolderWalletUnitRequest, HolderWalletUnit, HolderWalletUnitRelations,
    UpdateHolderWalletUnitRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use sea_orm::{ActiveModelTrait, EntityTrait, Set, Unchanged};
use shared_types::HolderWalletUnitId;
use time::OffsetDateTime;

use crate::entity::holder_wallet_unit;
use crate::holder_wallet_unit::HolderWalletUnitProvider;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[async_trait]
impl HolderWalletUnitRepository for HolderWalletUnitProvider {
    async fn create_holder_wallet_unit(
        &self,
        request: CreateHolderWalletUnitRequest,
    ) -> Result<HolderWalletUnitId, DataLayerError> {
        let model = holder_wallet_unit::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(model.id)
    }

    async fn get_holder_wallet_unit(
        &self,
        id: &HolderWalletUnitId,
        relations: &HolderWalletUnitRelations,
    ) -> Result<Option<HolderWalletUnit>, DataLayerError> {
        let model = holder_wallet_unit::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        let Some(model) = model else { return Ok(None) };

        let org_id = model.organisation_id;
        let auth_key_id = model.authentication_key_id;
        let mut holder_wallet_unit = HolderWalletUnit::from(model);

        if let Some(org_relations) = &relations.organisation {
            let org = self
                .organisation_repository
                .get_organisation(&org_id, org_relations)
                .await?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "holder_wallet_unit-organisation",
                    id: org_id.to_string(),
                })?;
            holder_wallet_unit.organisation = Some(org)
        }

        if let Some(key_relations) = &relations.authentication_key {
            let key = self
                .key_repository
                .get_key(&auth_key_id, key_relations)
                .await?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "holder_wallet_unit-organisation",
                    id: org_id.to_string(),
                })?;
            holder_wallet_unit.authentication_key = Some(key)
        }

        if let Some(wallet_unit_attestation_relations) = &relations.wallet_unit_attestations {
            let attestations = self
                .wallet_unit_attestation_repository
                .get_wallet_unit_attestations_by_holder_wallet_unit(
                    id,
                    wallet_unit_attestation_relations,
                )
                .await?;
            holder_wallet_unit.wallet_unit_attestations = Some(attestations)
        }

        Ok(Some(holder_wallet_unit))
    }

    async fn update_holder_wallet_unit(
        &self,
        id: &HolderWalletUnitId,
        request: UpdateHolderWalletUnitRequest,
    ) -> Result<(), DataLayerError> {
        let action = async {
            let update_model = holder_wallet_unit::ActiveModel {
                id: Unchanged(*id),
                last_modified: Set(OffsetDateTime::now_utc()),
                status: request
                    .status
                    .map(|status| Set(status.into()))
                    .unwrap_or_default(),
                ..Default::default()
            };
            update_model
                .update(&self.db)
                .await
                .map_err(to_update_data_layer_error)?;

            let Some(attestations) = request.wallet_unit_attestations else {
                return Ok(());
            };

            for attestation in attestations {
                let result = self
                    .wallet_unit_attestation_repository
                    .create_wallet_unit_attestation(attestation.clone())
                    .await;
                if let Err(err) = result {
                    match err {
                        DataLayerError::AlreadyExists => {
                            let attestation_id = attestation.id;
                            self.wallet_unit_attestation_repository
                                .update_wallet_attestation(&attestation_id, attestation.into())
                                .await?
                        }
                        err => return Err(err),
                    }
                }
            }
            Ok(())
        }
        .boxed();
        self.db.tx(action).await?
    }
}
