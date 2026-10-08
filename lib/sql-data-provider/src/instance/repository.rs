use async_trait::async_trait;
use autometrics::autometrics;
use futures::FutureExt;
use migration::supported_db_type::WithSupportedDbType;
use one_core::error::ErrorCodeMixinExt;
use one_core::model::instance::{
    Instance, InstanceList, InstanceListQuery, InstanceRole, UpdateInstanceRequest,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::instance_repository::InstanceRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, Unchanged,
};
use shared_types::{InstanceId, OrganisationId};

use crate::common::list_query_with_custom_model;
use crate::entity::instance;
use crate::instance::InstanceProvider;
use crate::instance::mapper::instance_from_model;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait]
impl InstanceRepository for InstanceProvider {
    async fn create(&self, request: Instance) -> Result<InstanceId, DataLayerError> {
        if !request.wallet_attestations.as_ref().await?.is_empty() {
            return Err(DataLayerError::IncorrectParameters(anyhow::anyhow!(
                "Wallet attestations must be created via their repository"
            ))
            .error_while("Wallet attestations must be created via its repository")
            .into());
        }

        let model = instance::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(model.id)
    }

    async fn get(&self, id: &InstanceId) -> Result<Instance, DataLayerError> {
        let model = instance::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::Instance,
                id: (*id).into(),
            })?;

        Ok(instance_from_model(
            model,
            &self.organisation_repository,
            &self.key_repository,
            &self.wallet_attestation_repository,
        ))
    }

    async fn get_by_role(
        &self,
        role: InstanceRole,
        organisation_id: OrganisationId,
    ) -> Result<Option<Instance>, DataLayerError> {
        let model = instance::Entity::find()
            .filter(instance::Column::Role.eq(instance::InstanceRole::from(role)))
            .filter(instance::Column::OrganisationId.eq(organisation_id))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        let Some(model) = model else { return Ok(None) };

        Ok(Some(instance_from_model(
            model,
            &self.organisation_repository,
            &self.key_repository,
            &self.wallet_attestation_repository,
        )))
    }

    async fn update(
        &self,
        id: &InstanceId,
        request: UpdateInstanceRequest,
    ) -> Result<(), DataLayerError> {
        let action = async {
            let update_model = instance::ActiveModel {
                id: Unchanged(*id),
                last_modified: Set(one_core::clock::now_utc()),
                status: request
                    .status
                    .map(|status| Set(status.into()))
                    .unwrap_or_default(),
                authentication_key_id: request
                    .authentication_key_id
                    .map(|key_id| Set(Some(key_id)))
                    .unwrap_or_default(),
                ..Default::default()
            };
            update_model
                .update(&self.db)
                .await
                .map_err(to_update_data_layer_error)?;

            Ok(())
        }
        .boxed();
        self.db.tx(action).await?
    }

    async fn list(&self, query_params: InstanceListQuery) -> Result<InstanceList, DataLayerError> {
        let query = instance::Entity::find()
            .with_list_query(&query_params, self.db.supported_db_type())
            .order_by_desc(instance::Column::CreatedDate)
            .order_by_desc(instance::Column::Id);

        list_query_with_custom_model(query, query_params, &self.db, |m| {
            Ok(instance_from_model(
                m,
                &self.organisation_repository,
                &self.key_repository,
                &self.wallet_attestation_repository,
            ))
        })
        .await
    }

    async fn delete(&self, id: &InstanceId) -> Result<(), DataLayerError> {
        instance::Entity::delete_by_id(*id)
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }
}
