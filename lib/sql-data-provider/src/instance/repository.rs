use async_trait::async_trait;
use futures::FutureExt;
use one_core::model::instance::{
    Instance, InstanceList, InstanceListQuery, InstanceRole, UpdateInstanceRequest,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::instance_repository::InstanceRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    Unchanged,
};
use shared_types::{InstanceId, OrganisationId};

use crate::common::list_query_with_custom_model;
use crate::entity::instance;
use crate::instance::InstanceProvider;
use crate::instance::mapper::instance_from_model;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[async_trait]
impl InstanceRepository for InstanceProvider {
    async fn create(&self, request: Instance) -> Result<InstanceId, DataLayerError> {
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
            &self.wallet_unit_attestation_repository,
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
            &self.wallet_unit_attestation_repository,
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

            let Some(attestations) = request.wallet_unit_attestations else {
                return Ok(());
            };

            for attestation in attestations {
                let result = self
                    .wallet_unit_attestation_repository
                    .create_wallet_instance_attestation(attestation.clone())
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

    async fn list(&self, query_params: InstanceListQuery) -> Result<InstanceList, DataLayerError> {
        let query = instance::Entity::find()
            .with_list_query(&query_params, self.db.get_database_backend())
            .order_by_desc(instance::Column::CreatedDate)
            .order_by_desc(instance::Column::Id);

        list_query_with_custom_model(query, query_params, &self.db, |m| {
            Ok(instance_from_model(
                m,
                &self.organisation_repository,
                &self.key_repository,
                &self.wallet_unit_attestation_repository,
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
