use std::sync::Arc;

use autometrics::autometrics;
use futures::FutureExt;
use one_core::model::organisation::{
    GetOrganisationList, Organisation, OrganisationListQuery, UpdateOrganisationRequest,
};
use one_core::proto::transaction_manager::IsolationLevel;
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use shared_types::OrganisationId;

use super::OrganisationProvider;
use super::mapper::{organisation_from_model, update_request_to_active_model};
use crate::common::list_query_with_custom_model;
use crate::entity::organisation;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl OrganisationRepository for OrganisationProvider {
    async fn create_organisation(
        &self,
        organisation: Organisation,
    ) -> Result<OrganisationId, DataLayerError> {
        let organisation_id = organisation.id;
        self.db
            .tx_with_config(
                async {
                    organisation::Entity::insert(organisation::ActiveModel::from(organisation))
                        .exec(&self.db)
                        .await
                        .map_err(to_data_layer_error)?;
                    Ok::<_, DataLayerError>(())
                }
                .boxed(),
                // In isolation mode "read committed" InnoDB will _not_ create gap locks. Given there
                // are multiple unique indexes, this is necessary to avoid deadlocks during parallel
                // inserts.
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??;
        Ok(organisation_id)
    }

    async fn update_organisation(
        &self,
        id: &OrganisationId,
        request: UpdateOrganisationRequest,
    ) -> Result<(), DataLayerError> {
        organisation::Entity::update(update_request_to_active_model(*id, request))
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get_organisation(&self, id: &OrganisationId) -> Result<Organisation, DataLayerError> {
        let organisation = organisation::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::Organisation,
                id: (*id).into(),
            })?;

        Ok(organisation_from_model(organisation, &self.cloned()))
    }

    async fn get_organisation_for_wallet_provider(
        &self,
        wallet_provider: &str,
    ) -> Result<Option<Organisation>, DataLayerError> {
        let organisation: Option<organisation::Model> = organisation::Entity::find()
            .filter(organisation::Column::WalletProvider.eq(wallet_provider))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(organisation.map(|org| organisation_from_model(org, &self.cloned())))
    }

    async fn get_organisation_for_verifier_provider(
        &self,
        verifier_provider: &str,
    ) -> Result<Option<Organisation>, DataLayerError> {
        let organisation: Option<organisation::Model> = organisation::Entity::find()
            .filter(organisation::Column::VerifierProvider.eq(verifier_provider))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(organisation.map(|org| organisation_from_model(org, &self.cloned())))
    }

    async fn get_organisation_list(
        &self,
        query_params: OrganisationListQuery,
    ) -> Result<GetOrganisationList, DataLayerError> {
        let query = organisation::Entity::find()
            .with_list_query(&query_params, self.db.get_database_backend());

        let repo = self.cloned();
        list_query_with_custom_model(query, query_params, &self.db, |org| {
            Ok(organisation_from_model(org, &repo))
        })
        .await
    }
}

impl OrganisationProvider {
    fn cloned(&self) -> Arc<dyn OrganisationRepository> {
        Arc::new(self.clone())
    }
}
