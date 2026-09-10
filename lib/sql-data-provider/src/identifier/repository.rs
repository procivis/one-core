use async_trait::async_trait;
use futures::FutureExt;
use one_core::model::identifier::{
    GetIdentifierList, Identifier, IdentifierListQuery, UpdateIdentifierRequest,
};
use one_core::proto::transaction_manager::IsolationLevel;
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::identifier_repository::IdentifierRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, Select, Set, Unchanged,
};
use shared_types::{DidId, IdentifierId};

use super::IdentifierProvider;
use super::mapper::identifier_from_model;
use crate::common::list_query_with_custom_model;
use crate::entity::identifier;
use crate::list_query_generic::{SelectWithFilterJoin, SelectWithListQuery};
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

impl IdentifierProvider {
    fn identifier_from_model(
        &self,
        model: identifier::Model,
    ) -> Result<Identifier, DataLayerError> {
        identifier_from_model(
            model,
            &self.organisation_repository,
            &self.did_repository,
            &self.key_repository,
            &self.certificate_repository,
            &self.trust_information_repository,
            &self.localized_text_repository,
        )
    }
}

#[async_trait]
impl IdentifierRepository for IdentifierProvider {
    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError> {
        let localized_texts = request.translations.as_ref().await?.to_owned();
        let identifier = self
            .db
            .tx_with_config(
                async {
                    let identifier = identifier::ActiveModel::from(request)
                        .insert(&self.db)
                        .await
                        .map_err(to_data_layer_error)?;

                    if !localized_texts.is_empty() {
                        self.localized_text_repository
                            .upsert_many(localized_texts)
                            .await?;
                    }
                    Ok::<_, DataLayerError>(identifier)
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??;
        Ok(identifier.id)
    }

    async fn get(&self, id: IdentifierId) -> Result<Identifier, DataLayerError> {
        let identifier = identifier::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::Identifier,
                id: id.into(),
            })?;

        self.identifier_from_model(identifier)
    }

    async fn get_from_did_id(&self, did_id: DidId) -> Result<Option<Identifier>, DataLayerError> {
        let identifier = identifier::Entity::find()
            .filter(identifier::Column::DidId.eq(did_id))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        identifier
            .map(|identifier| self.identifier_from_model(identifier))
            .transpose()
    }

    async fn update(
        &self,
        id: &IdentifierId,
        request: UpdateIdentifierRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = identifier::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(one_core::clock::now_utc()),
            name: request.name.map(Set).unwrap_or_default(),
            state: request
                .state
                .map(|state| Set(state.into()))
                .unwrap_or_default(),
            logo: request.logo.map(Set).unwrap_or_default(),
            ..Default::default()
        };

        let localized_texts = request.translations.unwrap_or_default();
        self.db
            .tx(async {
                update_model
                    .update(&self.db)
                    .await
                    .map_err(to_update_data_layer_error)?;
                if !localized_texts.is_empty() {
                    self.localized_text_repository
                        .upsert_many(localized_texts)
                        .await?;
                }
                Ok::<_, DataLayerError>(())
            }
            .boxed())
            .await??;
        Ok(())
    }

    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError> {
        let now = one_core::clock::now_utc();

        let identifier = identifier::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(now),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        identifier::Entity::update(identifier)
            .filter(identifier::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn hard_delete(&self, id: &IdentifierId) -> Result<(), DataLayerError> {
        identifier::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get_identifier_list(
        &self,
        query_params: IdentifierListQuery,
    ) -> Result<GetIdentifierList, DataLayerError> {
        let query = get_identifier_list_query(&query_params, self.db.get_database_backend());

        list_query_with_custom_model(query, query_params, &self.db, |model| {
            self.identifier_from_model(model)
        })
        .await
    }
}

fn get_identifier_list_query(
    query_params: &IdentifierListQuery,
    db_backend: DatabaseBackend,
) -> Select<identifier::Entity> {
    identifier::Entity::find()
        .select_only()
        .columns([
            identifier::Column::Id,
            identifier::Column::CreatedDate,
            identifier::Column::LastModified,
            identifier::Column::Name,
            identifier::Column::Type,
            identifier::Column::IsRemote,
            identifier::Column::State,
            identifier::Column::OrganisationId,
            identifier::Column::DidId,
            identifier::Column::KeyId,
            identifier::Column::DeletedAt,
            identifier::Column::Autogenerated,
            identifier::Column::Logo,
        ])
        .filter(identifier::Column::DeletedAt.is_null())
        .with_filter_join(query_params)
        .with_list_query(query_params, db_backend)
        .group_by(identifier::Column::Id)
        .group_by(identifier::Column::CreatedDate)
        .group_by(identifier::Column::LastModified)
        .group_by(identifier::Column::Name)
        .group_by(identifier::Column::Type)
        .group_by(identifier::Column::IsRemote)
        .group_by(identifier::Column::State)
        .group_by(identifier::Column::OrganisationId)
        .group_by(identifier::Column::DidId)
        .group_by(identifier::Column::KeyId)
        .group_by(identifier::Column::DeletedAt)
        .group_by(identifier::Column::Autogenerated)
        .group_by(identifier::Column::Logo)
        .order_by_desc(identifier::Column::CreatedDate)
        .order_by_desc(identifier::Column::Id)
}
