use async_trait::async_trait;
use one_core::model::identifier::{Identifier, IdentifierRelations, UpdateIdentifierRequest};
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::IdentifierRepository;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Unchanged};
use shared_types::{DidId, IdentifierId};
use time::OffsetDateTime;

use super::IdentifierProvider;
use crate::entity::identifier;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

impl IdentifierProvider {
    async fn resolve_relations(
        &self,
        model: identifier::Model,
        relations: &IdentifierRelations,
    ) -> Result<Identifier, DataLayerError> {
        let mut result: Identifier = model.clone().into();

        if let Some(organisation_relations) = &relations.organisation {
            if let Some(organisation_id) = &model.organisation_id {
                result.organisation = Some(
                    self.organisation_repository
                        .get_organisation(organisation_id, organisation_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "identifier-organisation",
                            id: organisation_id.to_string(),
                        })?,
                );
            }
        }

        if let Some(did_relations) = &relations.did {
            if let Some(did_id) = &model.did_id {
                result.did = Some(
                    self.did_repository
                        .get_did(did_id, did_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "identifier-did",
                            id: did_id.to_string(),
                        })?,
                );
            }
        }

        if let Some(key_relations) = &relations.key {
            if let Some(key_id) = &model.key_id {
                result.key = Some(
                    self.key_repository
                        .get_key(key_id, key_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "identifier-key",
                            id: key_id.to_string(),
                        })?,
                );
            }
        }

        Ok(result)
    }
}

#[async_trait]
impl IdentifierRepository for IdentifierProvider {
    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError> {
        let identifier = identifier::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(identifier.id)
    }

    async fn get_from_did_id(
        &self,
        did_id: DidId,
        relations: &IdentifierRelations,
    ) -> Result<Option<Identifier>, DataLayerError> {
        let identifier = identifier::Entity::find()
            .filter(identifier::Column::DidId.eq(did_id))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        match identifier {
            None => Ok(None),
            Some(identifier) => Ok(Some(self.resolve_relations(identifier, relations).await?)),
        }
    }

    async fn update(
        &self,
        id: &IdentifierId,
        request: UpdateIdentifierRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = identifier::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            name: request.name.map(Set).unwrap_or_default(),
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

        Ok(())
    }

    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

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
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(())
    }
}
