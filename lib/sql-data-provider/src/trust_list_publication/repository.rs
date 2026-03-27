use autometrics::autometrics;
use futures::FutureExt;
use one_core::model::trust_list_publication::{
    GetTrustListPublicationList, TrustListPublication, TrustListPublicationListQuery,
    TrustListPublicationRelations, UpdateTrustListPublicationRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_list_publication_repository::TrustListPublicationRepository;
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::prelude::Expr;
use sea_orm::{ActiveModelTrait, ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder};
use shared_types::TrustListPublicationId;

use super::TrustListPublicationProvider;
use crate::common::list_query_with_base_model;
use crate::entity::{trust_entry, trust_list_publication};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl TrustListPublicationRepository for TrustListPublicationProvider {
    async fn create(
        &self,
        entity: TrustListPublication,
    ) -> Result<TrustListPublicationId, DataLayerError> {
        let id = entity.id;
        let model: trust_list_publication::ActiveModel = entity.into();
        model.insert(&self.db).await.map_err(to_data_layer_error)?;
        Ok(id)
    }

    async fn get(
        &self,
        id: TrustListPublicationId,
        relations: &TrustListPublicationRelations,
    ) -> Result<Option<TrustListPublication>, DataLayerError> {
        let entity_model = trust_list_publication::Entity::find_by_id(id)
            .filter(trust_list_publication::Column::DeletedAt.is_null())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(entity_model) = entity_model else {
            return Ok(None);
        };

        let organisation_id = entity_model.organisation_id;
        let identifier_id = entity_model.identifier_id;
        let key_id = entity_model.key_id;
        let certificate_id = entity_model.certificate_id;

        let mut result = TrustListPublication::from(entity_model);

        if let Some(organisation_relations) = &relations.organisation {
            result.organisation = Some(
                self.organisation_repository
                    .get_organisation(&organisation_id, organisation_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_list_publication-organisation",
                        id: organisation_id.to_string(),
                    })?,
            );
        }

        if let Some(identifier_relations) = &relations.identifier {
            result.identifier = Some(
                self.identifier_repository
                    .get(identifier_id, identifier_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_list_publication-identifier",
                        id: identifier_id.to_string(),
                    })?,
            );
        }

        if let Some(key_id) = key_id
            && let Some(key_relations) = &relations.key
        {
            result.key = Some(
                self.key_repository
                    .get_key(&key_id, key_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_list_publication-key",
                        id: key_id.to_string(),
                    })?,
            );
        }

        if let Some(certificate_id) = certificate_id
            && let Some(certificate_relations) = &relations.certificate
        {
            result.certificate = Some(
                self.certificate_repository
                    .get(certificate_id, certificate_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_list_publication-certificate",
                        id: certificate_id.to_string(),
                    })?,
            );
        }

        Ok(Some(result))
    }

    async fn list(
        &self,
        query: TrustListPublicationListQuery,
    ) -> Result<GetTrustListPublicationList, DataLayerError> {
        let db_query = trust_list_publication::Entity::find()
            .filter(trust_list_publication::Column::DeletedAt.is_null())
            .with_list_query(&query)
            .order_by_desc(trust_list_publication::Column::CreatedDate)
            .order_by_desc(trust_list_publication::Column::Id);

        list_query_with_base_model(db_query, query, &self.db).await
    }

    async fn update(
        &self,
        id: TrustListPublicationId,
        request: UpdateTrustListPublicationRequest,
    ) -> Result<(), DataLayerError> {
        trust_list_publication::Entity::update(trust_list_publication::ActiveModel {
            id: Unchanged(id),
            last_modified: Set(one_core::clock::now_utc()),
            content: request.content.map(Set).unwrap_or_default(),
            sequence_number: request.sequence_number.map(Set).unwrap_or_default(),
            ..Default::default()
        })
        .filter(
            Condition::all()
                .add(trust_list_publication::Column::Id.eq(id))
                .add(trust_list_publication::Column::DeletedAt.is_null()),
        )
        .exec(&self.db)
        .await
        .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn delete(&self, id: TrustListPublicationId) -> Result<(), DataLayerError> {
        self.db
            .tx(async {
                trust_entry::Entity::delete_many()
                    .filter(trust_entry::Column::TrustListPublicationId.eq(id))
                    .exec(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;

                trust_list_publication::Entity::update_many()
                    .col_expr(
                        trust_list_publication::Column::DeletedAt,
                        Expr::value(one_core::clock::now_utc()),
                    )
                    .filter(
                        Condition::all()
                            .add(trust_list_publication::Column::Id.eq(id))
                            .add(trust_list_publication::Column::DeletedAt.is_null()),
                    )
                    .exec(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;
                Ok(())
            }
            .boxed())
            .await?
    }
}
