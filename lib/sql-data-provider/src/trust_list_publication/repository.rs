use autometrics::autometrics;
use futures::FutureExt;
use one_core::model::trust_list_publication::{
    GetTrustListPublicationList, TrustListPublication, TrustListPublicationListQuery,
    UpdateTrustListPublicationRequest,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::trust_list_publication_repository::TrustListPublicationRepository;
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder,
};
use shared_types::TrustListPublicationId;

use super::TrustListPublicationProvider;
use super::mapper::trust_list_publication_from_model;
use crate::common::list_query_with_custom_model;
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
    ) -> Result<TrustListPublication, DataLayerError> {
        let entity_model = trust_list_publication::Entity::find_by_id(id)
            .filter(trust_list_publication::Column::DeletedAt.is_null())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::TrustListPublication,
                id: id.into(),
            })?;

        Ok(trust_list_publication_from_model(
            entity_model,
            &self.organisation_repository,
            &self.identifier_repository,
            &self.key_repository,
            &self.certificate_repository,
        ))
    }

    async fn list(
        &self,
        query: TrustListPublicationListQuery,
    ) -> Result<GetTrustListPublicationList, DataLayerError> {
        let db_query = trust_list_publication::Entity::find()
            .filter(trust_list_publication::Column::DeletedAt.is_null())
            .with_list_query(&query, self.db.get_database_backend())
            .order_by_desc(trust_list_publication::Column::CreatedDate)
            .order_by_desc(trust_list_publication::Column::Id);

        list_query_with_custom_model(db_query, query, &self.db, |model| {
            Ok(trust_list_publication_from_model(
                model,
                &self.organisation_repository,
                &self.identifier_repository,
                &self.key_repository,
                &self.certificate_repository,
            ))
        })
        .await
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
            sequence_number: request
                .sequence_number
                .map(|s| Set(s as i32))
                .unwrap_or_default(),
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
