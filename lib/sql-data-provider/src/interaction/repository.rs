use autometrics::autometrics;
use one_core::model::common::LockType;
use one_core::model::interaction::{Interaction, InteractionRelations, UpdateInteractionRequest};
use one_core::repository::error::DataLayerError;
use one_core::repository::interaction_repository::InteractionRepository;
use sea_orm::ActiveValue::Unchanged;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::Query;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect,
};
use shared_types::{CredentialId, InteractionId, NonceId, ProofId};
use time::OffsetDateTime;

use super::InteractionProvider;
use crate::entity::{credential, interaction, proof};
use crate::interaction::mapper::interaction_from_models;
use crate::mapper::{map_lock_type, to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl InteractionRepository for InteractionProvider {
    async fn create_interaction(
        &self,
        request: Interaction,
    ) -> Result<InteractionId, DataLayerError> {
        let interaction = interaction::ActiveModel::try_from(request)?
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        Ok(interaction.id)
    }

    async fn update_interaction(
        &self,
        id: InteractionId,
        request: UpdateInteractionRequest,
    ) -> Result<(), DataLayerError> {
        let mut model: interaction::ActiveModel = request.into();
        model.id = Unchanged(id);
        model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get_interaction(
        &self,
        id: &InteractionId,
        relations: &InteractionRelations,
        lock: Option<LockType>,
    ) -> Result<Option<Interaction>, DataLayerError> {
        let select = interaction::Entity::find_by_id(id);
        let select = match lock {
            None => select,
            Some(lock) => select.lock(map_lock_type(lock)),
        };
        let interaction = select
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let Some(interaction) = interaction else {
            return Ok(None);
        };

        let organisation_id = interaction.organisation_id.to_owned();

        let organisation = if let Some(interaction_relations) = &relations.organisation {
            Some(
                self.organisation_repository
                    .get_organisation(&organisation_id, interaction_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "interaction-organisation",
                        id: organisation_id.to_string(),
                    })?,
            )
        } else {
            None
        };

        Ok(Some(interaction_from_models(interaction, organisation)))
    }

    async fn mark_nonce_as_used(
        &self,
        interaction_id: &InteractionId,
        nonce_id: NonceId,
    ) -> Result<(), DataLayerError> {
        let stmt = self.db.get_database_backend().build(
            Query::update()
                .table(interaction::Entity)
                .value(interaction::Column::NonceId, nonce_id)
                .and_where(Expr::col(interaction::Column::Id).eq(interaction_id.to_string()))
                .and_where(Expr::col(interaction::Column::NonceId).is_null()),
        );
        let result = self.db.execute(stmt).await.map_err(to_data_layer_error)?;
        if result.rows_affected() == 0 {
            return Err(DataLayerError::RecordNotUpdated);
        }
        Ok(())
    }

    async fn delete_interaction(&self, id: &InteractionId) -> Result<(), DataLayerError> {
        interaction::Entity::delete_by_id(*id)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }

    async fn update_expired_credentials(&self) -> Result<Vec<CredentialId>, DataLayerError> {
        let now = now_truncated_to_milliseconds()?;

        let stmt = self.db.get_database_backend().build(
            Query::update()
                .table(credential::Entity)
                .value(
                    credential::Column::State,
                    credential::CredentialState::InteractionExpired,
                )
                .value(credential::Column::LastModified, now)
                .and_where(
                    Expr::col(credential::Column::Id).in_subquery(
                        Query::select()
                            .expr(Expr::col((credential::Entity, credential::Column::Id)))
                            .from(credential::Entity)
                            .inner_join(
                                interaction::Entity,
                                Expr::col((interaction::Entity, interaction::Column::Id)).equals((
                                    credential::Entity,
                                    credential::Column::InteractionId,
                                )),
                            )
                            .cond_where(
                                credential::Column::State.eq(credential::CredentialState::Pending),
                            )
                            .cond_where(interaction::Column::ExpiresAt.lt(now))
                            .to_owned(),
                    ),
                ),
        );
        let result = self.db.execute(stmt).await.map_err(to_data_layer_error)?;
        let rows_affected = result.rows_affected();
        tracing::debug!("Expired credentials: affected rows: {rows_affected}");

        let models: Vec<CredentialId> = credential::Entity::find()
            .select_only()
            .column(credential::Column::Id)
            .filter(credential::Column::State.eq(credential::CredentialState::InteractionExpired))
            .filter(credential::Column::LastModified.eq(now))
            .into_tuple()
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        tracing::debug!("Expired credentials, models: {}", models.len());

        if rows_affected < models.len() as _ {
            tracing::warn!(
                "Updating expired credential interactions: Rows affected: {rows_affected}, but detected models: {}",
                models.len()
            );
        }

        Ok(models)
    }

    async fn update_expired_proofs(&self) -> Result<Vec<ProofId>, DataLayerError> {
        let now = now_truncated_to_milliseconds()?;

        let stmt = self.db.get_database_backend().build(
            Query::update()
                .table(proof::Entity)
                .value(
                    proof::Column::State,
                    proof::ProofRequestState::InteractionExpired,
                )
                .value(proof::Column::LastModified, now)
                .and_where(
                    Expr::col(proof::Column::Id).in_subquery(
                        Query::select()
                            .expr(Expr::col((proof::Entity, proof::Column::Id)))
                            .from(proof::Entity)
                            .inner_join(
                                interaction::Entity,
                                Expr::col((interaction::Entity, interaction::Column::Id))
                                    .equals((proof::Entity, proof::Column::InteractionId)),
                            )
                            .cond_where(proof::Column::State.eq(proof::ProofRequestState::Pending))
                            .cond_where(interaction::Column::ExpiresAt.lt(now))
                            .to_owned(),
                    ),
                ),
        );
        let result = self.db.execute(stmt).await.map_err(to_data_layer_error)?;
        let rows_affected = result.rows_affected();
        tracing::debug!("Expired proofs: affected rows: {rows_affected}");

        let models: Vec<ProofId> = proof::Entity::find()
            .select_only()
            .column(proof::Column::Id)
            .filter(proof::Column::State.eq(proof::ProofRequestState::InteractionExpired))
            .filter(proof::Column::LastModified.eq(now))
            .into_tuple()
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        tracing::debug!("Expired proofs, models: {}", models.len());

        if rows_affected < models.len() as _ {
            tracing::warn!(
                "Updating expired proof interactions: Rows affected: {rows_affected}, but detected models: {}",
                models.len()
            );
        }

        Ok(models)
    }
}

/// keeps exactly 3 digits of fraction of seconds
///
/// necessary for SQL equals comparison
fn now_truncated_to_milliseconds() -> Result<OffsetDateTime, DataLayerError> {
    let now = OffsetDateTime::now_utc();
    now.replace_millisecond(now.millisecond())
        .map_err(|_| DataLayerError::MappingError)
}
