use std::str::FromStr;

use anyhow::anyhow;
use autometrics::autometrics;
use futures::future::join_all;
use one_core::model::revocation_list::{
    RevocationList, RevocationListId, RevocationListPurpose, RevocationListRelations,
    StatusListType,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::revocation_list_repository::RevocationListRepository;
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Unchanged,
};
use shared_types::IdentifierId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::entity;
use crate::entity::revocation_list;
use crate::mapper::to_update_data_layer_error;
use crate::revocation_list::RevocationListProvider;

impl RevocationListProvider {
    async fn entity_model_to_repository_model(
        &self,
        revocation_list: revocation_list::Model,
        relations: &RevocationListRelations,
    ) -> Result<RevocationList, DataLayerError> {
        let issuer_identifier = match relations.issuer_identifier.as_ref() {
            Some(relations) => Some(
                self.identifier_repository
                    .get(revocation_list.issuer_identifier_id, relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "revocation_list-identifier",
                        id: revocation_list.issuer_identifier_id.to_string(),
                    })?,
            ),
            None => None,
        };

        Ok(RevocationList {
            id: Uuid::from_str(&revocation_list.id)?,
            created_date: revocation_list.created_date,
            last_modified: revocation_list.last_modified,
            credentials: revocation_list.credentials,
            purpose: revocation_list.purpose.into(),
            issuer_identifier,
            format: revocation_list.format.into(),
            // TODO fix in ONE-3968
            r#type: match revocation_list.r#type.as_str() {
                "BITSTRING_STATUS_LIST" | "BITSTRINGSTATUSLIST" => {
                    StatusListType::BitstringStatusList
                }
                "TOKENSTATUSLIST" => StatusListType::TokenStatusList,
                _ => return Err(DataLayerError::Db(anyhow!("Invalid revocation list type"))),
            },
        })
    }
}

#[autometrics]
#[async_trait::async_trait]
impl RevocationListRepository for RevocationListProvider {
    async fn create_revocation_list(
        &self,
        request: RevocationList,
    ) -> Result<RevocationListId, DataLayerError> {
        let issuer_identifier = request
            .issuer_identifier
            .ok_or(DataLayerError::MappingError)?;

        revocation_list::ActiveModel {
            id: Set(request.id.to_string()),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            credentials: Set(request.credentials),
            purpose: Set(request.purpose.into()),
            issuer_identifier_id: Set(issuer_identifier.id),
            format: Set(request.format.into()),
            r#type: Set(request.r#type.to_string()),
        }
        .insert(&self.db.tx())
        .await
        .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(request.id)
    }

    async fn get_revocation_list(
        &self,
        id: &RevocationListId,
        relations: &RevocationListRelations,
    ) -> Result<Option<RevocationList>, DataLayerError> {
        let revocation_list = revocation_list::Entity::find_by_id(id.to_string())
            .one(&self.db.tx())
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        match revocation_list {
            None => Ok(None),
            Some(revocation_list) => {
                let revocation_list = self
                    .entity_model_to_repository_model(revocation_list, relations)
                    .await?;

                Ok(Some(revocation_list))
            }
        }
    }

    async fn get_revocation_lists(
        &self,
        ids: &[RevocationListId],
        relations: &RevocationListRelations,
    ) -> Result<Vec<RevocationList>, DataLayerError> {
        let ids: Vec<_> = ids.iter().map(|id| id.to_string()).collect();
        let models = revocation_list::Entity::find()
            .filter(revocation_list::Column::Id.is_in(ids))
            .all(&self.db.tx())
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        join_all(
            models
                .into_iter()
                .map(|model| self.entity_model_to_repository_model(model, relations)),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<RevocationList>, DataLayerError>>()
    }

    async fn get_revocation_by_issuer_identifier_id(
        &self,
        issuer_identifier_id: IdentifierId,
        purpose: RevocationListPurpose,
        status_list_type: StatusListType,
        relations: &RevocationListRelations,
    ) -> Result<Option<RevocationList>, DataLayerError> {
        let purpose_as_db_type = entity::revocation_list::RevocationListPurpose::from(purpose);

        let revocation_list = revocation_list::Entity::find()
            .filter(
                revocation_list::Column::IssuerIdentifierId
                    .eq(issuer_identifier_id)
                    .and(revocation_list::Column::Purpose.eq(purpose_as_db_type.into_value()))
                    .and(revocation_list::Column::Type.eq(status_list_type.to_string())),
            )
            .one(&self.db.tx())
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        match revocation_list {
            None => Ok(None),
            Some(revocation_list) => {
                let revocation_list = self
                    .entity_model_to_repository_model(revocation_list, relations)
                    .await?;

                Ok(Some(revocation_list))
            }
        }
    }

    async fn update_credentials(
        &self,
        revocation_list_id: &Uuid,
        credentials: Vec<u8>,
    ) -> Result<(), DataLayerError> {
        let update_model = revocation_list::ActiveModel {
            id: Unchanged(revocation_list_id.to_string()),
            last_modified: Set(OffsetDateTime::now_utc()),
            credentials: Set(credentials),
            ..Default::default()
        };

        update_model
            .update(&self.db.tx())
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }
}
