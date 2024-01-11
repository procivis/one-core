use autometrics::autometrics;
use sea_orm::{ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, QueryFilter, Set, Unchanged};
use shared_types::DidId;
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{entity::revocation_list, revocation_list::RevocationListProvider};
use one_core::{
    model::revocation_list::{RevocationList, RevocationListId, RevocationListRelations},
    repository::{error::DataLayerError, revocation_list_repository::RevocationListRepository},
};

impl RevocationListProvider {
    async fn entity_model_to_repository_model(
        &self,
        revocation_list: revocation_list::Model,
        relations: &RevocationListRelations,
    ) -> Result<RevocationList, DataLayerError> {
        let issuer_did = match relations.issuer_did.as_ref() {
            None => None,
            Some(relations) => {
                let did_id = &revocation_list.issuer_did_id;
                let did = self
                    .did_repository
                    .get_did(did_id, relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "revocation_list-did",
                        id: did_id.to_string(),
                    })?;

                Some(did)
            }
        };

        Ok(RevocationList {
            id: Uuid::from_str(&revocation_list.id)?,
            created_date: revocation_list.created_date,
            last_modified: revocation_list.last_modified,
            credentials: revocation_list.credentials,
            issuer_did,
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
        let issuer_did = request.issuer_did.ok_or(DataLayerError::MappingError)?;

        revocation_list::ActiveModel {
            id: Set(request.id.to_string()),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            credentials: Set(request.credentials),
            issuer_did_id: Set(issuer_did.id),
        }
        .insert(&self.db)
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
            .one(&self.db)
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

    async fn get_revocation_by_issuer_did_id(
        &self,
        issuer_did_id: &DidId,
        relations: &RevocationListRelations,
    ) -> Result<Option<RevocationList>, DataLayerError> {
        let revocation_list = revocation_list::Entity::find()
            .filter(revocation_list::Column::IssuerDidId.eq(issuer_did_id))
            .one(&self.db)
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

        update_model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::Db(e.into()),
        })?;

        Ok(())
    }
}
