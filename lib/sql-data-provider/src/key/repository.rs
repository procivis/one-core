use crate::entity::{credential, key, key_did, organisation};
use crate::error_mapper::to_data_layer_error;
use crate::key::mapper::from_model_and_relations;
use crate::key::KeyProvider;
use one_core::model::credential::{Credential, CredentialRelations};
use one_core::model::did::DidRelations;
use one_core::model::key::{Key, KeyId, KeyRelations, RelatedDid};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::key_repository::KeyRepository;
use sea_orm::{ActiveModelTrait, EntityTrait, ModelTrait, Set};
use std::str::FromStr;
use uuid::Uuid;

impl KeyProvider {
    async fn get_credential(
        &self,
        key: &key::Model,
        credential_relations: &Option<CredentialRelations>,
    ) -> Result<Option<Credential>, DataLayerError> {
        match &credential_relations {
            None => Ok(None),
            Some(credential_relations) => {
                let model = key
                    .find_related(credential::Entity)
                    .one(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;
                match model {
                    None => Ok(None),
                    Some(model) => {
                        let credential: Credential = model.try_into()?;
                        Ok(Some(
                            self.credential_repository
                                .get_credential(&credential.id, credential_relations)
                                .await?,
                        ))
                    }
                }
            }
        }
    }

    async fn get_did(
        &self,
        key_did: &key_did::Model,
        did_relations: &DidRelations,
    ) -> Result<RelatedDid, DataLayerError> {
        let id = Uuid::from_str(&key_did.did_id).map_err(|_| DataLayerError::MappingError)?;
        let did = self.did_repository.get_did(&id, did_relations).await?;

        Ok(RelatedDid {
            role: key_did.role.to_owned().into(),
            did,
        })
    }

    async fn get_dids(
        &self,
        key: &key::Model,
        did_relations: &Option<DidRelations>,
    ) -> Result<Option<Vec<RelatedDid>>, DataLayerError> {
        match &did_relations {
            None => Ok(None),
            Some(did_relations) => {
                let key_dids: Vec<key_did::Model> = key
                    .find_related(key_did::Entity)
                    .all(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;

                let mut result = vec![];
                for key_did in &key_dids {
                    result.push(self.get_did(key_did, did_relations).await?)
                }

                Ok(Some(result))
            }
        }
    }

    async fn get_organisation(
        &self,
        key: &key::Model,
        organisation_relations: &Option<OrganisationRelations>,
    ) -> Result<Option<Organisation>, DataLayerError> {
        match &organisation_relations {
            None => Ok(None),
            Some(organisation_relations) => {
                let model = key
                    .find_related(organisation::Entity)
                    .one(&self.db)
                    .await
                    .map_err(to_data_layer_error)?
                    .ok_or(DataLayerError::RecordNotFound)?;
                let organisation: Organisation = model.try_into()?;
                Ok(Some(
                    self.organisation_repository
                        .get_organisation(&organisation.id, organisation_relations)
                        .await?,
                ))
            }
        }
    }
}

#[async_trait::async_trait]
impl KeyRepository for KeyProvider {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError> {
        let credential_id = request
            .credential
            .map(|credential| credential.id.to_string());

        let organisation_id = request
            .organisation
            .ok_or(DataLayerError::MappingError)?
            .id
            .to_string();

        key::ActiveModel {
            id: Set(request.id.to_string()),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            name: Set(request.name),
            public_key: Set(request.public_key),
            private_key: Set(request.private_key),
            storage_type: Set(request.storage_type),
            key_type: Set(request.key_type),
            credential_id: Set(credential_id),
            organisation_id: Set(organisation_id),
        }
        .insert(&self.db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(request.id)
    }

    async fn get_key(&self, id: &KeyId, relations: &KeyRelations) -> Result<Key, DataLayerError> {
        let key = key::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| {
                tracing::error!("Error while fetching key {}. Error: {}", id, e.to_string());
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?
            .ok_or(DataLayerError::RecordNotFound)?;

        let credential = self.get_credential(&key, &relations.credential).await?;
        let dids = self.get_dids(&key, &relations.dids).await?;
        let organisation = self.get_organisation(&key, &relations.organisation).await?;

        from_model_and_relations(key, credential, dids, organisation)
    }
}
