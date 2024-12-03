use std::str::FromStr;

use shared_types::{DidId, DidValue, TrustAnchorId, TrustEntityId};
use uuid::Uuid;

use super::dto::{
    CreateRemoteTrustEntityRequestDTO, CreateTrustEntityFromDidPublisherRequestDTO,
    CreateTrustEntityRequestDTO, GetTrustEntitiesResponseDTO, GetTrustEntityResponseDTO,
    ListTrustEntitiesQueryDTO, UpdateTrustEntityFromDidRequestDTO,
};
use super::mapper::{
    trust_entity_from_did_request, trust_entity_from_partial_and_did_and_anchor,
    trust_entity_from_request, update_request_from_dto,
};
use super::TrustEntityService;
use crate::common_mapper::{get_or_create_did, DidRole};
use crate::config::core_config::TrustManagementType::SimpleTrustList;
use crate::model::did::{DidRelations, DidType};
use crate::model::key::KeyRelations;
use crate::model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch};
use crate::model::list_query::ListPagination;
use crate::model::trust_anchor::{TrustAnchor, TrustAnchorRelations};
use crate::model::trust_entity::{TrustEntity, TrustEntityRelations};
use crate::repository::error::DataLayerError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::trust_anchor::dto::{ListTrustAnchorsQueryDTO, TrustAnchorFilterValue};
use crate::service::trust_entity::dto::{
    CreateTrustEntityFromDidPublisherResponseDTO, UpdateTrustEntityActionFromDidRequestDTO,
};
use crate::service::trust_entity::mapper::get_detail_trust_entity_response;
use crate::util::bearer_token::{prepare_bearer_token, validate_bearer_token};

impl TrustEntityService {
    pub async fn create_trust_entity(
        &self,
        request: CreateTrustEntityRequestDTO,
    ) -> Result<TrustEntityId, ServiceError> {
        let trust_anchor = self
            .trust_anchor_repository
            .get(request.trust_anchor_id)
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(request.trust_anchor_id))?;

        if !trust_anchor.is_publisher {
            return Err(BusinessLogicError::TrustAnchorMustBePublish.into());
        }

        let did = self
            .did_repository
            .get_did(&request.did_id, &DidRelations::default())
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(request.trust_anchor_id))?;

        if did.did_type == DidType::Remote {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "Only local DIDs allowed".to_string(),
            }
            .into());
        }

        let entity = trust_entity_from_request(request, trust_anchor.clone(), did);
        self.trust_entity_repository
            .create(entity)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    BusinessLogicError::TrustEntityAlreadyPresent.into()
                }
                err => err.into(),
            })
    }

    pub async fn publisher_create_trust_entity_for_did(
        &self,
        request: CreateTrustEntityFromDidPublisherRequestDTO,
        bearer_token: &str,
    ) -> Result<TrustEntityId, ServiceError> {
        let did_value = request.did.clone();

        self.validate_bearer_token(&did_value, bearer_token).await?;

        let trust_anchor = self.get_trust_anchor(request.trust_anchor_id, true).await?;

        if !trust_anchor.is_publisher {
            return Err(BusinessLogicError::TrustAnchorMustBePublish.into());
        }

        let trust = self
            .trust_provider
            .get(&trust_anchor.r#type)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.r#type.clone()))?;

        if !trust.is_enabled() {
            return Err(BusinessLogicError::TrustAnchorIsDisabled.into());
        }

        let did =
            get_or_create_did(&*self.did_repository, &None, &did_value, DidRole::Verifier).await?;

        if !self
            .trust_entity_repository
            .get_by_did_id(did.id)
            .await?
            .is_empty()
        {
            return Err(BusinessLogicError::TrustEntityAlreadyPresent.into());
        }

        let entity = trust_entity_from_did_request(request, trust_anchor.clone(), did);

        trust.publish_entity(&trust_anchor, &entity).await;

        self.trust_entity_repository
            .create(entity)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    BusinessLogicError::TrustEntityAlreadyPresent.into()
                }
                err => err.into(),
            })
    }

    pub async fn create_remote_trust_entity_for_did(
        &self,
        request: CreateRemoteTrustEntityRequestDTO,
    ) -> Result<TrustEntityId, ServiceError> {
        let did = self
            .did_repository
            .get_did(
                &request.did_id,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Did(request.did_id))?;

        if did.did_type != DidType::Local {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "Only local DIDs allowed".to_string(),
            }
            .into());
        }

        let trust_anchor = self
            .get_trust_anchor(request.trust_anchor_id, false)
            .await?;
        if trust_anchor.is_publisher {
            return Err(BusinessLogicError::TrustAnchorMustBeClient.into());
        }

        let trust = self
            .trust_provider
            .get(&trust_anchor.r#type)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.r#type.clone()))?;

        if !trust.is_enabled() {
            return Err(BusinessLogicError::TrustAnchorIsDisabled.into());
        }

        // the published reference should look like: {scheme://domain}/ssi/trust/v1/{trustAnchorId}
        let base_url = trust_anchor
            .publisher_reference
            .split_once("/ssi/")
            .ok_or(ServiceError::MappingError(
                "Invalid publisher reference".to_string(),
            ))?
            .0;

        let trust_anchor_id = trust_anchor
            .publisher_reference
            .rsplit_once('/')
            .ok_or(ServiceError::MappingError(
                "Invalid publisher reference".to_string(),
            ))?
            .1;

        let trust_anchor_id = TrustAnchorId::from_str(trust_anchor_id)
            .map_err(|e| ServiceError::MappingError(format!("Invalid publisher reference: {e}")))?;

        let bearer_token =
            prepare_bearer_token(&did, &*self.key_provider, &*self.did_method_provider).await?;

        let request = CreateTrustEntityFromDidPublisherRequestDTO {
            trust_anchor_id: Some(trust_anchor_id),
            did: did.did,
            name: request.name,
            logo: request.logo,
            terms_url: request.terms_url,
            privacy_url: request.privacy_url,
            website: request.website,
            role: request.role,
        };

        let url = format!("{base_url}/ssi/trust-entity/v1");
        let response: CreateTrustEntityFromDidPublisherResponseDTO = self
            .client
            .post(&url)
            .bearer_auth(&bearer_token)
            .json(request)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?
            .send()
            .await
            .map_err(|e| ServiceError::Other(e.to_string()))?
            .error_for_status()
            .map_err(|e| ServiceError::Other(e.to_string()))?
            .json()
            .map_err(|e| ServiceError::Other(e.to_string()))?;

        Ok(response.id)
    }

    pub async fn get_trust_entity(
        &self,
        id: TrustEntityId,
    ) -> Result<GetTrustEntityResponseDTO, ServiceError> {
        let result = self
            .trust_entity_repository
            .get(
                id,
                &TrustEntityRelations {
                    trust_anchor: Some(TrustAnchorRelations::default()),
                    did: Some(DidRelations::default()),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::TrustEntity(id))?;

        result.try_into()
    }

    pub async fn publisher_get_trust_entity_for_did(
        &self,
        did_value: DidValue,
        bearer_token: &str,
    ) -> Result<GetTrustEntityResponseDTO, ServiceError> {
        self.validate_bearer_token(&did_value, bearer_token).await?;

        let did = self
            .did_repository
            .get_did_by_value(&did_value, &DidRelations::default())
            .await?
            .ok_or(ServiceError::ValidationError("unknown did".to_string()))?;

        let did_id_as_uuid = Uuid::from(did.id);

        let result = self
            .trust_entity_repository
            .get_by_did_id(did.id)
            .await?
            .first()
            .cloned()
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::TrustEntity(did_id_as_uuid.into()),
            ))?;

        get_detail_trust_entity_response(result, did)
    }

    pub async fn list_trust_entities(
        &self,
        filters: ListTrustEntitiesQueryDTO,
    ) -> Result<GetTrustEntitiesResponseDTO, ServiceError> {
        self.trust_entity_repository
            .list(filters)
            .await
            .map_err(Into::into)
    }

    async fn update_trust_entity(
        &self,
        entity: TrustEntity,
        request: UpdateTrustEntityFromDidRequestDTO,
    ) -> Result<(), ServiceError> {
        let request = update_request_from_dto(entity.state.clone(), request)?;

        self.trust_entity_repository
            .update(entity.id, request)
            .await?;

        Ok(())
    }

    // PUBLISHER
    pub async fn update_trust_entity_by_trust_entity(
        &self,
        id: TrustEntityId,
        update_request: UpdateTrustEntityFromDidRequestDTO,
    ) -> Result<(), ServiceError> {
        let entity = self
            .trust_entity_repository
            .get(
                id,
                &TrustEntityRelations {
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::TrustEntity(id))?;

        self.update_trust_entity(entity, update_request).await?;

        Ok(())
    }

    // NON-PUBLISHER
    pub async fn update_trust_entity_by_did(
        &self,
        did_value: DidValue,
        request: UpdateTrustEntityFromDidRequestDTO,
        bearer_token: &str,
    ) -> Result<(), ServiceError> {
        self.validate_bearer_token(&did_value, bearer_token).await?;

        if let Some(UpdateTrustEntityActionFromDidRequestDTO::Remove) = request.action {
            return Err(ValidationError::InvalidUpdateRequest.into());
        }

        let did = self
            .did_repository
            .get_did_by_value(&did_value, &DidRelations::default())
            .await?
            .ok_or(EntityNotFoundError::DidValue(did_value))?;

        let entities = self.trust_entity_repository.get_by_did_id(did.id).await?;
        if entities.len() != 1 {
            return Err(BusinessLogicError::TrustEntityHasDuplicates.into());
        }

        let entity = entities
            .first()
            .ok_or(ServiceError::MappingError("first is None".to_string()))?;

        self.update_trust_entity(entity.clone(), request).await?;

        Ok(())
    }

    async fn validate_bearer_token(
        &self,
        did_value: &DidValue,
        bearer_token: &str,
    ) -> Result<(), ServiceError> {
        let jwt = validate_bearer_token(
            bearer_token,
            self.did_method_provider.clone(),
            self.key_algorithm_provider.clone(),
        )
        .await?;

        let token_issuer = jwt.payload.issuer.ok_or(ValidationError::Unauthorized)?;

        if token_issuer != did_value.as_str() {
            return Err(ValidationError::Unauthorized.into());
        }

        Ok(())
    }

    async fn get_trust_anchor(
        &self,
        trust_anchor_id: Option<TrustAnchorId>,
        is_publisher: bool,
    ) -> Result<TrustAnchor, ServiceError> {
        match trust_anchor_id {
            None => {
                let anchors = self
                    .trust_anchor_repository
                    .list(ListTrustAnchorsQueryDTO {
                        pagination: Some(ListPagination {
                            page: 0,
                            page_size: 2,
                        }),
                        sorting: None,
                        filtering: Some(ListFilterCondition::Value(
                            TrustAnchorFilterValue::IsPublisher(is_publisher),
                        )),
                        include: None,
                    })
                    .await?;
                if anchors.values.len() > 1 {
                    return Err(BusinessLogicError::MultipleMatchingTrustAnchors.into());
                }
                let trust_anchor = anchors.values.first().ok_or(ServiceError::EntityNotFound(
                    EntityNotFoundError::TrustAnchor(Uuid::default().into()),
                ))?;
                Ok(trust_anchor.clone().into())
            }
            Some(trust_anchor_id) => {
                Ok(self
                    .trust_anchor_repository
                    .get(trust_anchor_id)
                    .await?
                    .ok_or(EntityNotFoundError::TrustAnchor(trust_anchor_id))?)
            }
        }
    }
    pub async fn lookup_did(
        &self,
        did_id: DidId,
    ) -> Result<GetTrustEntityResponseDTO, ServiceError> {
        let trust_anchor_list = self
            .trust_anchor_repository
            .list(ListTrustAnchorsQueryDTO {
                pagination: None,
                sorting: None,
                filtering: Some(
                    TrustAnchorFilterValue::Type(StringMatch::equals(SimpleTrustList.to_string()))
                        .condition(),
                ),
                include: None,
            })
            .await?;

        for trust_anchor in trust_anchor_list.values.into_iter().map(TrustAnchor::from) {
            let trust = self
                .trust_provider
                .get(&trust_anchor.r#type)
                .ok_or_else(|| {
                    MissingProviderError::TrustManager(trust_anchor.r#type.to_owned())
                })?;

            let did = self
                .did_repository
                .get_did(&did_id, &DidRelations::default())
                .await?
                .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Did(
                    did_id,
                )))?;

            let maybe_entity = trust
                .lookup_did(&trust_anchor, &did.did)
                .await
                .map_err(ServiceError::TrustManagementError)?;

            if let Some(trust_entity) = maybe_entity {
                return Ok(trust_entity_from_partial_and_did_and_anchor(
                    trust_entity,
                    did,
                    trust_anchor,
                ));
            }
        }

        Err(ServiceError::BusinessLogic(
            BusinessLogicError::MissingTrustEntity(did_id),
        ))
    }
}
