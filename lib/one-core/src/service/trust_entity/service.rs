use shared_types::{DidValue, TrustAnchorId, TrustEntityId};
use uuid::Uuid;

use super::dto::{
    CreateTrustEntityFromDidRequestDTO, CreateTrustEntityRequestDTO, GetTrustEntitiesResponseDTO,
    GetTrustEntityResponseDTO, ListTrustEntitiesQueryDTO, UpdateTrustEntityFromDidRequestDTO,
};
use super::mapper::{
    trust_entity_from_did_request, trust_entity_from_request, update_request_from_dto,
};
use super::TrustEntityService;
use crate::common_mapper::{get_or_create_did, DidRole};
use crate::common_validator::validate_expiration_time;
use crate::model::did::{DidRelations, KeyRole};
use crate::model::list_filter::ListFilterCondition;
use crate::model::list_query::ListPagination;
use crate::model::trust_anchor::{TrustAnchor, TrustAnchorRelations};
use crate::model::trust_entity::TrustEntityRelations;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::revocation::lvvc::holder_fetch::BearerTokenPayload;
use crate::repository::error::DataLayerError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::trust_anchor::dto::{ListTrustAnchorsQueryDTO, TrustAnchorFilterValue};
use crate::util::key_verification::KeyVerification;

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

        let trust = self
            .trust_provider
            .get(&trust_anchor.r#type)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.r#type.to_owned()))?;

        let entity = trust_entity_from_request(request, trust_anchor.clone(), did);

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

    pub async fn create_trust_entity_for_did(
        &self,
        request: CreateTrustEntityFromDidRequestDTO,
        bearer_token: &str,
    ) -> Result<TrustEntityId, ServiceError> {
        let did_value = request.did.clone();

        self.validate_bearer_token(&did_value, bearer_token).await?;

        let trust_anchor = self.get_trust_anchor(request.trust_anchor_id).await?;

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
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::TrustEntity(id))?;

        Ok(result.into())
    }

    pub async fn get_trust_entity_for_did(
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

        Ok(result.into())
    }

    pub async fn delete_trust_entity(&self, id: TrustEntityId) -> Result<(), ServiceError> {
        self.trust_entity_repository
            .get(id, &Default::default())
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::TrustEntity(id),
            ))?;

        self.trust_entity_repository
            .delete(id)
            .await
            .map_err(Into::into)
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

    pub async fn update_trust_entity_for_did(
        &self,
        did_value: DidValue,
        request: UpdateTrustEntityFromDidRequestDTO,
        bearer_token: &str,
    ) -> Result<(), ServiceError> {
        self.validate_bearer_token(&did_value, bearer_token).await?;

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

        let request = update_request_from_dto(entity.state.clone(), request)?;

        self.trust_entity_repository
            .update(entity.id, request)
            .await?;

        Ok(())
    }

    async fn validate_bearer_token(
        &self,
        did_value: &DidValue,
        bearer_token: &str,
    ) -> Result<(), ServiceError> {
        // first validate bearer token
        let token_signature_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::Authentication,
        });

        let jwt: Jwt<BearerTokenPayload> =
            Jwt::build_from_token(bearer_token, Some(token_signature_verification))
                .await
                .map_err(|_| ValidationError::Unauthorized)?;

        // checking timestamp to prevent replay attack
        validate_expiration_time(&Some(jwt.payload.custom.timestamp), 60)
            .map_err(|_| ValidationError::Unauthorized)?;

        let token_issuer = jwt.payload.issuer.ok_or(ValidationError::Unauthorized)?;

        if token_issuer != did_value.as_str() {
            return Err(ValidationError::Unauthorized.into());
        }

        Ok(())
    }

    async fn get_trust_anchor(
        &self,
        trust_anchor_id: Option<TrustAnchorId>,
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
                            TrustAnchorFilterValue::IsPublisher(true),
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
}
