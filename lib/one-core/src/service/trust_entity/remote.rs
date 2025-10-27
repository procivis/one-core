use std::str::FromStr;

use shared_types::{DidId, TrustAnchorId, TrustEntityId};

use super::TrustEntityService;
use super::dto::{
    CreateRemoteTrustEntityRequestDTO, CreateTrustEntityFromDidPublisherRequestDTO,
    GetRemoteTrustEntityResponseDTO, UpdateTrustEntityFromDidRequestDTO,
};
use crate::model::did::{Did, DidRelations, DidType};
use crate::model::key::KeyRelations;
use crate::proto::bearer_token::prepare_bearer_token;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::trust_entity::dto::{
    CreateTrustEntityFromDidPublisherResponseDTO, UpdateTrustEntityActionFromDidRequestDTO,
};

impl TrustEntityService {
    pub async fn create_remote_trust_entity_for_did(
        &self,
        request: CreateRemoteTrustEntityRequestDTO,
    ) -> Result<TrustEntityId, ServiceError> {
        let RemoteOperationProperties {
            did,
            remote_anchor_id,
            remote_anchor_base_url,
            bearer_token,
        } = self
            .prepare_remote_operation_for_did(&request.did_id, request.trust_anchor_id)
            .await?;

        let request = CreateTrustEntityFromDidPublisherRequestDTO {
            trust_anchor_id: Some(remote_anchor_id),
            did: did.did,
            name: request.name,
            logo: request.logo,
            terms_url: request.terms_url,
            privacy_url: request.privacy_url,
            website: request.website,
            role: request.role,
        };

        let url = format!("{remote_anchor_base_url}/ssi/trust-entity/v1");
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

    pub async fn update_remote_trust_entity_for_did(
        &self,
        did_id: DidId,
        request: UpdateTrustEntityFromDidRequestDTO,
    ) -> Result<(), ServiceError> {
        if let Some(UpdateTrustEntityActionFromDidRequestDTO::Remove) = request.action {
            return Err(ValidationError::InvalidUpdateRequest.into());
        }

        let RemoteOperationProperties {
            did,
            remote_anchor_base_url,
            bearer_token,
            ..
        } = self
            .prepare_remote_operation_for_did(
                &did_id, None, // assuming there's already one remote trust anchor
            )
            .await?;

        let url = format!("{remote_anchor_base_url}/ssi/trust-entity/v1/{}", did.did);
        self.client
            .patch(&url)
            .bearer_auth(&bearer_token)
            .json(request)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?
            .send()
            .await
            .map_err(|e| ServiceError::Other(e.to_string()))?
            .error_for_status()
            .map_err(|e| ServiceError::Other(e.to_string()))?;

        Ok(())
    }

    pub async fn get_remote_trust_entity_for_did(
        &self,
        did_id: DidId,
    ) -> Result<GetRemoteTrustEntityResponseDTO, ServiceError> {
        let RemoteOperationProperties {
            did,
            remote_anchor_base_url,
            bearer_token,
            ..
        } = self.prepare_remote_operation_for_did(&did_id, None).await?;

        let url = format!("{remote_anchor_base_url}/ssi/trust-entity/v1/{}", did.did);
        let response: GetRemoteTrustEntityResponseDTO = self
            .client
            .get(&url)
            .bearer_auth(&bearer_token)
            .send()
            .await
            .map_err(|e| ServiceError::Other(e.to_string()))?
            .error_for_status()
            .map_err(|e| ServiceError::Other(e.to_string()))?
            .json()
            .map_err(|e| ServiceError::Other(e.to_string()))?;

        Ok(response)
    }

    async fn prepare_remote_operation_for_did(
        &self,
        did_id: &DidId,
        local_trust_anchor_id: Option<TrustAnchorId>,
    ) -> Result<RemoteOperationProperties, ServiceError> {
        let did = self
            .did_repository
            .get_did(
                did_id,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Did(did_id.to_owned()))?;

        if did.did_type != DidType::Local {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "Only local DIDs allowed".to_string(),
            }
            .into());
        }

        let trust_anchor = self
            .get_trust_anchor(
                // assuming there's already one remote trust anchor created
                local_trust_anchor_id,
                false,
            )
            .await?;
        if trust_anchor.is_publisher {
            return Err(BusinessLogicError::TrustAnchorMustBeClient.into());
        }

        self.trust_provider
            .get(&trust_anchor.r#type)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.r#type.clone()))?;

        // the published reference should look like: {scheme://domain}/ssi/trust/v1/{trustAnchorId}
        let remote_anchor_base_url = trust_anchor
            .publisher_reference
            .split_once("/ssi/")
            .ok_or(ServiceError::MappingError(
                "Invalid publisher reference".to_string(),
            ))?
            .0
            .to_owned();

        let remote_anchor_id = trust_anchor
            .publisher_reference
            .rsplit_once('/')
            .ok_or(ServiceError::MappingError(
                "Invalid publisher reference".to_string(),
            ))?
            .1;

        let remote_anchor_id = TrustAnchorId::from_str(remote_anchor_id)
            .map_err(|e| ServiceError::MappingError(format!("Invalid publisher reference: {e}")))?;

        let bearer_token =
            prepare_bearer_token(&did, &*self.key_provider, &self.key_algorithm_provider).await?;

        Ok(RemoteOperationProperties {
            did,
            remote_anchor_id,
            remote_anchor_base_url,
            bearer_token,
        })
    }
}

struct RemoteOperationProperties {
    did: Did,
    remote_anchor_id: TrustAnchorId,
    remote_anchor_base_url: String,
    bearer_token: String,
}
