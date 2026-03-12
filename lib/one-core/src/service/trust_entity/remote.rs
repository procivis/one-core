use std::str::FromStr;

use shared_types::{DidId, TrustAnchorId, TrustEntityId};

use super::TrustEntityService;
use super::dto::{
    CreateRemoteTrustEntityRequestDTO, CreateTrustEntityFromDidPublisherRequestDTO,
    CreateTrustEntityFromDidPublisherResponseDTO, GetRemoteTrustEntityResponseDTO,
    UpdateTrustEntityActionFromDidRequestDTO, UpdateTrustEntityFromDidRequestDTO,
};
use super::error::TrustEntityServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::did::{Did, DidRelations};
use crate::model::identifier::IdentifierRelations;
use crate::model::key::KeyRelations;
use crate::proto::bearer_token::prepare_bearer_token;
use crate::service::error::MissingProviderError;

impl TrustEntityService {
    pub async fn create_remote_trust_entity_for_did(
        &self,
        request: CreateRemoteTrustEntityRequestDTO,
    ) -> Result<TrustEntityId, TrustEntityServiceError> {
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
        let response: CreateTrustEntityFromDidPublisherResponseDTO = async {
            self.client
                .post(&url)
                .bearer_auth(&bearer_token)
                .json(request)?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("posting trust entity")?;

        Ok(response.id)
    }

    pub async fn update_remote_trust_entity_for_did(
        &self,
        did_id: DidId,
        request: UpdateTrustEntityFromDidRequestDTO,
    ) -> Result<(), TrustEntityServiceError> {
        if let Some(UpdateTrustEntityActionFromDidRequestDTO::Remove) = request.action {
            return Err(TrustEntityServiceError::InvalidUpdateRequest);
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
        async {
            self.client
                .patch(&url)
                .bearer_auth(&bearer_token)
                .json(request)?
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("patching trust entity")?;

        Ok(())
    }

    pub async fn get_remote_trust_entity_for_did(
        &self,
        did_id: DidId,
    ) -> Result<GetRemoteTrustEntityResponseDTO, TrustEntityServiceError> {
        let RemoteOperationProperties {
            did,
            remote_anchor_base_url,
            bearer_token,
            ..
        } = self.prepare_remote_operation_for_did(&did_id, None).await?;

        let url = format!("{remote_anchor_base_url}/ssi/trust-entity/v1/{}", did.did);
        let response: GetRemoteTrustEntityResponseDTO = async {
            self.client
                .get(&url)
                .bearer_auth(&bearer_token)
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("fetching trust entity")?;

        Ok(response)
    }

    async fn prepare_remote_operation_for_did(
        &self,
        did_id: &DidId,
        local_trust_anchor_id: Option<TrustAnchorId>,
    ) -> Result<RemoteOperationProperties, TrustEntityServiceError> {
        let identifier = self
            .identifier_repository
            .get_from_did_id(
                *did_id,
                &IdentifierRelations {
                    did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting identifier")?
            .ok_or(TrustEntityServiceError::MissingDid(did_id.to_owned()))?;

        if identifier.is_remote {
            return Err(TrustEntityServiceError::IncompatibleDidType {
                reason: "Only local DIDs allowed".to_string(),
            });
        }

        let trust_anchor = self
            .get_trust_anchor(
                // assuming there's already one remote trust anchor created
                local_trust_anchor_id,
                false,
            )
            .await?;
        if trust_anchor.is_publisher {
            return Err(TrustEntityServiceError::TrustAnchorMustBeClient);
        }

        self.trust_provider
            .get(&trust_anchor.r#type)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.r#type.clone()))
            .error_while("getting trust manager")?;

        // the published reference should look like: {scheme://domain}/ssi/trust/v1/{trustAnchorId}
        let remote_anchor_base_url = trust_anchor
            .publisher_reference
            .split_once("/ssi/")
            .ok_or(TrustEntityServiceError::MappingError(
                "Invalid publisher reference".to_string(),
            ))?
            .0
            .to_owned();

        let remote_anchor_id = trust_anchor
            .publisher_reference
            .rsplit_once('/')
            .ok_or(TrustEntityServiceError::MappingError(
                "Invalid publisher reference".to_string(),
            ))?
            .1;

        let remote_anchor_id = TrustAnchorId::from_str(remote_anchor_id).map_err(|e| {
            TrustEntityServiceError::MappingError(format!("Invalid publisher reference: {e}"))
        })?;

        let bearer_token = prepare_bearer_token(
            &identifier,
            &*self.key_provider,
            &self.key_algorithm_provider,
        )
        .await
        .error_while("preparing bearer token")?;

        Ok(RemoteOperationProperties {
            did: identifier.did.ok_or(TrustEntityServiceError::MappingError(
                "missing did".to_string(),
            ))?,
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
