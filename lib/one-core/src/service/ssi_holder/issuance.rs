use std::sync::Arc;

use shared_types::{CredentialId, DidId, IdentifierId, KeyId};
use time::OffsetDateTime;
use url::Url;

use super::SSIHolderService;
use super::dto::HandleInvitationResultDTO;
use crate::common_mapper::value_to_model_claims;
use crate::common_validator::throw_if_credential_state_not_eq;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Clearable, Credential, CredentialRelations, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidRelations, KeyRole};
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::interaction::{InteractionId, InteractionRelations};
use crate::model::key::Key;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::provider::issuance_protocol::IssuanceProtocol;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::openid4vci_draft13::handle_invitation_operations::HandleInvitationOperationsImpl;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    InvitationResponseDTO, SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::key_storage::model::KeySecurity;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::ssi_holder::validator::validate_holder_capabilities;
use crate::service::storage_proxy::StorageProxyImpl;
use crate::util::oidc::map_to_openid4vp_format;

impl SSIHolderService {
    pub async fn accept_credential(
        &self,
        interaction_id: &InteractionId,
        did_id: Option<DidId>,
        identifier_id: Option<IdentifierId>,
        key_id: Option<KeyId>,
        tx_code: Option<String>,
    ) -> Result<(), ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?;

        if credentials.is_empty() {
            return Err(BusinessLogicError::MissingCredentialsForInteraction {
                interaction_id: *interaction_id,
            }
            .into());
        }

        let identifier = match (did_id, identifier_id) {
            (Some(did_id), None) => self
                .identifier_repository
                .get_from_did_id(
                    did_id,
                    &IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(Default::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or(ServiceError::from(ValidationError::DidNotFound))?,
            (None, Some(identifier_id)) => self
                .identifier_repository
                .get(
                    identifier_id,
                    &IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(Default::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or(ServiceError::from(EntityNotFoundError::Identifier(
                    identifier_id,
                )))?,
            (Some(_), Some(_)) | (None, None) => {
                return Err(BusinessLogicError::OverlappingHolderDidWithIdentifier.into());
            }
        };

        let did = identifier.did.to_owned().ok_or(ServiceError::MappingError(
            "missing identifier did".to_string(),
        ))?;

        let selected_key = match key_id {
            Some(key_id) => did
                .find_key(&key_id, KeyRole::Authentication)?
                .ok_or(ValidationError::KeyNotFound)?,
            None => did.find_first_key_by_role(KeyRole::Authentication)?.ok_or(
                ValidationError::InvalidKey(
                    "No key with role authentication available".to_string(),
                ),
            )?,
        };

        let holder_jwk_key_id = self
            .did_method_provider
            .get_verification_method_id_from_did_and_key(&did, selected_key)
            .await?;

        let key_security = self
            .key_provider
            .get_key_storage(&selected_key.storage_type)
            .ok_or_else(|| MissingProviderError::KeyStorage(selected_key.storage_type.clone()))?
            .get_capabilities()
            .security;

        // Errors are gathered into vec, so we can try to accept all credentials.
        let mut errors = vec![];

        for credential in credentials {
            if let Err(error) = self
                .accept_and_save_credential(
                    &credential,
                    &did,
                    &identifier,
                    &key_security,
                    selected_key,
                    &holder_jwk_key_id,
                    tx_code.clone(),
                )
                .await
            {
                tracing::error!("Failed to accept credential: {error}");

                let _result = self
                    .credential_repository
                    .update_credential(
                        credential.id,
                        UpdateCredentialRequest {
                            state: Some(CredentialStateEnum::Error),
                            ..Default::default()
                        },
                    )
                    .await;

                errors.push(error);
            }
        }

        if let Some(error) = errors.into_iter().next() {
            return Err(error);
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn accept_and_save_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        holder_identifer: &Identifier,
        key_security: &[KeySecurity],
        selected_key: &Key,
        holder_jwk_key_id: &str,
        tx_code: Option<String>,
    ) -> Result<(), ServiceError> {
        throw_if_credential_state_not_eq(credential, CredentialStateEnum::Pending)?;

        let wallet_storage_matches = match credential
            .schema
            .as_ref()
            .and_then(|schema| schema.wallet_storage_type.as_ref())
        {
            Some(WalletStorageTypeEnum::Hardware) => key_security.contains(&KeySecurity::Hardware),
            Some(WalletStorageTypeEnum::Software) => key_security.contains(&KeySecurity::Software),
            Some(WalletStorageTypeEnum::RemoteSecureElement) => {
                key_security.contains(&KeySecurity::RemoteSecureElement)
            }
            None => true,
        };

        if !wallet_storage_matches {
            return Err(BusinessLogicError::UnfulfilledWalletStorageType.into());
        }

        let storage_access = StorageProxyImpl::new(
            self.interaction_repository.clone(),
            self.credential_schema_repository.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
            self.identifier_repository.clone(),
            self.did_method_provider.clone(),
        );

        let schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("schema is None".to_string()))?;

        let format = &schema.format;
        let formatter =
            self.formatter_provider
                .get_formatter(format)
                .ok_or(ServiceError::MissingProvider(
                    MissingProviderError::Formatter(format.to_owned()),
                ))?;

        validate_holder_capabilities(
            &self.config,
            holder_did,
            holder_identifer,
            selected_key,
            &formatter.get_capabilities(),
            self.key_algorithm_provider.as_ref(),
        )?;

        let format_type = self
            .config
            .format
            .get_fields(&schema.format)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .r#type;

        let format = map_to_openid4vp_format(&format_type)
            .map(|s| s.to_string())
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let issuer_response = self
            .issuance_protocol_provider
            .get_protocol(&credential.exchange)
            .ok_or(MissingProviderError::ExchangeProtocol(
                credential.exchange.clone(),
            ))?
            .holder_accept_credential(
                credential,
                holder_did,
                selected_key,
                Some(holder_jwk_key_id.to_string()),
                &format,
                &storage_access,
                tx_code.clone(),
            )
            .await?;

        let issuer_response = self.resolve_update_issuer_response(issuer_response).await?;
        let claims = self
            .extract_claims(&credential.id, &issuer_response.credential, schema)
            .await?;

        self.credential_repository
            .update_credential(
                credential.id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Accepted),
                    suspend_end_date: Clearable::DontTouch,
                    credential: Some(issuer_response.credential.bytes().collect()),
                    holder_identifier_id: Some(holder_identifer.id),
                    key: Some(selected_key.id),
                    claims: Some(claims),
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }

    async fn extract_claims(
        &self,
        credential_id: &CredentialId,
        credential: &str,
        schema: &CredentialSchema,
    ) -> Result<Vec<Claim>, ServiceError> {
        let credential_format = &schema.format;

        let formatter = self
            .formatter_provider
            .get_formatter(credential_format)
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::Formatter(credential_format.to_owned()),
            ))?;

        let credential = formatter
            .extract_credentials_unverified(credential, Some(schema))
            .await
            .map_err(ServiceError::FormatterError)?;

        let mut collected_claims: Vec<Claim> = Vec::new();

        let claim_schemas = schema
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::BusinessLogic(
                BusinessLogicError::MissingClaimSchemas,
            ))?;
        let now = OffsetDateTime::now_utc();

        for (key, value) in credential.claims.claims {
            let this_claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| claim_schema.schema.key == key)
                .ok_or(ServiceError::BusinessLogic(
                    BusinessLogicError::MissingClaimSchemas,
                ))?;

            collected_claims.extend(value_to_model_claims(
                *credential_id,
                claim_schemas,
                &value,
                now,
                &this_claim_schema.schema,
                &key,
            )?);
        }

        Ok(collected_claims)
    }

    pub async fn reject_credential(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<(), ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?;

        if credentials.is_empty() {
            return Err(BusinessLogicError::MissingCredentialsForInteraction {
                interaction_id: *interaction_id,
            }
            .into());
        }

        for credential in credentials {
            throw_if_credential_state_not_eq(&credential, CredentialStateEnum::Pending)?;

            self.issuance_protocol_provider
                .get_protocol(&credential.exchange)
                .ok_or(MissingProviderError::ExchangeProtocol(
                    credential.exchange.clone(),
                ))?
                .holder_reject_credential(&credential)
                .await?;

            self.credential_repository
                .update_credential(
                    credential.id,
                    UpdateCredentialRequest {
                        state: Some(CredentialStateEnum::Rejected),
                        ..Default::default()
                    },
                )
                .await?;
        }

        Ok(())
    }

    pub(super) async fn handle_issuance_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        exchange: String,
        issuance_protocol: Arc<dyn IssuanceProtocol>,
    ) -> Result<HandleInvitationResultDTO, ServiceError> {
        let storage_access = StorageProxyImpl::new(
            self.interaction_repository.clone(),
            self.credential_schema_repository.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
            self.identifier_repository.clone(),
            self.did_method_provider.clone(),
        );

        let handle_operations = HandleInvitationOperationsImpl::new(
            organisation.clone(),
            self.credential_schema_repository.clone(),
            self.vct_type_metadata_cache.clone(),
            self.client.clone(),
        );

        let InvitationResponseDTO {
            credentials,
            interaction_id,
            tx_code,
        } = issuance_protocol
            .holder_handle_invitation(url, organisation, &storage_access, &handle_operations)
            .await?;

        let result = HandleInvitationResultDTO::Credential {
            interaction_id,
            credential_ids: credentials.iter().map(|c| c.id).collect(),
            tx_code,
        };

        for mut credential in credentials {
            credential.exchange = exchange.to_owned();
            self.credential_repository
                .create_credential(credential)
                .await?;
        }

        Ok(result)
    }

    async fn resolve_update_issuer_response(
        &self,
        update_response: UpdateResponse<SubmitIssuerResponse>,
    ) -> Result<SubmitIssuerResponse, ServiceError> {
        if let Some(create_did) = update_response.create_did {
            self.did_repository.create_did(create_did).await?;
        }
        if let Some(create_identifier) = update_response.create_identifier {
            self.identifier_repository.create(create_identifier).await?;
        }
        if let Some(update_credential_schema) = update_response.update_credential_schema {
            self.credential_schema_repository
                .update_credential_schema(update_credential_schema)
                .await?;
        }
        if let Some((credential_id, update_credential)) = update_response.update_credential {
            self.credential_repository
                .update_credential(credential_id, update_credential)
                .await?;
        }
        Ok(update_response.result)
    }
}
