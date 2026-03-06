use one_dto_mapper::convert_inner;
use shared_types::{CredentialId, OrganisationId};
use uuid::Uuid;

use super::CredentialService;
use super::dto::{
    CreateCredentialRequestDTO, CredentialAttestationBlobs, CredentialDetailResponseDTO,
    CredentialRevocationCheckResponseDTO, DetailCredentialClaimResponseDTO,
    GetCredentialListResponseDTO, GetCredentialQueryDTO, ShareCredentialResponseDTO,
    SuspendCredentialRequestDTO,
};
use super::mapper::{
    claims_from_create_request, credential_detail_response_from_model, from_create_request,
};
use super::validator::{validate_format_and_did_method_compatibility, validate_redirect_uri};
use crate::config::validator::protocol::validate_protocol_did_compatibility;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::list_response_try_into;
use crate::model::certificate::CertificateRelations;
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Credential, CredentialRelations, CredentialRole, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, KeyRole};
use crate::model::identifier::{IdentifierRelations, IdentifierState};
use crate::model::interaction::{InteractionRelations, InteractionType};
use crate::model::organisation::OrganisationRelations;
use crate::model::validity_credential::ValidityCredentialType;
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::issuance_protocol::model::ShareResponse;
use crate::provider::revocation::model::RevocationState;
use crate::repository::error::DataLayerError;
use crate::service::credential::validator::validate_webhook_url;
use crate::service::credential_schema::validator::validate_key_storage_security_supported;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::util::interactions::{add_new_interaction, clear_previous_interaction};
use crate::util::key_selection::{KeyFilter, KeySelection, SelectedKey};
use crate::validator::{
    throw_if_credential_schema_not_in_session_org, throw_if_credential_state_eq,
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
};

impl CredentialService {
    /// Creates a credential according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential request
    pub async fn create_credential(
        &self,
        request: CreateCredentialRequestDTO,
    ) -> Result<CredentialId, ServiceError> {
        let issuer_identifier = match request.issuer {
            Some(issuer_identifier_id) => self
                .identifier_repository
                .get(
                    issuer_identifier_id,
                    &IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(Default::default()),
                            ..Default::default()
                        }),
                        certificates: Some(CertificateRelations {
                            key: Some(Default::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await
                .error_while("getting identifier")?
                .ok_or(ServiceError::from(EntityNotFoundError::Identifier(
                    issuer_identifier_id,
                )))?,
            None => {
                let issuer_did_id = request.issuer_did.ok_or(ServiceError::ValidationError(
                    "No issuer or issuerDid specified".to_string(),
                ))?;

                self.identifier_repository
                    .get_from_did_id(
                        issuer_did_id,
                        &IdentifierRelations {
                            did: Some(DidRelations {
                                keys: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("getting identifier")?
                    .ok_or(ServiceError::from(EntityNotFoundError::Did(issuer_did_id)))?
            }
        };

        let Some(schema) = self
            .credential_schema_repository
            .get_credential_schema(
                &request.credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(Default::default()),
                    organisation: Some(Default::default()),
                },
            )
            .await
            .error_while("getting credential schema")?
        else {
            return Err(EntityNotFoundError::CredentialSchema(request.credential_schema_id).into());
        };
        throw_if_org_relation_not_matching_session(
            schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        validate_key_storage_security_supported(schema.key_storage_security, &self.config)
            .error_while("validating key storage security")?;

        let claim_schemas = schema
            .claim_schemas
            .to_owned()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;

        let formatter_capabilities = self
            .formatter_provider
            .get_credential_formatter(&schema.format)
            .ok_or(MissingProviderError::Formatter(schema.format.to_string()))?
            .get_capabilities();

        let exchange_capabilities = self
            .protocol_provider
            .get_protocol(&request.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(
                request.protocol.to_owned(),
            ))?
            .get_capabilities();

        let key_filter = KeyFilter {
            did_role: Some(KeyRole::AssertionMethod),
            algorithms: Some(formatter_capabilities.signing_key_algorithms.clone()),
            ..Default::default()
        };
        let selection = issuer_identifier.select_key(KeySelection {
            key: request.issuer_key,
            did: request.issuer_did,
            certificate: request.issuer_certificate,
            key_filter: Some(key_filter),
        })?;

        let (issuer_key, issuer_certificate) = match selection {
            SelectedKey::Key(_) => {
                return Err(ServiceError::ValidationError(
                    "Key identifiers not supported".to_string(),
                ));
            }
            SelectedKey::Certificate { certificate, key } => (key, Some(certificate.to_owned())),
            SelectedKey::Did { did, key } => {
                validate_protocol_did_compatibility(
                    &exchange_capabilities.did_methods,
                    &did.did_method,
                    &self.config.did,
                )?;
                validate_format_and_did_method_compatibility(
                    &did.did_method,
                    &formatter_capabilities,
                    &self.config,
                )?;
                (&key.key, None)
            }
        };

        super::validator::validate_create_request(
            &request.protocol,
            &request.claim_values,
            &schema,
            &formatter_capabilities,
            &self.config,
        )?;
        validate_redirect_uri(
            &request.protocol,
            request.redirect_uri.as_deref(),
            &self.config,
        )?;
        validate_webhook_url(
            request.webhook_destination_url.as_ref(),
            &request.protocol,
            &self.config,
            self.notification_scheduler.as_ref(),
        )?;

        let credential_id = Uuid::new_v4().into();
        let claims = claims_from_create_request(
            credential_id,
            request.claim_values.clone(),
            &claim_schemas,
        )?;

        let success_log = format!(
            "Created credential {} using schema `{}` ({}) and issuer `{}` ({}): protocol `{}`",
            credential_id,
            schema.name,
            schema.id,
            issuer_identifier.name,
            issuer_identifier.id,
            request.protocol
        );
        let issuer_key = issuer_key.to_owned();
        let credential = from_create_request(
            request,
            credential_id,
            claims,
            issuer_identifier,
            issuer_certificate,
            schema,
            issuer_key,
        );

        let result = self
            .credential_repository
            .create_credential(credential)
            .await
            .error_while("creating credential")?;

        tracing::info!(message = success_log);
        Ok(result)
    }

    /// Deletes a credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn delete_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        };

        let schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential_schema is None".to_string(),
            ))?;
        throw_if_org_relation_not_matching_session(
            schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        let is_issuer = credential.role == CredentialRole::Issuer;
        if is_issuer && let Some(method_id) = &schema.revocation_method {
            let _revocation_fields = self
                .config
                .revocation
                .get_fields(method_id)
                .error_while("getting revocation config")?;
            throw_if_credential_state_eq(&credential, CredentialStateEnum::Accepted)?;
        }

        self.credential_repository
            .delete_credential(&credential)
            .await
            .map_err(|error| match error {
                // credential not found or already deleted
                DataLayerError::RecordNotUpdated => {
                    ServiceError::from(EntityNotFoundError::Credential(*credential_id))
                }
                error => error.error_while("deleting credential").into(),
            })?;

        tracing::info!("Deleted credential {}", credential.id);
        Ok(())
    }

    /// Returns details of a credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn get_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    issuer_identifier: Some(Default::default()),
                    issuer_certificate: Some(CertificateRelations::default()),
                    holder_identifier: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?;

        let credential = credential.ok_or(EntityNotFoundError::Credential(*credential_id))?;
        throw_if_credential_schema_not_in_session_org(&credential, &*self.session_provider)?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        }

        let mdoc_validity_credentials = match &credential.schema {
            Some(schema) if schema.format.to_string() == "MDOC" => self
                .validity_credential_repository
                .get_latest_by_credential_id(*credential_id, ValidityCredentialType::Mdoc)
                .await
                .error_while("getting validity credential")?,
            _ => None,
        };

        let attestation_blobs = self.get_wallet_attestation_blobs(&credential).await?;

        let response = credential_detail_response_from_model(
            credential,
            &self.config,
            mdoc_validity_credentials,
            attestation_blobs,
        )?;

        Ok(response)
    }

    async fn get_wallet_attestation_blobs(
        &self,
        credential: &Credential,
    ) -> Result<CredentialAttestationBlobs, ServiceError> {
        if credential.wallet_instance_attestation_blob_id.is_none()
            && credential.wallet_unit_attestation_blob_id.is_none()
        {
            return Ok(CredentialAttestationBlobs::default());
        }

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))?;

        let wallet_instance_attestation_blob = match &credential.wallet_instance_attestation_blob_id
        {
            Some(blob_id) => Some(
                db_blob_storage
                    .get(blob_id)
                    .await
                    .error_while("getting WIA blob")?
                    .ok_or(ServiceError::MappingError(
                        "wallet instance attestation blob is None".to_string(),
                    ))?,
            ),
            None => None,
        };
        let wallet_unit_attestation_blob = match &credential.wallet_unit_attestation_blob_id {
            Some(blob_id) => Some(
                db_blob_storage
                    .get(blob_id)
                    .await
                    .error_while("getting WUA blob")?
                    .ok_or(ServiceError::MappingError(
                        "wallet unit attestation blob is None".to_string(),
                    ))?,
            ),
            None => None,
        };

        Ok(CredentialAttestationBlobs {
            wallet_instance_attestation_blob,
            wallet_unit_attestation_blob,
        })
    }

    /// Returns list of credentials according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_credential_list(
        &self,
        organisation_id: &OrganisationId,
        query: GetCredentialQueryDTO,
    ) -> Result<GetCredentialListResponseDTO, ServiceError> {
        throw_if_org_not_matching_session(organisation_id, &*self.session_provider)?;
        let result = self
            .credential_repository
            .get_credential_list(query)
            .await
            .error_while("getting credentials")?;

        list_response_try_into(result)
    }

    pub async fn reactivate_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), ServiceError> {
        self.credential_validity_manager
            .change_credential_validity_state(credential_id, RevocationState::Valid)
            .await
            .error_while("reactivating credential")?;
        tracing::info!("Reactivated credential {credential_id}");
        Ok(())
    }

    pub async fn suspend_credential(
        &self,
        credential_id: &CredentialId,
        request: SuspendCredentialRequestDTO,
    ) -> Result<(), ServiceError> {
        self.credential_validity_manager
            .change_credential_validity_state(
                credential_id,
                RevocationState::Suspended {
                    suspend_end_date: request.suspend_end_date,
                },
            )
            .await
            .error_while("suspending credential")?;
        tracing::info!("Suspended credential {credential_id}");
        Ok(())
    }

    /// Revokes credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn revoke_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), ServiceError> {
        self.credential_validity_manager
            .change_credential_validity_state(credential_id, RevocationState::Revoked)
            .await
            .error_while("revoking credential")?;
        tracing::info!("Revoked credential {credential_id}");
        Ok(())
    }

    /// Checks credentials' revocation status
    ///
    /// # Arguments
    ///
    /// * `credential_ids` - credentials to check
    pub async fn check_revocation(
        &self,
        credential_ids: Vec<CredentialId>,
        force_refresh: bool,
    ) -> Result<Vec<CredentialRevocationCheckResponseDTO>, ServiceError> {
        let mut result = vec![];
        for credential_id in credential_ids {
            result.push(
                self.credential_validity_manager
                    .check_holder_credential_validity(credential_id, force_refresh)
                    .await
                    .error_while("checking credential validity")?,
            );
        }
        Ok(convert_inner(result))
    }

    /// Returns URL of shared credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn share_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<ShareCredentialResponseDTO, ServiceError> {
        let credential = self.get_credential_with_state(credential_id).await?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        }
        let Some(credential_schema) = credential.schema.as_ref() else {
            return Err(ServiceError::MappingError(
                "Missing credential schema".to_string(),
            ));
        };
        throw_if_org_relation_not_matching_session(
            credential_schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        if !matches!(
            credential.state,
            CredentialStateEnum::Created
                | CredentialStateEnum::Pending
                | CredentialStateEnum::InteractionExpired
        ) {
            return Err(BusinessLogicError::InvalidCredentialState {
                state: credential.state,
            }
            .into());
        }

        let Some(issuer_identifier) = credential.issuer_identifier.as_ref() else {
            return Err(ServiceError::MappingError(
                "Missing issuer identifier".to_string(),
            ));
        };

        if issuer_identifier.state != IdentifierState::Active {
            return Err(BusinessLogicError::IdentifierIsDeactivated(issuer_identifier.id).into());
        }

        let Some(organisation) = &credential_schema.organisation else {
            return Err(ServiceError::MappingError(
                "Missing organisation".to_string(),
            ));
        };

        let credential_exchange = &credential.protocol;
        let exchange = self
            .protocol_provider
            .get_protocol(credential_exchange)
            .ok_or(MissingProviderError::ExchangeProtocol(
                credential_exchange.clone(),
            ))?;

        let ShareResponse {
            url,
            interaction_id,
            interaction_data,
            expires_at,
            transaction_code,
        } = exchange
            .issuer_share_credential(&credential)
            .await
            .error_while("sharing credential")?;

        add_new_interaction(
            interaction_id,
            &*self.interaction_repository,
            interaction_data,
            Some(organisation.to_owned()),
            InteractionType::Issuance,
            expires_at,
        )
        .await?;
        self.credential_repository
            .update_credential(
                *credential_id,
                UpdateCredentialRequest {
                    state: (credential.state != CredentialStateEnum::Pending)
                        .then_some(CredentialStateEnum::Pending),
                    interaction: Some(interaction_id),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;
        clear_previous_interaction(&*self.interaction_repository, &credential.interaction).await?;
        tracing::info!("Shared credential {credential_id}");
        Ok(ShareCredentialResponseDTO {
            url,
            expires_at,
            transaction_code,
        })
    }

    // ============ Private methods

    /// Get credential with the latest credential state
    async fn get_credential_with_state(
        &self,
        id: &CredentialId,
    ) -> Result<Credential, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations::default()),
                    issuer_certificate: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?
            .ok_or(EntityNotFoundError::Credential(*id))?;

        Ok(credential)
    }
}
