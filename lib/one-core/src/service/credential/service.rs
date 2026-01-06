use shared_types::{CredentialId, OrganisationId};
use uuid::Uuid;

use super::CredentialService;
use super::dto::{
    CreateCredentialRequestDTO, CredentialAttestationBlobs, CredentialDetailResponseDTO,
    CredentialRevocationCheckResponseDTO, DetailCredentialClaimResponseDTO,
    GetCredentialListResponseDTO, GetCredentialQueryDTO, SuspendCredentialRequestDTO,
};
use super::mapper::{
    claims_from_create_request, credential_detail_response_from_model, from_create_request,
    get_issuer_details,
};
use super::validator::{
    throw_if_credential_schema_not_in_session_org, validate_format_and_did_method_compatibility,
    validate_redirect_uri, verify_suspension_support,
};
use crate::config::core_config::{FormatType, RevocationType};
use crate::config::validator::protocol::validate_protocol_did_compatibility;
use crate::mapper::identifier::{IdentifierEntitySelection, entities_for_local_active_identifier};
use crate::mapper::list_response_try_into;
use crate::model::certificate::CertificateRelations;
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::common::EntityShareResponseDTO;
use crate::model::credential::{
    Clearable, Credential, CredentialRelations, CredentialRole, CredentialStateEnum,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, KeyFilter, KeyRole};
use crate::model::identifier::{IdentifierRelations, IdentifierState};
use crate::model::interaction::{InteractionRelations, InteractionType};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::validity_credential::ValidityCredentialType;
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::issuance_protocol::model::ShareResponse;
use crate::provider::revocation::model::{
    CredentialDataByRole, Operation, RevocationMethodCapabilities, RevocationState,
};
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::validator::validate_key_storage_security_supported;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::util::interactions::{add_new_interaction, clear_previous_interaction};
use crate::validator::{
    throw_if_credential_state_eq, throw_if_org_not_matching_session,
    throw_if_org_relation_not_matching_session, throw_if_state_not_in,
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
                .await?
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
                    .await?
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
            .await?
        else {
            return Err(EntityNotFoundError::CredentialSchema(request.credential_schema_id).into());
        };
        throw_if_org_relation_not_matching_session(
            schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        validate_key_storage_security_supported(schema.key_storage_security, &self.config)?;

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
            role: Some(KeyRole::AssertionMethod),
            algorithms: Some(formatter_capabilities.signing_key_algorithms.clone()),
        };
        let selected_entities = entities_for_local_active_identifier(
            &issuer_identifier,
            &key_filter,
            request.issuer_key,
            request.issuer_did,
            request.issuer_certificate,
        )?;

        let (issuer_key, issuer_certificate) = match selected_entities {
            IdentifierEntitySelection::Key(_) => {
                return Err(ServiceError::ValidationError(
                    "Key identifiers not supported".to_string(),
                ));
            }
            IdentifierEntitySelection::Certificate { certificate, key } => {
                (key, Some(certificate.to_owned()))
            }
            IdentifierEntitySelection::Did { did, key } => {
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
                (key, None)
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

        let credential_id = Uuid::new_v4().into();
        let claims = claims_from_create_request(
            credential_id,
            request.claim_values.clone(),
            &claim_schemas,
        )?;

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
            .create_credential(credential.to_owned())
            .await?;

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
            .await?;

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

        let revocation_type = self
            .config
            .revocation
            .get_fields(&schema.revocation_method)
            .map_err(|err| {
                ServiceError::MappingError(format!(
                    "Unknown revocation method: {}: {err}",
                    schema.revocation_method
                ))
            })?
            .r#type();

        let is_issuer = credential.role == CredentialRole::Issuer;
        if is_issuer && *revocation_type != RevocationType::None {
            throw_if_credential_state_eq(&credential, CredentialStateEnum::Accepted)?;
        }

        self.credential_repository
            .delete_credential(&credential)
            .await
            .map_err(|error| match error {
                // credential not found or already deleted
                DataLayerError::RecordNotUpdated => {
                    EntityNotFoundError::Credential(*credential_id).into()
                }
                error => ServiceError::from(error),
            })?;

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
            .await?;

        let credential = credential.ok_or(EntityNotFoundError::Credential(*credential_id))?;
        throw_if_credential_schema_not_in_session_org(&credential, &*self.session_provider)?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        }

        let mdoc_validity_credentials = match &credential.schema {
            Some(schema) if schema.format.to_string() == "MDOC" => {
                self.validity_credential_repository
                    .get_latest_by_credential_id(*credential_id, ValidityCredentialType::Mdoc)
                    .await?
            }
            _ => None,
        };

        let attestation_blobs = self.get_wallet_attestation_blobs(&credential).await?;

        let mut response = credential_detail_response_from_model(
            credential,
            &self.config,
            mdoc_validity_credentials,
            attestation_blobs,
        )?;

        if response.schema.revocation_method == "LVVC" {
            let latest_lvvc = self
                .validity_credential_repository
                .get_latest_by_credential_id(credential_id.to_owned(), ValidityCredentialType::Lvvc)
                .await?;

            if let Some(latest_lvvc) = latest_lvvc {
                response.lvvc_issuance_date = Some(latest_lvvc.created_date);
            }
        }

        Ok(response)
    }

    async fn get_wallet_attestation_blobs(
        &self,
        credential: &Credential,
    ) -> Result<CredentialAttestationBlobs, ServiceError> {
        if credential.wallet_app_attestation_blob_id.is_none()
            && credential.wallet_unit_attestation_blob_id.is_none()
        {
            return Ok(CredentialAttestationBlobs::default());
        }

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))?;

        let wallet_app_attestation_blob = match &credential.wallet_app_attestation_blob_id {
            Some(blob_id) => Some(db_blob_storage.get(blob_id).await?.ok_or(
                ServiceError::MappingError("wallet app attestation blob is None".to_string()),
            )?),
            None => None,
        };
        let wallet_unit_attestation_blob = match &credential.wallet_unit_attestation_blob_id {
            Some(blob_id) => Some(db_blob_storage.get(blob_id).await?.ok_or(
                ServiceError::MappingError("wallet unit attestation blob is None".to_string()),
            )?),
            None => None,
        };

        Ok(CredentialAttestationBlobs {
            wallet_app_attestation_blob,
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
            .await?;

        list_response_try_into(result)
    }

    pub async fn reactivate_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), ServiceError> {
        self.change_issued_credential_revocation_state(credential_id, RevocationState::Valid)
            .await?;
        Ok(())
    }

    pub async fn suspend_credential(
        &self,
        credential_id: &CredentialId,
        request: SuspendCredentialRequestDTO,
    ) -> Result<(), ServiceError> {
        self.change_issued_credential_revocation_state(
            credential_id,
            RevocationState::Suspended {
                suspend_end_date: request.suspend_end_date,
            },
        )
        .await?;
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
        self.change_issued_credential_revocation_state(credential_id, RevocationState::Revoked)
            .await?;
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
                self.check_credential_revocation_status(credential_id, force_refresh)
                    .await?,
            );
        }
        Ok(result)
    }

    /// Returns URL of shared credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn share_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<EntityShareResponseDTO, ServiceError> {
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

        let credential_exchange = &credential.protocol;

        let Some(organisation) = &credential_schema.organisation else {
            return Err(ServiceError::MappingError(
                "Missing organisation".to_string(),
            ));
        };

        self.config
            .issuance_protocol
            .get_fields(credential_exchange)
            .map_err(|err| {
                ServiceError::MissingExchangeProtocol(format!("{credential_exchange}: {err}"))
            })?;

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
        } = exchange.issuer_share_credential(&credential).await?;

        add_new_interaction(
            interaction_id,
            &*self.interaction_repository,
            interaction_data,
            Some(organisation.to_owned()),
            InteractionType::Issuance,
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
            .await?;
        clear_previous_interaction(&*self.interaction_repository, &credential.interaction).await?;

        Ok(EntityShareResponseDTO { url, expires_at })
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
            .await?
            .ok_or(EntityNotFoundError::Credential(*id))?;

        Ok(credential)
    }

    async fn change_issued_credential_revocation_state(
        &self,
        credential_id: &CredentialId,
        revocation_state: RevocationState,
    ) -> Result<(), ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        certificates: Some(CertificateRelations {
                            key: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        };

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        }

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential schema is None".to_string(),
            ))?;

        throw_if_org_relation_not_matching_session(
            credential_schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        verify_suspension_support(credential_schema, &revocation_state)?;

        let current_state = &credential.state;

        let valid_states: &[CredentialStateEnum] = match revocation_state {
            RevocationState::Revoked => &[
                CredentialStateEnum::Accepted,
                CredentialStateEnum::Suspended,
            ],
            RevocationState::Valid => &[CredentialStateEnum::Suspended],
            RevocationState::Suspended { .. } => &[CredentialStateEnum::Accepted],
        };
        throw_if_state_not_in(current_state, valid_states)?;

        let revocation_method_key = &credential_schema.revocation_method;

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(revocation_method_key)
            .ok_or(MissingProviderError::RevocationMethod(
                revocation_method_key.to_owned(),
            ))?;

        let capabilities: RevocationMethodCapabilities = revocation_method.get_capabilities();
        let required_capability = match revocation_state {
            RevocationState::Valid | RevocationState::Suspended { .. } => Operation::Suspend,
            RevocationState::Revoked => Operation::Revoke,
        };
        if !capabilities.operations.contains(&required_capability) {
            return Err(
                BusinessLogicError::OperationNotSupportedByRevocationMethod {
                    operation: revocation_state.to_string(),
                }
                .into(),
            );
        }
        revocation_method
            .mark_credential_as(&credential, revocation_state.to_owned())
            .await?;

        let suspend_end_date =
            if let RevocationState::Suspended { suspend_end_date } = &revocation_state {
                suspend_end_date.to_owned()
            } else {
                None
            };
        self.credential_repository
            .update_credential(
                *credential_id,
                UpdateCredentialRequest {
                    state: Some(revocation_state.to_owned().into()),
                    suspend_end_date: Clearable::ForceSet(suspend_end_date),
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }

    async fn check_credential_revocation_status(
        &self,
        credential_id: CredentialId,
        force_refresh: bool,
    ) -> Result<CredentialRevocationCheckResponseDTO, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                &credential_id,
                &CredentialRelations {
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        certificates: Some(CertificateRelations {
                            key: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::Credential(credential_id),
            ))?;
        throw_if_credential_schema_not_in_session_org(&credential, &*self.session_provider)?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(credential_id).into());
        }
        if credential.role != CredentialRole::Holder {
            return Err(BusinessLogicError::RevocationCheckNotAllowedForRole {
                role: credential.role,
                credential_id,
            }
            .into());
        }

        let current_state = credential.state;
        match current_state {
            CredentialStateEnum::Accepted | CredentialStateEnum::Suspended => {
                // continue flow
            }
            CredentialStateEnum::Revoked => {
                // credential already revoked, no need to check further
                return Ok(CredentialRevocationCheckResponseDTO {
                    credential_id,
                    status: CredentialStateEnum::Revoked.into(),
                    success: true,
                    reason: None,
                });
            }
            _ => {
                // cannot check pending/offered credentials etc
                return Ok(CredentialRevocationCheckResponseDTO {
                    credential_id,
                    success: false,
                    reason: Some(format!("Invalid credential state: {current_state}")),
                    status: current_state.into(),
                });
            }
        };

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?
            .clone();

        let credentials = if let Some(credential_blob_id) = credential.credential_blob_id {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)
                .await
                .ok_or_else(|| {
                    MissingProviderError::BlobStorage(BlobStorageType::Db.to_string())
                })?;

            blob_storage
                .get(&credential_blob_id)
                .await?
                .ok_or(ServiceError::MappingError(
                    "credential blob is None".to_string(),
                ))?
                .value
        } else {
            vec![]
        };

        let credential_str = String::from_utf8(credentials)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        // Workaround credential format detection
        let format = self
            .config
            .format
            .get_fields(&credential_schema.format)?
            .r#type;

        let Some(formatter) = self
            .formatter_provider
            .get_credential_formatter(&credential_schema.format)
        else {
            return Err(
                MissingProviderError::Formatter(credential_schema.format.to_string()).into(),
            );
        };

        let detail_credential = formatter
            .extract_credentials_unverified(&credential_str, Some(&credential_schema))
            .await?;

        if format == FormatType::Mdoc {
            // Mdoc flow ends here. Nothing else to do for MDOC, since it does not have revocation mechanism
            return self
                .update_mdoc(&credential, &detail_credential, force_refresh)
                .await;
        }

        let credential_status = if !detail_credential.status.is_empty() {
            detail_credential.status
        } else {
            // no credential status -> credential is irrevocable
            return Ok(CredentialRevocationCheckResponseDTO {
                credential_id,
                status: CredentialStateEnum::Accepted.into(),
                success: true,
                reason: None,
            });
        };

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&credential_schema.revocation_method)
            .ok_or(MissingProviderError::RevocationMethod(
                credential_schema.revocation_method.clone(),
            ))?;

        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "issuer_identifier is None".to_string(),
                ))?;

        let issuer_details = get_issuer_details(issuer_identifier)?;

        let credential_data_by_role = match credential.role {
            CredentialRole::Holder => {
                Some(CredentialDataByRole::Holder(Box::new(credential.clone())))
            }
            CredentialRole::Issuer | CredentialRole::Verifier => None,
        };

        let mut worst_revocation_state = RevocationState::Valid;
        for status in credential_status {
            match revocation_method
                .check_credential_revocation_status(
                    &status,
                    &issuer_details,
                    credential_data_by_role.to_owned(),
                    force_refresh,
                )
                .await
            {
                Err(error) => {
                    return Ok(CredentialRevocationCheckResponseDTO {
                        credential_id,
                        status: current_state.into(),
                        success: false,
                        reason: Some(error.to_string()),
                    });
                }
                Ok(state) => match state {
                    RevocationState::Valid => {}
                    RevocationState::Revoked => {
                        worst_revocation_state = state;
                        break;
                    }
                    RevocationState::Suspended { .. } => {
                        worst_revocation_state = state;
                    }
                },
            };
        }

        let suspend_end_date = match &worst_revocation_state {
            RevocationState::Suspended { suspend_end_date } => suspend_end_date.to_owned(),
            _ => None,
        };
        let detected_state = worst_revocation_state.into();

        // update local credential state if change detected
        if current_state != detected_state {
            self.credential_repository
                .update_credential(
                    credential_id,
                    UpdateCredentialRequest {
                        state: Some(detected_state),
                        suspend_end_date: Clearable::ForceSet(suspend_end_date),
                        ..Default::default()
                    },
                )
                .await?;
        }

        Ok(CredentialRevocationCheckResponseDTO {
            credential_id,
            status: detected_state.into(),
            success: true,
            reason: None,
        })
    }
}
