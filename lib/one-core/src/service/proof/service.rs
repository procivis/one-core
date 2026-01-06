use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use shared_types::{CredentialFormat, CredentialId, OrganisationId, ProofId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofService;
use super::dto::{
    CreateProofInteractionData, CreateProofRequestDTO, GetProofListResponseDTO, GetProofQueryDTO,
    ProofDetailResponseDTO, ProposeProofResponseDTO, ShareProofRequestDTO,
};
use super::mapper::{
    get_holder_proof_detail, get_verifier_proof_detail, interaction_data_from_proof,
    proof_from_create_request,
};
use super::validator::{
    throw_if_proof_not_in_session_org, validate_did_and_format_compatibility,
    validate_holder_engagements, validate_mdl_exchange, validate_proof_for_proof_definition,
    validate_redirect_uri, validate_verification_key_storage_compatibility,
    validate_verifier_engagement,
};
use crate::config::core_config::{TransportType, VerificationEngagement, VerificationProtocolType};
use crate::config::validator::protocol::{
    validate_identifier, validate_protocol_did_compatibility, validate_protocol_type,
};
use crate::config::validator::transport::{
    SelectedTransportType, validate_and_select_transport_type,
};
use crate::mapper::identifier::{IdentifierEntitySelection, entities_for_local_active_identifier};
use crate::mapper::list_response_try_into;
use crate::model::certificate::CertificateRelations;
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::common::EntityShareResponseDTO;
use crate::model::credential::{CredentialFilterValue, CredentialRelations, GetCredentialQuery};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, KeyFilter, KeyRole};
use crate::model::history::{HistoryAction, HistoryFilterValue, HistoryListQuery};
use crate::model::identifier::IdentifierRelations;
use crate::model::interaction::{InteractionRelations, InteractionType};
use crate::model::key::KeyRelations;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{
    Proof, ProofClaimRelations, ProofRelations, ProofRole, ProofStateEnum, UpdateProofRequest,
};
use crate::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use crate::proto::nfc::static_handover_handler::NfcStaticHandoverHandler;
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::verification_protocol::dto::{
    PresentationDefinitionResponseDTO, PresentationDefinitionV2ResponseDTO,
    PresentationDefinitionVersion, ShareResponse,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::ble_holder::{
    MdocBleHolderInteractionData, NfcHceSession, receive_mdl_request, start_mdl_server,
};
use crate::provider::verification_protocol::iso_mdl::common::{EDeviceKey, KeyAgreement};
use crate::provider::verification_protocol::iso_mdl::device_engagement::{
    BleOptions, DeviceEngagement, DeviceRetrievalMethod, RetrievalOptions, Security,
};
use crate::provider::verification_protocol::iso_mdl::nfc::create_nfc_handover_select_message;
use crate::provider::verification_protocol::openid4vp::mapper::create_format_map;
use crate::provider::verification_protocol::{FormatMapper, TypeToDescriptorMapper};
use crate::service::credential_schema::validator::validate_key_storage_security_supported;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::proof::dto::ProposeProofRequestDTO;
use crate::service::proof::validator::{
    validate_format_and_exchange_protocol_compatibility, validate_scan_to_verify_compatibility,
};
use crate::service::storage_proxy::StorageProxyImpl;
use crate::util::interactions::{add_new_interaction, clear_previous_interaction};
use crate::validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
};

const DEFAULT_ENGAGEMENT: &str = "QR_CODE";

impl ProofService {
    /// Returns details of a proof
    ///
    /// # Arguments
    ///
    /// * `id` - Proof uuid
    pub async fn get_proof(&self, id: &ProofId) -> Result<ProofDetailResponseDTO, ServiceError> {
        let proof = self
            .proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(Default::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                organisation: None,
                            }),
                        }),
                    }),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            issuer_certificate: Some(CertificateRelations::default()),
                            holder_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    }),
                    verifier_identifier: Some(IdentifierRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_certificate: Some(CertificateRelations::default()),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                },
                None,
            )
            .await?;

        let Some(proof) = proof else {
            return Err(EntityNotFoundError::Proof(*id).into());
        };

        throw_if_proof_not_in_session_org(&proof, &*self.session_provider)?;

        let history_event = self
            .history_repository
            .get_history_list(HistoryListQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 1,
                }),
                sorting: None,
                filtering: Some(
                    HistoryFilterValue::EntityIds(vec![proof.id.into()]).condition()
                        & HistoryFilterValue::Actions(vec![HistoryAction::ClaimsRemoved]),
                ),
                include: None,
            })
            .await?
            .values
            .into_iter()
            .next();

        if proof.schema.is_some() {
            get_verifier_proof_detail(
                proof,
                &self.config,
                history_event,
                &*self.validity_credential_repository,
            )
            .await
        } else {
            get_holder_proof_detail(
                proof,
                &self.config,
                history_event,
                &*self.validity_credential_repository,
            )
            .await
        }
    }

    /// Returns presentation definition of proof
    ///
    /// # Arguments
    ///
    /// * `id` - Proof uuid
    pub async fn get_proof_presentation_definition(
        &self,
        id: &ProofId,
    ) -> Result<PresentationDefinitionResponseDTO, ServiceError> {
        let proof = self.load_proof_for_presentation_definition(id).await?;
        let exchange = self.protocol_provider.get_protocol(&proof.protocol).ok_or(
            MissingProviderError::ExchangeProtocol(proof.protocol.clone()),
        )?;
        validate_proof_for_proof_definition(
            &proof,
            &*self.session_provider,
            &*exchange,
            &PresentationDefinitionVersion::V1,
        )?;
        exchange
            .holder_get_presentation_definition(
                &proof,
                interaction_data_from_proof(&proof)?,
                &self.storage_access(),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn get_proof_presentation_definition_v2(
        &self,
        id: &ProofId,
    ) -> Result<PresentationDefinitionV2ResponseDTO, ServiceError> {
        let proof = self.load_proof_for_presentation_definition(id).await?;
        let exchange = self.protocol_provider.get_protocol(&proof.protocol).ok_or(
            MissingProviderError::ExchangeProtocol(proof.protocol.clone()),
        )?;
        validate_proof_for_proof_definition(
            &proof,
            &*self.session_provider,
            &*exchange,
            &PresentationDefinitionVersion::V2,
        )?;
        exchange
            .holder_get_presentation_definition_v2(
                &proof,
                interaction_data_from_proof(&proof)?,
                &self.storage_access(),
            )
            .await
            .map_err(Into::into)
    }

    async fn load_proof_for_presentation_definition(
        &self,
        id: &ProofId,
    ) -> Result<Proof, ServiceError> {
        self.proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    verifier_certificate: Some(CertificateRelations::default()),
                    ..Default::default()
                },
                None,
            )
            .await?
            .ok_or(EntityNotFoundError::Proof(*id).into())
    }

    fn storage_access(&self) -> StorageProxyImpl {
        StorageProxyImpl::new(
            self.interaction_repository.clone(),
            self.credential_schema.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
            self.certificate_repository.clone(),
            self.key_repository.clone(),
            self.identifier_repository.clone(),
        )
    }

    /// Returns list of proofs according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_proof_list(
        &self,
        organisation_id: &OrganisationId,
        query: GetProofQueryDTO,
    ) -> Result<GetProofListResponseDTO, ServiceError> {
        throw_if_org_not_matching_session(organisation_id, &*self.session_provider)?;
        let result = self.proof_repository.get_proof_list(query).await?;
        list_response_try_into(result)
    }

    /// Creates a new proof
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn create_proof(
        &self,
        request: CreateProofRequestDTO,
    ) -> Result<ProofId, ServiceError> {
        validate_protocol_type(&request.protocol, &self.config.verification_protocol)?;
        validate_mdl_exchange(
            &request.protocol,
            request.iso_mdl_engagement.as_deref(),
            request.redirect_uri.as_deref(),
            &self.config.verification_protocol,
        )?;
        validate_verifier_engagement(
            request.iso_mdl_engagement.as_deref(),
            request.engagement.as_deref(),
            &self.config.verification_engagement,
        )?;
        validate_redirect_uri(
            &request.protocol,
            request.redirect_uri.as_deref(),
            &self.config.verification_protocol,
        )?;

        let now = OffsetDateTime::now_utc();
        let proof_schema_id = request.proof_schema_id;
        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(
                &proof_schema_id,
                &ProofSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    proof_inputs: Some(ProofInputSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations::default()),
                        credential_schema: Some(CredentialSchemaRelations {
                            claim_schemas: Some(ClaimSchemaRelations::default()),
                            ..Default::default()
                        }),
                    }),
                },
            )
            .await?
            .ok_or(BusinessLogicError::MissingProofSchema { proof_schema_id })?;
        throw_if_org_relation_not_matching_session(
            proof_schema.organisation.as_ref(),
            &*self.session_provider,
        )?;

        // ONE-843: cannot create proof based on deleted schema
        if proof_schema.deleted_at.is_some() {
            return Err(BusinessLogicError::ProofSchemaDeleted { proof_schema_id }.into());
        }

        validate_format_and_exchange_protocol_compatibility(
            &request.protocol,
            &self.config,
            &proof_schema,
            &*self.credential_formatter_provider,
        )?;

        validate_scan_to_verify_compatibility(&request, &self.config)?;

        for credential_schema in proof_schema
            .input_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "input_schemas is None".to_string(),
            ))?
            .iter()
            .flat_map(|input| input.credential_schema.as_ref())
        {
            validate_key_storage_security_supported(
                credential_schema.key_storage_security,
                &self.config,
            )?;
        }

        let exchange_type = self
            .config
            .verification_protocol
            .get_fields(&request.protocol)?
            .r#type;

        if exchange_type == VerificationProtocolType::ScanToVerify {
            return self
                .handle_scan_to_verify(
                    proof_schema,
                    request.protocol,
                    request.profile,
                    request
                        .scan_to_verify
                        .ok_or(ValidationError::InvalidScanToVerifyParameters)?,
                )
                .await;
        } else if exchange_type == VerificationProtocolType::IsoMdl {
            let iso_mdl_engagement = request
                .iso_mdl_engagement
                .ok_or(ValidationError::InvalidMdlParameters)?;
            let engagement_type = VerificationEngagement::from_str(
                request
                    .engagement
                    .as_ref()
                    .ok_or(ValidationError::InvalidMdlParameters)?,
            )
            .map_err(|_| ValidationError::InvalidMdlParameters)?;
            return self
                .handle_iso_mdl_verifier(
                    proof_schema,
                    request.protocol,
                    iso_mdl_engagement,
                    engagement_type,
                    request.profile,
                )
                .await;
        }

        let Some(exchange_protocol) = self.protocol_provider.get_protocol(&request.protocol) else {
            return Err(MissingProviderError::ExchangeProtocol(request.protocol.to_owned()).into());
        };
        let exchange_protocol_capabilities = exchange_protocol.get_capabilities();

        let verifier_identifier = match request.verifier_identifier_id {
            Some(verifier_identifier_id) => self
                .identifier_repository
                .get(
                    verifier_identifier_id,
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
                    verifier_identifier_id,
                )))?,
            None => {
                let verifier_did_id =
                    request
                        .verifier_did_id
                        .ok_or(ServiceError::ValidationError(
                            "No verifier or verifierDid specified".to_string(),
                        ))?;

                self.identifier_repository
                    .get_from_did_id(
                        verifier_did_id,
                        &IdentifierRelations {
                            did: Some(DidRelations {
                                keys: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                    .await?
                    .ok_or(ServiceError::from(EntityNotFoundError::Did(
                        verifier_did_id,
                    )))?
            }
        };

        let selected_entities = entities_for_local_active_identifier(
            &verifier_identifier,
            &KeyFilter::role_filter(KeyRole::Authentication),
            request.verifier_key,
            request.verifier_did_id,
            request.verifier_certificate,
        )?;
        let (verifier_key, verifier_certificate) = match selected_entities {
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
                    &exchange_protocol_capabilities.did_methods,
                    &did.did_method,
                    &self.config.did,
                )?;
                validate_did_and_format_compatibility(
                    &proof_schema,
                    did,
                    &*self.credential_formatter_provider,
                )?;
                (key, None)
            }
        };

        if verifier_key.key_type == "BBS_PLUS" {
            return Err(ValidationError::BBSNotSupported.into());
        }

        validate_verification_key_storage_compatibility(
            &proof_schema,
            verifier_key,
            &*self.credential_formatter_provider,
            &self.config,
        )?;

        validate_identifier(
            verifier_identifier.clone(),
            &exchange_protocol_capabilities.verifier_identifier_types,
            &self.config.identifier,
        )?;

        let transport = validate_and_select_transport_type(
            &request.transport,
            &self.config.transport,
            &exchange_protocol_capabilities,
        )?;

        let mut maybe_interaction = None;
        let transport = match transport {
            SelectedTransportType::Single(single) => single,
            // for multiple transports we store them in interaction data and set the transport=""
            SelectedTransportType::Multiple(multiple) => {
                let data = CreateProofInteractionData {
                    transport: multiple,
                };

                maybe_interaction = Some(
                    add_new_interaction(
                        Uuid::new_v4(),
                        &*self.interaction_repository,
                        serde_json::to_vec(&data).ok(),
                        proof_schema.organisation.clone(),
                        InteractionType::Verification,
                    )
                    .await?,
                );

                String::new()
            }
        };

        let success_log_detail = format!(
            "using proof schema `{}` ({}): protocol `{}`, transport `{}`",
            proof_schema.name, proof_schema.id, request.protocol, transport
        );
        let verifier_key = verifier_key.to_owned();
        let proof_id = self
            .proof_repository
            .create_proof(proof_from_create_request(
                request,
                now,
                proof_schema,
                transport,
                verifier_identifier,
                verifier_key,
                verifier_certificate,
                maybe_interaction,
            ))
            .await?;

        tracing::info!("Created proof request {proof_id} {success_log_detail}");
        Ok(proof_id)
    }

    /// Request proof
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    pub async fn share_proof(
        &self,
        id: &ProofId,
        request: ShareProofRequestDTO,
    ) -> Result<EntityShareResponseDTO, ServiceError> {
        let proof = self.load_proof(id).await?;
        throw_if_proof_not_in_session_org(&proof, &*self.session_provider)?;

        let previous_state = proof.state;
        if !matches!(
            previous_state,
            ProofStateEnum::Created | ProofStateEnum::Pending | ProofStateEnum::InteractionExpired
        ) {
            return Err(BusinessLogicError::InvalidProofState {
                state: previous_state,
            }
            .into());
        }

        if proof
            .engagement
            .as_ref()
            .is_some_and(|engagement| engagement != DEFAULT_ENGAGEMENT)
        {
            return Err(ValidationError::InvalidProofEngagement.into());
        }

        let organisation = proof
            .schema
            .as_ref()
            .and_then(|schema| schema.organisation.as_ref())
            .ok_or_else(|| VerificationProtocolError::Failed("Missing organisation".to_string()))?;

        let exchange = self.protocol_provider.get_protocol(&proof.protocol).ok_or(
            MissingProviderError::ExchangeProtocol(proof.protocol.to_owned()),
        )?;

        let config = self.config.clone();
        let format_type_mapper: FormatMapper = Arc::new(move |input: &CredentialFormat| {
            Ok(config
                .format
                .get_fields(input)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
                .r#type
                .to_owned())
        });

        let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(create_format_map);

        let on_submission_callback = Some(self.get_on_submission_ble_mqtt_callback(*id));

        let ShareResponse {
            url,
            interaction_id,
            interaction_data,
            expires_at,
        } = exchange
            .verifier_share_proof(
                &proof,
                format_type_mapper,
                type_to_descriptor_mapper,
                on_submission_callback,
                request.params,
            )
            .await?;

        add_new_interaction(
            interaction_id,
            &*self.interaction_repository,
            interaction_data,
            Some(organisation.to_owned()),
            InteractionType::Verification,
        )
        .await?;

        self.proof_repository
            .update_proof(
                &proof.id,
                UpdateProofRequest {
                    state: (previous_state != ProofStateEnum::Pending)
                        .then_some(ProofStateEnum::Pending),
                    interaction: Some(Some(interaction_id)),
                    engagement: Some(Some(DEFAULT_ENGAGEMENT.to_string())),
                    ..Default::default()
                },
                None,
            )
            .await?;
        clear_previous_interaction(&*self.interaction_repository, &proof.interaction).await?;
        tracing::info!("Shared proof request {}", proof.id);
        Ok(EntityShareResponseDTO { url, expires_at })
    }

    pub async fn delete_proof_claims(&self, proof_id: ProofId) -> Result<(), ServiceError> {
        let proof = self
            .proof_repository
            .get_proof(
                &proof_id,
                &ProofRelations {
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations::default(),
                        credential: Some(CredentialRelations::default()),
                    }),
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: None,
                    }),
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    ..Default::default()
                },
                None,
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(
                proof_id,
            )))?;
        throw_if_proof_not_in_session_org(&proof, &*self.session_provider)?;

        let credential_ids = proof
            .claims
            .ok_or(ServiceError::MappingError("claims are None".to_string()))?
            .into_iter()
            .map(|proof_claim| {
                Ok::<CredentialId, ServiceError>(
                    proof_claim
                        .credential
                        .ok_or(ServiceError::MappingError("credential is None".to_string()))?
                        .id,
                )
            })
            .collect::<Result<HashSet<_>, _>>()?;

        self.proof_repository.delete_proof_claims(&proof.id).await?;

        self.claim_repository
            .delete_claims_for_credentials(credential_ids.clone())
            .await?;

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))?;

        let credential_blob_ids = self
            .credential_repository
            .get_credential_list(GetCredentialQuery {
                filtering: Some(
                    CredentialFilterValue::CredentialIds(Vec::from_iter(credential_ids.clone()))
                        .condition(),
                ),
                ..GetCredentialQuery::default()
            })
            .await?
            .values
            .into_iter()
            .filter_map(|c| c.credential_blob_id)
            .collect::<Vec<_>>();

        blob_storage.delete_many(&credential_blob_ids).await?;

        self.credential_repository
            .delete_credential_blobs(credential_ids)
            .await?;

        if let Some(proof_blob_id) = proof.proof_blob_id {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)
                .await
                .ok_or_else(|| {
                    MissingProviderError::BlobStorage(BlobStorageType::Db.to_string())
                })?;

            blob_storage.delete(&proof_blob_id).await?;
        }
        tracing::info!("Deleted proof claims for proof {}", proof.id);
        Ok(())
    }

    pub async fn propose_proof(
        &self,
        request: ProposeProofRequestDTO,
    ) -> Result<ProposeProofResponseDTO, ServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)?;
        validate_protocol_type(&request.protocol, &self.config.verification_protocol)?;
        let engagement =
            validate_holder_engagements(&request.engagement, &self.config.verification_engagement)?;
        let exchange_type = self
            .config
            .verification_protocol
            .get_fields(&request.protocol)?
            .r#type;
        if exchange_type != VerificationProtocolType::IsoMdl {
            return Err(ValidationError::InvalidExchangeType {
                value: request.protocol,
                source: anyhow::anyhow!("propose_proof"),
            }
            .into());
        }

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let transport = self
            .config
            .transport
            .get_enabled_transport_type(TransportType::Ble)
            .map_err(|_| ServiceError::Other("BLE transport not available".into()))?;

        let ble = self
            .ble
            .as_ref()
            .ok_or_else(|| ServiceError::Other("BLE is missing in service".into()))?;

        let now = OffsetDateTime::now_utc();
        let ble_server = start_mdl_server(ble).await?;
        let key_pair = KeyAgreement::<EDeviceKey>::new();
        let device_engagement = DeviceEngagement {
            security: Security {
                key_bytes: EmbeddedCbor::new(EDeviceKey::new(key_pair.device_key().0))
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
            },
            device_retrieval_methods: vec![DeviceRetrievalMethod {
                retrieval_options: RetrievalOptions::Ble(BleOptions {
                    peripheral_server_uuid: ble_server.service_uuid,
                    peripheral_server_mac_address: ble_server.mac_address.clone(),
                }),
            }],
        };

        let (qr_code, qr_engagement) = if engagement.contains(&VerificationEngagement::QrCode) {
            let device_engagement_bytes = device_engagement
                .clone()
                .into_cbor()
                .map_err(|err| ServiceError::Other(err.to_string()))?;

            (
                Some(
                    device_engagement_bytes
                        .generate_qr_code()
                        .map_err(|err| ServiceError::Other(err.to_string()))?,
                ),
                Some(device_engagement_bytes),
            )
        } else {
            (None, None)
        };

        let nfc_engagement = if engagement.contains(&VerificationEngagement::NFC) {
            let nfc_hce_provider = self
                .nfc_hce_provider
                .clone()
                .ok_or(ServiceError::Other("NFC HCE provider is missing".into()))?;

            // NFC device engagement does not contain device retrieval methods
            let device_engagement_bytes = {
                let mut device_engagement = device_engagement;
                device_engagement.device_retrieval_methods = vec![];
                device_engagement
                    .into_cbor()
                    .map_err(|err| ServiceError::Other(err.to_string()))?
            };

            let select_message =
                create_nfc_handover_select_message(&ble_server, device_engagement_bytes.clone())
                    .map_err(|err| {
                        ServiceError::Other(format!("Failed to create NFC payload: {err}"))
                    })?
                    .to_buffer()
                    .map_err(|err| {
                        ServiceError::Other(format!("Failed to generate NFC payload: {err}"))
                    })?;

            let handler = Arc::new(NfcStaticHandoverHandler::new(
                nfc_hce_provider.clone(),
                &select_message,
            )?);
            nfc_hce_provider
                .start_hosting(handler.to_owned(), request.ui_message)
                .await?;
            Some(NfcHceSession {
                handler,
                hce: nfc_hce_provider,
                select_message,
                device_engagement: device_engagement_bytes,
            })
        } else {
            None
        };

        let interaction_id = Uuid::new_v4();
        let interaction_data = serde_json::to_vec(&MdocBleHolderInteractionData {
            organisation_id: request.organisation_id,
            service_uuid: ble_server.service_uuid,
            continuation_task_id: ble_server.task_id,
            session: None,
            engagement,
        })
        .context("interaction serialization error")
        .map_err(VerificationProtocolError::Other)?;

        let interaction = add_new_interaction(
            interaction_id,
            &*self.interaction_repository,
            Some(interaction_data),
            organisation,
            InteractionType::Verification,
        )
        .await?;

        let proof_id = self
            .proof_repository
            .create_proof(Proof {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                protocol: request.protocol,
                redirect_uri: None,
                state: ProofStateEnum::Pending,
                role: ProofRole::Holder,
                requested_date: Some(now),
                completed_date: None,
                profile: None,
                schema: None,
                transport: transport.to_owned(),
                claims: None,
                verifier_identifier: None,
                verifier_key: None,
                verifier_certificate: None,
                interaction: Some(interaction.clone()),
                proof_blob_id: None,
                engagement: None,
            })
            .await?;

        receive_mdl_request(
            ble,
            key_pair,
            self.interaction_repository.clone(),
            interaction,
            self.proof_repository.clone(),
            proof_id,
            qr_engagement,
            nfc_engagement,
        )
        .await?;

        Ok(ProposeProofResponseDTO {
            proof_id,
            interaction_id,
            url: qr_code,
        })
    }

    pub async fn delete_proof(&self, proof_id: ProofId) -> Result<(), ServiceError> {
        let Some(proof) = self
            .proof_repository
            .get_proof(
                &proof_id,
                &ProofRelations {
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: None,
                    }),
                    ..Default::default()
                },
                None,
            )
            .await?
        else {
            return Err(EntityNotFoundError::Proof(proof_id).into());
        };
        throw_if_proof_not_in_session_org(&proof, &*self.session_provider)?;

        match proof.state {
            ProofStateEnum::Created | ProofStateEnum::Pending => {
                self.exchange_retract_proof(&proof).await?;
                self.hard_delete_proof(&proof).await?
            }
            ProofStateEnum::Requested => {
                self.exchange_retract_proof(&proof).await?;
                let proof_update = UpdateProofRequest {
                    state: Some(ProofStateEnum::Retracted),
                    proof_blob_id: None,
                    ..Default::default()
                };
                self.proof_repository
                    .update_proof(&proof.id, proof_update, None)
                    .await?;
            }
            state => return Err(BusinessLogicError::InvalidProofState { state }.into()),
        };
        if let Some(proof_blob_id) = proof.proof_blob_id {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)
                .await
                .ok_or_else(|| {
                    MissingProviderError::BlobStorage(BlobStorageType::Db.to_string())
                })?;

            blob_storage.delete(&proof_blob_id).await?;
        }
        tracing::info!("Deleted proof {}", proof.id);
        Ok(())
    }

    // ============ Private methods

    async fn hard_delete_proof(&self, proof: &Proof) -> Result<(), ServiceError> {
        self.proof_repository.delete_proof(&proof.id).await?;
        if let Some(ref interaction) = proof.interaction {
            self.interaction_repository
                .delete_interaction(&interaction.id)
                .await?;
        };
        Ok(())
    }

    /// Release resources consumed by the exchange protocol for this particular proof
    /// (e.g. BLE advertising).
    async fn exchange_retract_proof(&self, proof: &Proof) -> Result<(), ServiceError> {
        // If the configuration is changed such that the exchange protocol of the proof no longer
        // exists we can simply skip the retracting.
        if let Some(exchange_protocol) = self.protocol_provider.get_protocol(&proof.protocol) {
            exchange_protocol.retract_proof(proof).await?;
        };
        Ok(())
    }

    /// Get proof with relations
    async fn load_proof(&self, id: &ProofId) -> Result<Proof, ServiceError> {
        let proof = self
            .proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    interaction: Some(InteractionRelations::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(ClaimSchemaRelations::default()),
                        },
                        ..Default::default()
                    }),
                    verifier_key: Some(KeyRelations::default()),
                    verifier_identifier: Some(IdentifierRelations {
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
                    verifier_certificate: Some(CertificateRelations {
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                },
                None,
            )
            .await?
            .ok_or(EntityNotFoundError::Proof(*id))?;

        Ok(proof)
    }
}
