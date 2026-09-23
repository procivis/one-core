use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use shared_types::{CredentialFormat, ProofId, TransactionDataId};
use standardized_types::openid4vp::dcql::CredentialQueryId;
use uuid::Uuid;

use super::ProofService;
use super::dto::{
    CreateProofInteractionData, CreateProofRequestDTO, GetProofListResponseDTO,
    ProofDetailResponseDTO, ProofFilterParamsDTO, ProofTransactionDataResponseDTO,
    ProposeProofRequestDTO, ProposeProofResponseDTO, ShareProofRequestDTO, ShareProofResponseDTO,
};
use super::error::ProofServiceError;
use super::mapper::{
    get_holder_proof_detail, get_proof_trust_information, get_verifier_proof_detail,
    interaction_data_from_proof, list_item_from_proof, proof_from_create_request,
};
use super::validator::{
    throw_if_proof_not_in_session_org, validate_did_and_format_compatibility,
    validate_format_and_exchange_protocol_compatibility, validate_holder_engagements,
    validate_mdl_exchange, validate_proof_for_proof_definition, validate_redirect_uri,
    validate_transaction_data, validate_verification_key_storage_compatibility,
    validate_verifier_engagement, validate_webhook_url,
};
use crate::config::core_config::{
    BlobStorageType, TransportType, VerificationEngagement, VerificationProtocolType,
};
use crate::config::validator::protocol::{
    validate_identifier, validate_protocol_did_compatibility, validate_protocol_type,
};
use crate::config::validator::transport::{
    SelectedTransportType, validate_and_select_transport_type,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::certificate::CertificateRole;
use crate::model::credential::{CredentialFilterValue, CredentialListQuery};
use crate::model::did::KeyRole;
use crate::model::history::{HistoryAction, HistoryFilterValue, HistoryListQuery};
use crate::model::identifier::IdentifierType;
use crate::model::interaction::InteractionType;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::proof::{
    Proof, ProofRole, ProofStateEnum, SortableProofColumn, UpdateProofRequest,
};
use crate::proto::key_verification::KeyVerification;
use crate::proto::nfc::static_handover_handler::NfcStaticHandoverHandler;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::transaction_data::Features::SupportsMultipleTxDataPerPresentation;
use crate::provider::transaction_data::{
    assign_entries_to_distinct_credentials, decode_transaction_data,
};
use crate::provider::verification_protocol::dto::{
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
};
use crate::provider::verification_protocol::iso_mdl::ble_holder::{
    MdocBleHolderInteractionData, NfcHceSession, receive_mdl_request, start_mdl_server,
};
use crate::provider::verification_protocol::iso_mdl::ble_verifier::IsoMdlVerifier;
use crate::provider::verification_protocol::iso_mdl::common::{EDeviceKey, KeyAgreement};
use crate::provider::verification_protocol::iso_mdl::device_engagement::{
    BleOptions, DeviceEngagement, DeviceRetrievalMethod, RetrievalOptions, Security,
};
use crate::provider::verification_protocol::iso_mdl::nfc::create_nfc_handover_select_message;
use crate::provider::verification_protocol::openid4vp::model::{
    CommonVerifierInteractionContent, OpenID4VPHolderInteractionData, TransactionDataRequest,
};
use crate::provider::verification_protocol::{FormatMapper, deserialize_interaction_data};
use crate::repository::error::DataLayerError;
use crate::service::common_dto::{ListQueryDTO, TrustInformationDetailResponseDTO};
use crate::service::common_mapper::recorded_ecosystem_outcomes;
use crate::service::credential_schema::validator::validate_key_storage_security_supported;
use crate::util::interactions::{add_new_interaction, clear_previous_interaction};
use crate::util::key_selection::{CertificateFilter, KeyFilter, KeySelection, SelectedKey};
use crate::validator::ecosystem::{
    SelectionRole, validate_ecosystem_selection_allow_not_set, validate_ecosystem_selection_final,
};
use crate::validator::proof_schema::resolve_proof_input_schema_formats;
use crate::validator::throw_if_org_id_not_matching_session;

const DEFAULT_ENGAGEMENT: &str = "QR_CODE";

impl ProofService {
    /// Returns details of a proof
    ///
    /// # Arguments
    ///
    /// * `id` - Proof uuid
    pub async fn get_proof(
        &self,
        id: &ProofId,
    ) -> Result<ProofDetailResponseDTO, ProofServiceError> {
        let proof = self
            .proof_repository
            .get_proof(id, None)
            .await
            .error_while("getting proof")?;

        throw_if_proof_not_in_session_org(&proof, &*self.session_provider).await?;

        let history_event = self
            .history_repository
            .get_history_list(HistoryListQuery {
                include_count: false,
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
            .await
            .error_while("getting history list")?
            .values
            .into_iter()
            .next();

        if proof.schema.is_some() {
            get_verifier_proof_detail(
                proof,
                &self.config,
                history_event,
                &*self.credential_repository,
                &*self.credential_formatter_provider,
                self.ecosystem_provider.as_ref(),
                &*self.history_repository,
            )
            .await
        } else {
            let trust_information = get_proof_trust_information(
                &proof,
                self.ecosystem_provider.as_ref(),
                &*self.history_repository,
            )
            .await?;

            get_holder_proof_detail(
                proof,
                &self.config,
                history_event,
                trust_information,
                &*self.credential_repository,
                &*self.credential_formatter_provider,
            )
            .await
        }
    }

    pub async fn get_proof_presentation_definition_v2(
        &self,
        id: &ProofId,
    ) -> Result<PresentationDefinitionV2ResponseDTO, ProofServiceError> {
        let proof = self.load_proof_for_presentation_definition(id).await?;
        let exchange = self.protocol_provider.get_protocol(&proof.protocol)?;
        validate_proof_for_proof_definition(
            &proof,
            &*self.session_provider,
            &*exchange,
            &PresentationDefinitionVersion::V2,
        )
        .await?;
        Ok(exchange
            .holder_get_presentation_definition_v2(
                &proof,
                interaction_data_from_proof(&proof).await?,
                &[],
            )
            .await
            .error_while("getting presentation definition V2")?)
    }

    async fn load_proof_for_presentation_definition(
        &self,
        id: &ProofId,
    ) -> Result<Proof, ProofServiceError> {
        self.proof_repository
            .get_proof(id, None)
            .await
            .error_while("getting proof")
            .map_err(Into::into)
    }

    /// Returns the details of a single (holder-side) transaction data entry of a proof request.
    pub async fn holder_transaction_data_details(
        &self,
        proof_id: &ProofId,
        transaction_data_id: &TransactionDataId,
    ) -> Result<ProofTransactionDataResponseDTO, ProofServiceError> {
        let proof = self
            .load_proof_for_presentation_definition(proof_id)
            .await?;
        throw_if_proof_not_in_session_org(&proof, &*self.session_provider).await?;
        if proof.role != ProofRole::Holder {
            return Err(ProofServiceError::InvalidRole(proof.role));
        }

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ProofServiceError::MappingError(
                "missing interaction".to_string(),
            ))?
            .as_ref()
            .await?;
        let interaction_data: OpenID4VPHolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("reading interaction data")?;

        let validated = interaction_data
            .transaction_data
            .validated()
            .error_while("validating transaction data")?;
        let entry = validated.get(transaction_data_id).ok_or(
            ProofServiceError::TransactionDataNotFound(*transaction_data_id),
        )?;

        let provider = self
            .transaction_data_provider
            .get_transaction_data_by_name(&entry.transaction_data_type)?;

        let transaction_data_display = provider
            .get_display_data(&entry.raw)
            .error_while("assembling transaction data display")?;
        let raw_transaction_data =
            decode_transaction_data(&entry.raw).error_while("decoding raw transaction data")?;

        Ok(ProofTransactionDataResponseDTO {
            id: *transaction_data_id,
            r#type: entry.transaction_data_type.clone(),
            credential_query_ids: entry.credential_query_ids.clone(),
            transaction_data_display,
            raw_transaction_data: Some(raw_transaction_data),
        })
    }

    /// Returns list of proofs according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_proof_list(
        &self,
        filter_params: ListQueryDTO<SortableProofColumn, ProofFilterParamsDTO>,
    ) -> Result<GetProofListResponseDTO, ProofServiceError> {
        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let result = self
            .proof_repository
            .get_proof_list(filter_params.into())
            .await
            .and_then(|list| list.require_count())
            .error_while("getting proofs")?;

        let mut response_dtos = Vec::with_capacity(result.values.len());
        for value in result.values {
            response_dtos.push(list_item_from_proof(value).await?);
        }
        Ok(GetProofListResponseDTO {
            values: response_dtos,
            total_pages: result.total_pages,
            total_items: result.total_items,
        })
    }

    /// Creates a new proof
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn create_proof(
        &self,
        request: CreateProofRequestDTO,
    ) -> Result<ProofId, ProofServiceError> {
        validate_protocol_type(&request.protocol, &self.config.verification_protocol)
            .error_while("validating protocol")?;
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
        validate_webhook_url(
            request.webhook_destination_url.as_ref(),
            &request.protocol,
            &self.config,
            self.notification_scheduler.as_ref(),
        )?;

        let now = crate::clock::now_utc();
        let proof_schema_id = request.proof_schema_id;
        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(&proof_schema_id)
            .await
            .map_err(|error| match error {
                DataLayerError::EntityNotFound { .. } => {
                    ProofServiceError::MissingProofSchema(proof_schema_id)
                }
                error => error.error_while("getting proof schema").into(),
            })?;
        throw_if_org_id_not_matching_session(
            proof_schema.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        // ONE-843: cannot create proof based on deleted schema
        if proof_schema.deleted_at.is_some() {
            return Err(ProofServiceError::ProofSchemaDeleted(proof_schema_id));
        }

        validate_format_and_exchange_protocol_compatibility(
            &request.protocol,
            &self.config,
            &proof_schema,
            &*self.credential_formatter_provider,
        )
        .await?;

        let organisation = proof_schema.organisation.as_ref().await?;
        validate_ecosystem_selection_final(
            request.ecosystem.as_ref(),
            &organisation,
            self.ecosystem_provider.as_ref(),
            SelectionRole::Verifier,
        )
        .error_while("validating ecosystem")?;
        drop(organisation);

        for credential_schema in proof_schema
            .input_schemas
            .as_ref()
            .await?
            .iter()
            .map(|input| &input.credential_schema)
        {
            validate_key_storage_security_supported(
                credential_schema
                    .as_ref()
                    .await?
                    .wallet_attestation
                    .key_storage_security_level,
                &self.config,
            )
            .error_while("validating key storage security")?;
        }

        let exchange_type = self
            .config
            .verification_protocol
            .get_fields(&request.protocol)
            .error_while("getting protocol")?
            .r#type;

        let exchange_protocol = self.protocol_provider.get_protocol(&request.protocol)?;

        let exchange_protocol_capabilities = exchange_protocol.get_capabilities();

        let verifier_identifier = match request.verifier_identifier_id {
            Some(verifier_identifier_id) => self
                .identifier_repository
                .get(verifier_identifier_id)
                .await
                .error_while("getting identifier")?,
            None => {
                let verifier_did_id = request
                    .verifier_did_id
                    .ok_or(ProofServiceError::NoVerifier)?;

                self.identifier_repository
                    .get_from_did_id(verifier_did_id)
                    .await
                    .error_while("getting identifier")?
                    .ok_or(ProofServiceError::MissingDid(verifier_did_id))?
            }
        };

        let selection = verifier_identifier
            .select_key(KeySelection {
                did: request.verifier_did_id,
                certificate: CertificateFilter::id(request.verifier_certificate),
                key: KeyFilter::did_role(KeyRole::Authentication).and_id(request.verifier_key),
            })
            .await
            .error_while("selecting key")?;
        let (verifier_key, verifier_certificate) = match selection {
            SelectedKey::Key(_) => {
                return Err(ProofServiceError::InvalidIdentifierType(
                    IdentifierType::Key,
                ));
            }
            SelectedKey::Certificate { certificate, key } => (*key, Some(*certificate)),
            SelectedKey::Did { did, key } => {
                validate_protocol_did_compatibility(
                    &exchange_protocol_capabilities.did_methods,
                    &did.did_method,
                    &self.config.did,
                )
                .error_while("validating DID compatibility")?;
                validate_did_and_format_compatibility(
                    &proof_schema,
                    &did,
                    &*self.credential_formatter_provider,
                )
                .await?;
                (key.key, None)
            }
        };

        if exchange_type == VerificationProtocolType::IsoMdl {
            let iso_mdl_engagement = request
                .iso_mdl_engagement
                .ok_or(ProofServiceError::InvalidMdlParameters)?;
            let engagement_type = VerificationEngagement::from_str(
                request
                    .engagement
                    .as_ref()
                    .ok_or(ProofServiceError::InvalidMdlParameters)?,
            )
            .map_err(|_| ProofServiceError::InvalidMdlParameters)?;

            let auth_fn = self.key_provider.get_signature_provider(
                &verifier_key,
                None,
                self.key_algorithm_provider.clone(),
            )?;

            let verifier = verifier_certificate.map(|certificate| IsoMdlVerifier {
                certificate,
                identifier: verifier_identifier,
                key: verifier_key,
                auth_fn,
            });

            return self
                .handle_iso_mdl_verifier(
                    proof_schema,
                    request.protocol,
                    iso_mdl_engagement,
                    engagement_type,
                    request.profile,
                    verifier,
                    request.ecosystem,
                )
                .await;
        }

        if let Some(cert) = &verifier_certificate
            && !cert.roles.contains(&CertificateRole::Authentication)
        {
            return Err(ProofServiceError::NoKeyWithRole(KeyRole::Authentication));
        }

        if verifier_key.key_type == "BBS_PLUS" {
            return Err(ProofServiceError::BBSNotSupported);
        }

        validate_verification_key_storage_compatibility(
            &proof_schema,
            &verifier_key,
            &*self.credential_formatter_provider,
            &self.config,
        )
        .await?;

        validate_identifier(
            verifier_identifier.clone(),
            &exchange_protocol_capabilities.verifier_identifier_types,
            &self.config.identifier,
        )
        .error_while("validating identifier")?;

        let transport = validate_and_select_transport_type(
            &request.transport,
            &self.config.transport,
            &exchange_protocol_capabilities,
        )
        .error_while("validating transport")?;

        validate_transaction_data(
            &request.transaction_data,
            &proof_schema,
            &*self.credential_formatter_provider,
        )
        .await?;

        let mut maybe_interaction = None;
        let (transport, interaction_transports, multiple_transports) = match transport {
            SelectedTransportType::Single(single) => (single.clone(), vec![single], false),
            // for multiple transports we store them in interaction data and set the transport=""
            SelectedTransportType::Multiple(multiple) => (String::new(), multiple, true),
        };

        if multiple_transports || !request.transaction_data.is_empty() {
            let mut transaction_data: Vec<TransactionDataRequest> =
                Vec::with_capacity(request.transaction_data.len());
            let mut potentially_conflicting_tx_data: HashMap<_, Vec<Vec<CredentialQueryId>>> =
                HashMap::new();

            let inputs = proof_schema.input_schemas.as_ref().await?;
            let mut formats_by_schema = HashMap::new();
            for input in &inputs {
                let formats = resolve_proof_input_schema_formats(input)
                    .await
                    .error_while("resolving proof input formats")?;
                formats_by_schema.insert(input.credential_schema.id(), formats);
            }

            for tx_data in &request.transaction_data {
                let provider = self
                    .transaction_data_provider
                    .get_transaction_data_by_name(&tx_data.r#type)?;
                let capabilities = provider.get_capabilities();
                let mut credential_ids = Vec::new();
                for schema_id in &tx_data.credential_schema_ids {
                    let formats = formats_by_schema.get(schema_id).ok_or(
                        ProofServiceError::TransactionDataUnknownCredentialSchema(*schema_id),
                    )?;
                    for format in formats {
                        let format_type = self
                            .config
                            .format
                            .get_fields(&format.format)
                            .error_while("getting credential format config")?
                            .r#type;
                        if !capabilities.formats.contains(&format_type) {
                            return Err(ProofServiceError::TransactionDataFormatUnsupported(
                                *schema_id,
                            ));
                        }
                        credential_ids.push(CredentialQueryId::from(format.id.to_string()));
                    }
                }
                let encoded = provider
                    .prepare_transaction_data(credential_ids.clone(), tx_data.data.clone())
                    .error_while("preparing transaction data")?;

                if transaction_data.iter().any(|data| data.encoded == encoded) {
                    return Err(ProofServiceError::DuplicitTransactionData);
                }

                transaction_data.push(TransactionDataRequest {
                    r#type: tx_data.r#type.clone(),
                    credential_ids,
                    data: tx_data.data.clone(),
                    encoded,
                });

                if !capabilities
                    .features
                    .contains(&SupportsMultipleTxDataPerPresentation)
                {
                    potentially_conflicting_tx_data
                        .entry(&tx_data.r#type)
                        .or_default()
                        // Format alternatives represent one proof input, not
                        // additional credentials available to authorize entries.
                        .push(
                            tx_data
                                .credential_schema_ids
                                .iter()
                                .map(|id| CredentialQueryId::from(id.to_string()))
                                .collect(),
                        );
                }
            }

            // Reject requests whose entries cannot each be authorized by a
            // distinct credential (see `assign_entries_to_distinct_credentials`).
            // Only entries of the same type compete; different types can share
            // a credential as their evidence lives under different keys.
            if potentially_conflicting_tx_data
                .values()
                .any(|entries| assign_entries_to_distinct_credentials(entries).is_none())
            {
                return Err(ProofServiceError::UnsatisfiableTransactionData);
            }

            let data = CreateProofInteractionData {
                transport: interaction_transports,
                common: CommonVerifierInteractionContent { transaction_data },
            };

            maybe_interaction = Some(
                add_new_interaction(
                    Uuid::new_v4().into(),
                    &*self.interaction_repository,
                    serde_json::to_vec(&data).ok(),
                    proof_schema.organisation.to_owned(),
                    InteractionType::Verification,
                    None,
                    request.ecosystem.clone(),
                )
                .await
                .error_while("adding interaction")?,
            );
        }

        let success_log_detail = format!(
            "using proof schema `{}` ({}): protocol `{}`, transport `{}`",
            proof_schema.name, proof_schema.id, request.protocol, transport
        );

        let ecosystem = request.ecosystem.clone();
        let proof = proof_from_create_request(
            request,
            now,
            proof_schema,
            transport,
            verifier_identifier,
            verifier_key,
            verifier_certificate,
            maybe_interaction,
        );

        if let Some(ecosystem) = &ecosystem {
            let ecosystem = self.ecosystem_provider.get(ecosystem)?;
            ecosystem
                .validate_proof(&proof)
                .await
                .error_while("validating ecosystem")?;
        }

        let proof_id = self
            .proof_repository
            .create_proof(proof)
            .await
            .error_while("creating proof")?;

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
    ) -> Result<ShareProofResponseDTO, ProofServiceError> {
        let proof = self
            .proof_repository
            .get_proof(id, None)
            .await
            .error_while("getting proof")?;
        throw_if_proof_not_in_session_org(&proof, &*self.session_provider).await?;

        let previous_state = proof.state;
        if !matches!(
            previous_state,
            ProofStateEnum::Created | ProofStateEnum::Pending | ProofStateEnum::InteractionExpired
        ) {
            return Err(ProofServiceError::InvalidState(previous_state));
        }

        if proof
            .engagement
            .as_ref()
            .is_some_and(|engagement| engagement != DEFAULT_ENGAGEMENT)
        {
            return Err(ProofServiceError::InvalidEngagement);
        }

        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or_else(|| ProofServiceError::MappingError("Missing proof_schema".to_string()))?
            .as_ref()
            .await?;

        let organisation = proof_schema.organisation.to_owned();

        let exchange = self.protocol_provider.get_protocol(&proof.protocol)?;

        let config = self.config.clone();
        let format_type_mapper: FormatMapper = Arc::new(move |input: &CredentialFormat| {
            Ok(config
                .format
                .get_fields(input)
                .error_while("getting protocol")?
                .r#type
                .to_owned())
        });

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
                on_submission_callback,
                request.params,
            )
            .await
            .error_while("sharing proof")?;

        add_new_interaction(
            interaction_id,
            &*self.interaction_repository,
            interaction_data,
            organisation,
            InteractionType::Verification,
            expires_at,
            proof.ecosystem,
        )
        .await
        .error_while("adding interaction")?;

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
            .await
            .error_while("updating proof")?;
        clear_previous_interaction(
            &*self.interaction_repository,
            proof.interaction.as_ref().map(|i| i.id_ref()),
        )
        .await
        .error_while("clearing interaction")?;
        tracing::info!("Shared proof request {}", proof.id);
        Ok(ShareProofResponseDTO { url, expires_at })
    }

    pub async fn delete_proof_claims(&self, proof_id: ProofId) -> Result<(), ProofServiceError> {
        let proof = self
            .proof_repository
            .get_proof(&proof_id, None)
            .await
            .error_while("getting proof")?;
        throw_if_proof_not_in_session_org(&proof, &*self.session_provider).await?;

        let credential_ids = proof
            .claims
            .as_ref()
            .await?
            .into_iter()
            .map(|proof_claim| proof_claim.credential.id())
            .collect::<HashSet<_>>();

        self.proof_repository
            .delete_proof_claims(&proof.id)
            .await
            .error_while("deleting proof claims")?;

        self.claim_repository
            .delete_claims_for_credentials(credential_ids.clone())
            .await
            .error_while("deleting credential claims")?;

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let credential_blob_ids = self
            .credential_repository
            .get_credential_list(CredentialListQuery {
                include_count: false,
                filtering: Some(
                    CredentialFilterValue::CredentialIds(Vec::from_iter(credential_ids.clone()))
                        .condition()
                        & CredentialFilterValue::Deleted(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting credentials")?
            .values
            .into_iter()
            .filter_map(|c| c.credential_blob_id)
            .collect::<Vec<_>>();

        blob_storage
            .delete_many(&credential_blob_ids)
            .await
            .error_while("deleting credential blobs")?;

        self.credential_repository
            .delete_credential_blobs(credential_ids)
            .await
            .error_while("deleting credential blobs")?;

        if let Some(proof_blob_id) = proof.proof_blob_id {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)?;

            blob_storage
                .delete(&proof_blob_id)
                .await
                .error_while("deleting proof blobs")?;
        }
        tracing::info!("Deleted proof claims for proof {}", proof.id);
        Ok(())
    }

    pub async fn propose_proof(
        &self,
        request: ProposeProofRequestDTO,
    ) -> Result<ProposeProofResponseDTO, ProofServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        validate_protocol_type(&request.protocol, &self.config.verification_protocol)
            .error_while("validating protocol")?;
        let engagement =
            validate_holder_engagements(&request.engagement, &self.config.verification_engagement)?;
        let exchange_type = self
            .config
            .verification_protocol
            .get_fields(&request.protocol)
            .error_while("getting protocol")?
            .r#type;
        if exchange_type != VerificationProtocolType::IsoMdl {
            return Err(ProofServiceError::InvalidExchangeType {
                value: request.protocol,
                source: anyhow::anyhow!("propose_proof"),
            });
        }

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?;

        validate_ecosystem_selection_allow_not_set(
            request.ecosystem.as_ref(),
            &organisation,
            self.ecosystem_provider.as_ref(),
        )
        .error_while("validating ecosystem")?;

        let transport = self
            .config
            .transport
            .get_enabled_transport_type(TransportType::Ble)
            .error_while("checking transport config")?;

        let ble = self
            .ble
            .as_ref()
            .ok_or_else(|| ProofServiceError::Other("BLE is missing in service".into()))?;

        let now = crate::clock::now_utc();
        let ble_server = start_mdl_server(ble)
            .await
            .error_while("starting mDL server")?;
        let key_pair = KeyAgreement::<EDeviceKey>::new();
        let device_engagement = DeviceEngagement {
            version: Default::default(),
            security: Security {
                key_bytes: EmbeddedCbor::new(EDeviceKey::new(key_pair.device_key().0))
                    .map_err(|e| ProofServiceError::MappingError(e.to_string()))?,
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
                .map_err(|err| ProofServiceError::Other(err.to_string()))?;

            (
                Some(
                    device_engagement_bytes
                        .generate_qr_code()
                        .map_err(|err| ProofServiceError::Other(err.to_string()))?,
                ),
                Some(device_engagement_bytes),
            )
        } else {
            (None, None)
        };

        let nfc_engagement = if engagement.contains(&VerificationEngagement::NFC) {
            let nfc_hce_provider =
                self.nfc_hce_provider
                    .clone()
                    .ok_or(ProofServiceError::Other(
                        "NFC HCE provider is missing".into(),
                    ))?;

            // NFC device engagement does not contain device retrieval methods
            let device_engagement_bytes = {
                let mut device_engagement = device_engagement;
                device_engagement.device_retrieval_methods = vec![];
                device_engagement
                    .into_cbor()
                    .map_err(|err| ProofServiceError::Other(err.to_string()))?
            };

            let select_message =
                create_nfc_handover_select_message(&ble_server, device_engagement_bytes.clone())
                    .map_err(|err| {
                        ProofServiceError::Other(format!("Failed to create NFC payload: {err}"))
                    })?
                    .to_buffer()
                    .map_err(|err| {
                        ProofServiceError::Other(format!("Failed to generate NFC payload: {err}"))
                    })?;

            let handler = Arc::new(
                NfcStaticHandoverHandler::new(nfc_hce_provider.clone(), &select_message)
                    .error_while("creating NFC handler")?,
            );
            nfc_hce_provider
                .start_hosting(handler.to_owned(), request.ui_message)
                .await
                .error_while("starting NFC hosting")?;
            Some(NfcHceSession {
                handler,
                hce: nfc_hce_provider,
                select_message,
                device_engagement: device_engagement_bytes,
            })
        } else {
            None
        };

        let interaction_id = Uuid::new_v4().into();
        let interaction_data = serde_json::to_vec(&MdocBleHolderInteractionData {
            organisation_id: request.organisation_id,
            service_uuid: ble_server.service_uuid,
            continuation_task_id: ble_server.task_id,
            session: None,
            engagement,
        })
        .map_err(|e| ProofServiceError::MappingError(e.to_string()))?;

        let interaction = add_new_interaction(
            interaction_id,
            &*self.interaction_repository,
            Some(interaction_data),
            organisation,
            InteractionType::Verification,
            None,
            request.ecosystem.to_owned(),
        )
        .await
        .error_while("adding interaction")?;

        let proof_id = self
            .proof_repository
            .create_proof(Proof {
                ecosystem: request.ecosystem,
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
                claims: Default::default(),
                verifier_identifier: None,
                verifier_key: None,
                verifier_certificate: None,
                interaction: Some(interaction.clone().into()),
                proof_blob_id: None,
                engagement: None,
                webhook_url: None,
                subscriber_information: None,
            })
            .await
            .error_while("creating proof")?;

        receive_mdl_request(
            ble,
            key_pair,
            self.interaction_repository.clone(),
            interaction,
            self.proof_repository.clone(),
            proof_id,
            qr_engagement,
            nfc_engagement,
            self.ecosystem_provider.clone(),
            self.certificate_validator.clone(),
            self.identifier_creator.clone(),
            self.verification_fn(),
        )
        .await
        .error_while("receiving mDL request")?;

        Ok(ProposeProofResponseDTO {
            proof_id,
            interaction_id,
            url: qr_code,
        })
    }

    pub async fn delete_proof(&self, proof_id: ProofId) -> Result<(), ProofServiceError> {
        let proof = self
            .proof_repository
            .get_proof(&proof_id, None)
            .await
            .error_while("getting proof")?;
        throw_if_proof_not_in_session_org(&proof, &*self.session_provider).await?;

        match proof.state {
            ProofStateEnum::Created
            | ProofStateEnum::Pending
            | ProofStateEnum::InteractionExpired => {
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
                    .await
                    .error_while("updating proof")?;
            }
            state => return Err(ProofServiceError::InvalidState(state)),
        };
        if let Some(proof_blob_id) = proof.proof_blob_id {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)?;

            blob_storage
                .delete(&proof_blob_id)
                .await
                .error_while("deleting proof blob")?;
        }
        tracing::info!("Deleted proof {}", proof.id);
        Ok(())
    }

    pub async fn get_trust_details(
        &self,
        id: ProofId,
    ) -> Result<TrustInformationDetailResponseDTO, ProofServiceError> {
        let proof = self
            .proof_repository
            .get_proof(&id, None)
            .await
            .error_while("getting credential")?;

        throw_if_proof_not_in_session_org(&proof, &*self.session_provider).await?;
        if proof.role != ProofRole::Holder {
            return Err(ProofServiceError::InvalidRole(proof.role));
        }

        let mut result = TrustInformationDetailResponseDTO {
            // an untrusted verifier is an answer, not a failed request, so this is a 200
            ecosystem_errors: recorded_ecosystem_outcomes(id.into(), &*self.history_repository)
                .await?,
            ..Default::default()
        };

        if let Some(ecosystem_id) = proof.ecosystem {
            let ecosystem = self.ecosystem_provider.get(&ecosystem_id)?;
            let verifier = ecosystem
                .verifier_trust_details(&id)
                .await
                .error_while("getting ecosystem trust detail")?;

            result.ecosystem = Some(ecosystem_id);
            result.verifier = Some(verifier.info.into());
        }

        Ok(result)
    }

    // ============ Private methods

    async fn hard_delete_proof(&self, proof: &Proof) -> Result<(), ProofServiceError> {
        self.proof_repository
            .delete_proof(&proof.id)
            .await
            .error_while("deleting proof")?;
        if let Some(ref interaction) = proof.interaction {
            self.interaction_repository
                .delete_interaction(interaction.id_ref())
                .await
                .error_while("deleting interaction")?;
        };
        Ok(())
    }

    /// Release resources consumed by the exchange protocol for this particular proof
    /// (e.g. BLE advertising).
    async fn exchange_retract_proof(&self, proof: &Proof) -> Result<(), ProofServiceError> {
        // If the configuration is changed such that the exchange protocol of the proof no longer
        // exists we can simply skip the retracting.
        if let Ok(exchange_protocol) = self.protocol_provider.get_protocol(&proof.protocol) {
            exchange_protocol
                .retract_proof(proof)
                .await
                .error_while("retracting proof")?;
        };
        Ok(())
    }

    fn verification_fn(&self) -> VerificationFn {
        Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        })
    }
}
