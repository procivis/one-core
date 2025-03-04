use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use futures::future::BoxFuture;
use shared_types::{CredentialId, OrganisationId, ProofId};
use time::OffsetDateTime;
use uuid::Uuid;
use ProofStateEnum::{Created, Pending, Requested, Retracted};

use super::dto::{
    CreateProofInteractionData, CreateProofRequestDTO, GetProofListResponseDTO, GetProofQueryDTO,
    ProofDetailResponseDTO, ProposeProofResponseDTO, ShareProofRequestDTO,
};
use super::mapper::{
    get_holder_proof_detail, get_verifier_proof_detail, proof_from_create_request,
};
use super::validator::{
    validate_mdl_exchange, validate_redirect_uri, validate_verification_key_storage_compatibility,
};
use super::ProofService;
use crate::common_mapper::{get_encryption_key_jwk_from_proof, list_response_try_into};
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::{ExchangeType, TransportType};
use crate::config::validator::exchange::{
    validate_exchange_did_compatibility, validate_exchange_operation, validate_exchange_type,
};
use crate::config::validator::transport::{
    validate_and_select_transport_type, SelectedTransportType,
};
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::common::EntityShareResponseDTO;
use crate::model::credential::CredentialRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, KeyRole};
use crate::model::history::{HistoryAction, HistoryFilterValue, HistoryListQuery};
use crate::model::interaction::InteractionRelations;
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
use crate::provider::credential_formatter::mdoc_formatter::mdoc::EmbeddedCbor;
use crate::provider::exchange_protocol::dto::{Operation, PresentationDefinitionResponseDTO};
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::iso_mdl::ble_holder::{
    receive_mdl_request, start_mdl_server, MdocBleHolderInteractionData,
};
use crate::provider::exchange_protocol::iso_mdl::common::{EDeviceKey, KeyAgreement};
use crate::provider::exchange_protocol::iso_mdl::device_engagement::{
    BleOptions, DeviceEngagement, DeviceRetrievalMethod, RetrievalOptions, Security,
};
use crate::provider::exchange_protocol::openid4vc::mapper::{
    create_format_map, create_open_id_for_vp_formats,
};
use crate::provider::exchange_protocol::openid4vc::model::{OpenID4VCParams, ShareResponse};
use crate::provider::exchange_protocol::{FormatMapper, TypeToDescriptorMapper};
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::proof::validator::{
    validate_format_and_exchange_protocol_compatibility, validate_scan_to_verify_compatibility,
};
use crate::service::storage_proxy::StorageProxyImpl;
use crate::util::history::log_history_event_proof;
use crate::util::interactions::{
    add_new_interaction, clear_previous_interaction, update_proof_interaction,
};
use crate::util::oidc::create_oicd_to_core_format_map;

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
                            issuer_did: Some(Default::default()),
                            holder_did: Some(Default::default()),
                            ..Default::default()
                        }),
                    }),
                    verifier_did: Some(Default::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_key: None,
                    interaction: Some(Default::default()),
                },
            )
            .await?;

        let Some(proof) = proof else {
            return Err(EntityNotFoundError::Proof(*id).into());
        };

        let history_event = self
            .history_repository
            .get_history_list(HistoryListQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 1,
                }),
                sorting: None,
                filtering: Some(
                    HistoryFilterValue::EntityId(proof.id.into()).condition()
                        & HistoryFilterValue::Action(HistoryAction::ClaimsRemoved),
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
        let proof = self
            .proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    holder_did: Some(DidRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Proof(*id))?;

        if proof
            .holder_did
            .as_ref()
            .is_some_and(|did| did.did_type.is_remote())
        {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "holder_did is remote".to_string(),
            }
            .into());
        }

        throw_if_latest_proof_state_not_eq(&proof, Requested)?;

        let exchange = self.protocol_provider.get_protocol(&proof.exchange).ok_or(
            MissingProviderError::ExchangeProtocol(proof.exchange.clone()),
        )?;
        let interaction_data = proof
            .interaction
            .as_ref()
            .and_then(|interaction| interaction.data.as_ref())
            .map(|interaction| serde_json::from_slice(interaction))
            .ok_or_else(|| ServiceError::MappingError("proof interaction is missing".into()))?
            .map_err(|err| ServiceError::MappingError(err.to_string()))?;

        let storage_access = StorageProxyImpl::new(
            self.interaction_repository.clone(),
            self.credential_schema.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
            self.did_method_provider.clone(),
        );

        exchange
            .holder_get_presentation_definition(
                &proof,
                interaction_data,
                &storage_access,
                create_oicd_to_core_format_map(),
            )
            .await
            .map_err(Into::into)
    }

    /// Returns list of proofs according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_proof_list(
        &self,
        query: GetProofQueryDTO,
    ) -> Result<GetProofListResponseDTO, ServiceError> {
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
        validate_exchange_type(&request.exchange, &self.config.exchange)?;
        validate_mdl_exchange(
            &request.exchange,
            request.iso_mdl_engagement.as_deref(),
            request.redirect_uri.as_deref(),
            &self.config.exchange,
        )?;
        validate_redirect_uri(
            &request.exchange,
            request.redirect_uri.as_deref(),
            &self.config.exchange,
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

        // ONE-843: cannot create proof based on deleted schema
        if proof_schema.deleted_at.is_some() {
            return Err(BusinessLogicError::ProofSchemaDeleted { proof_schema_id }.into());
        }

        validate_format_and_exchange_protocol_compatibility(
            &request.exchange,
            &self.config,
            &proof_schema,
            &*self.credential_formatter_provider,
        )?;

        validate_scan_to_verify_compatibility(&request, &self.config)?;

        let exchange_type = self.config.exchange.get_fields(&request.exchange)?.r#type;
        if exchange_type == ExchangeType::ScanToVerify {
            return self
                .handle_scan_to_verify(
                    proof_schema,
                    request.exchange,
                    request
                        .scan_to_verify
                        .ok_or(ValidationError::InvalidScanToVerifyParameters)?,
                )
                .await;
        } else if exchange_type == ExchangeType::IsoMdl {
            return self
                .handle_iso_mdl_verifier(
                    proof_schema,
                    request.exchange,
                    request
                        .iso_mdl_engagement
                        .ok_or(ValidationError::InvalidMdlParameters)?,
                )
                .await;
        }

        let Some(verifier_did) = self
            .did_repository
            .get_did(
                &request.verifier_did_id,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    organisation: None,
                },
            )
            .await?
        else {
            return Err(EntityNotFoundError::Did(request.verifier_did_id).into());
        };

        if verifier_did.deactivated {
            return Err(BusinessLogicError::DidIsDeactivated(verifier_did.id).into());
        }

        if verifier_did.did_type.is_remote() {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "verifier_did is remote".to_string(),
            }
            .into());
        }

        let verifier_key = match request.verifier_key {
            Some(verifier_key) => verifier_did.find_key(&verifier_key, KeyRole::Authentication)?,
            None => verifier_did.find_first_key_by_role(KeyRole::Authentication)?,
        }
        .to_owned();

        if verifier_key.key_type == "BBS_PLUS" {
            return Err(ValidationError::BBSNotSupported.into());
        }

        validate_verification_key_storage_compatibility(
            &proof_schema,
            &verifier_key,
            &*self.credential_formatter_provider,
        )?;

        let Some(exchange_protocol) = self.protocol_provider.get_protocol(&request.exchange) else {
            return Err(MissingProviderError::ExchangeProtocol(request.exchange.to_owned()).into());
        };
        let exchange_protocol_capabilities = exchange_protocol.get_capabilities();
        validate_exchange_operation(&exchange_protocol_capabilities, &Operation::VERIFICATION)?;
        validate_exchange_did_compatibility(
            &exchange_protocol_capabilities,
            &Operation::VERIFICATION,
            &verifier_did.did_method,
        )?;

        let transport = validate_and_select_transport_type(
            &request.transport,
            &self.config.transport,
            &exchange_protocol_capabilities,
        )?;

        let mut maybe_interaction_id = None;
        let transport = match transport {
            SelectedTransportType::Single(single) => single,
            // for multiple transports we store them in interaction data and set the transport=""
            SelectedTransportType::Multiple(multiple) => {
                let interaction_id = Uuid::new_v4();
                let data = CreateProofInteractionData {
                    transport: multiple,
                };

                add_new_interaction(
                    interaction_id,
                    &self.base_url,
                    &*self.interaction_repository,
                    serde_json::to_vec(&data).ok(),
                    proof_schema.organisation.clone(),
                )
                .await?;

                maybe_interaction_id = Some(interaction_id);

                String::new()
            }
        };

        let proof_id = self
            .proof_repository
            .create_proof(proof_from_create_request(
                request,
                now,
                proof_schema,
                transport,
                verifier_did,
                Some(verifier_key),
            ))
            .await?;

        if let Some(interaction_id) = maybe_interaction_id {
            update_proof_interaction(proof_id, interaction_id, &*self.proof_repository).await?;
        }

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
        callback: Option<BoxFuture<'static, ()>>,
    ) -> Result<EntityShareResponseDTO, ServiceError> {
        let proof = self.get_proof_with_state(id).await?;

        match proof.state {
            Created => {
                self.proof_repository
                    .update_proof(
                        &proof.id,
                        UpdateProofRequest {
                            state: Some(Pending),
                            ..Default::default()
                        },
                        None,
                    )
                    .await?;
            }
            Pending => {}
            state => {
                return Err(BusinessLogicError::InvalidProofState { state }.into());
            }
        }

        let exchange = self.protocol_provider.get_protocol(&proof.exchange).ok_or(
            MissingProviderError::ExchangeProtocol(proof.exchange.to_owned()),
        )?;

        let exchange_params: OpenID4VCParams = self.config.exchange.get(&proof.exchange)?;

        let client_id_schema = request
            .params
            .unwrap_or_default()
            .client_id_schema
            .unwrap_or(
                exchange_params
                    .presentation
                    .verifier
                    .default_client_id_schema,
            );

        let formats = create_open_id_for_vp_formats();
        let jwk = get_encryption_key_jwk_from_proof(&proof, &*self.key_algorithm_provider)?;

        let config = self.config.clone();
        let format_type_mapper: FormatMapper = Arc::new(move |input| {
            Ok(config
                .format
                .get_fields(input)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
                .r#type
                .to_owned())
        });

        let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(create_format_map);

        let ShareResponse {
            url,
            interaction_id,
            context,
        } = exchange
            .verifier_share_proof(
                &proof,
                format_type_mapper,
                jwk.key_id,
                jwk.jwk.into(),
                formats,
                type_to_descriptor_mapper,
                callback,
                client_id_schema,
            )
            .await?;

        let organisation = proof
            .schema
            .as_ref()
            .and_then(|schema| schema.organisation.as_ref())
            .ok_or_else(|| ExchangeProtocolError::Failed("Missing organisation".to_string()))?;

        add_new_interaction(
            interaction_id,
            &self.base_url,
            &*self.interaction_repository,
            serde_json::to_vec(&context).ok(),
            Some(organisation.to_owned()),
        )
        .await?;
        update_proof_interaction(proof.id, interaction_id, &*self.proof_repository).await?;
        clear_previous_interaction(&*self.interaction_repository, &proof.interaction).await?;

        let _ =
            log_history_event_proof(&*self.history_repository, &proof, HistoryAction::Shared).await;

        Ok(EntityShareResponseDTO { url })
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
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(
                proof_id,
            )))?;

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
            .delete_claims_for_credentials(credential_ids)
            .await?;

        Ok(())
    }

    pub async fn propose_proof(
        &self,
        exchange: String,
        organisation_id: OrganisationId,
    ) -> Result<ProposeProofResponseDTO, ServiceError> {
        validate_exchange_type(&exchange, &self.config.exchange)?;
        let exchange_type = self.config.exchange.get_fields(&exchange)?.r#type;
        if exchange_type != ExchangeType::IsoMdl {
            return Err(ValidationError::InvalidExchangeType {
                value: exchange,
                source: anyhow::anyhow!("propose_proof"),
            }
            .into());
        }

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
        let server = start_mdl_server(ble).await?;
        let key_pair = KeyAgreement::<EDeviceKey>::new();
        let device_engagement = DeviceEngagement {
            security: Security {
                key_bytes: EmbeddedCbor::new(EDeviceKey::new(key_pair.device_key().0))
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
            },
            device_retrieval_methods: vec![DeviceRetrievalMethod {
                retrieval_options: RetrievalOptions::Ble(BleOptions {
                    peripheral_server_uuid: server.service_uuid,
                    peripheral_server_mac_address: server.mac_address,
                }),
            }],
        };

        let qr = device_engagement
            .generate_qr_code()
            .map_err(|err| ServiceError::Other(err.to_string()))?;

        let interaction_id = Uuid::new_v4();

        let interaction_data = serde_json::to_vec(&MdocBleHolderInteractionData {
            organisation_id,
            service_uuid: server.service_uuid,
            continuation_task_id: server.task_id,
            session: None,
        })
        .context("interaction serialization error")
        .map_err(ExchangeProtocolError::Other)?;

        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id, &OrganisationRelations::default())
            .await?;

        let interaction = add_new_interaction(
            interaction_id,
            &self.base_url,
            &*self.interaction_repository,
            Some(interaction_data),
            organisation,
        )
        .await?;

        let proof_id = self
            .proof_repository
            .create_proof(Proof {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                issuance_date: now,
                exchange,
                redirect_uri: None,
                state: Pending,
                role: ProofRole::Holder,
                requested_date: Some(now),
                completed_date: None,
                schema: None,
                transport: transport.to_owned(),
                claims: None,
                verifier_did: None,
                holder_did: None,
                verifier_key: None,
                interaction: Some(interaction.clone()),
            })
            .await?;

        receive_mdl_request(
            ble,
            qr.device_engagement,
            key_pair,
            self.interaction_repository.clone(),
            interaction,
            self.proof_repository.clone(),
            proof_id,
        )
        .await?;

        Ok(ProposeProofResponseDTO {
            proof_id,
            interaction_id,
            url: qr.qr_code_content,
        })
    }

    pub async fn delete_proof(&self, proof_id: ProofId) -> Result<(), ServiceError> {
        let Some(proof) = self
            .proof_repository
            .get_proof(
                &proof_id,
                &ProofRelations {
                    interaction: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(EntityNotFoundError::Proof(proof_id).into());
        };

        match proof.state {
            Created | Pending => {
                self.exchange_retract_proof(&proof).await?;
                self.hard_delete_proof(&proof).await?
            }
            Requested => {
                self.exchange_retract_proof(&proof).await?;
                let proof_update = UpdateProofRequest {
                    state: Some(Retracted),
                    ..Default::default()
                };
                self.proof_repository
                    .update_proof(&proof.id, proof_update, None)
                    .await?;
            }
            state => return Err(BusinessLogicError::InvalidProofState { state }.into()),
        };
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
        let exchange_protocol = self.protocol_provider.get_protocol(&proof.exchange).ok_or(
            ServiceError::MissingExchangeProtocol(proof.exchange.clone()),
        )?;
        exchange_protocol.retract_proof(proof).await?;
        Ok(())
    }

    /// Get latest proof state
    async fn get_proof_with_state(&self, id: &ProofId) -> Result<Proof, ServiceError> {
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
                    verifier_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Proof(*id))?;

        Ok(proof)
    }
}
