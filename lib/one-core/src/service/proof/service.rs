use shared_types::ProofId;
use time::OffsetDateTime;

use super::dto::{
    CreateProofRequestDTO, GetProofListResponseDTO, GetProofQueryDTO, ProofDetailResponseDTO,
};
use super::mapper::{
    get_holder_proof_detail, get_verifier_proof_detail, proof_from_create_request,
    proof_requested_history_event,
};
use super::ProofService;
use crate::common_mapper::list_response_try_into;
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::validator::exchange::validate_exchange_type;
use crate::config::validator::transport::get_available_transport_type;
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::common::EntityShareResponseDTO;
use crate::model::credential::CredentialRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, KeyRole};
use crate::model::interaction::InteractionRelations;
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{
    Proof, ProofClaimRelations, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations,
    UpdateProofRequest,
};
use crate::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use crate::provider::exchange_protocol::dto::PresentationDefinitionResponseDTO;
use crate::provider::exchange_protocol::openid4vc::model::BLEOpenID4VPInteractionData;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::proof::validator::validate_format_and_exchange_protocol_compatibility;

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
                    state: Some(Default::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            state: Some(Default::default()),
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

        if proof.schema.is_some() {
            get_verifier_proof_detail(proof, &self.config)
        } else {
            get_holder_proof_detail(proof, &self.config)
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
                    state: Some(ProofStateRelations::default()),
                    holder_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        let Some(proof) = proof else {
            return Err(EntityNotFoundError::Proof(*id).into());
        };

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

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        let exchange = self.protocol_provider.get_protocol(&proof.exchange).ok_or(
            MissingProviderError::ExchangeProtocol(proof.exchange.clone()),
        )?;
        Ok(exchange.get_presentation_definition(&proof).await?)
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

        let now = OffsetDateTime::now_utc();
        let proof_schema_id = request.proof_schema_id;
        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(
                &proof_schema_id,
                &ProofSchemaRelations {
                    organisation: None,
                    proof_inputs: Some(ProofInputSchemaRelations {
                        claim_schemas: None,
                        credential_schema: Some(CredentialSchemaRelations::default()),
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
            &self.credential_formatter_provider,
        )?;

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

        let transport = get_available_transport_type(&self.config.transport)?;

        self.proof_repository
            .create_proof(proof_from_create_request(
                request,
                now,
                proof_schema,
                transport,
                verifier_did,
                Some(verifier_key),
            ))
            .await
            .map_err(ServiceError::from)
    }

    /// Request proof
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    pub async fn share_proof(&self, id: &ProofId) -> Result<EntityShareResponseDTO, ServiceError> {
        let (proof, proof_state) = self.get_proof_with_state(id).await?;

        let now = OffsetDateTime::now_utc();

        match proof_state {
            ProofStateEnum::Created => {
                self.proof_repository
                    .set_proof_state(
                        id,
                        ProofState {
                            created_date: now,
                            last_modified: now,
                            state: ProofStateEnum::Pending,
                        },
                    )
                    .await?;
            }
            ProofStateEnum::Pending => {}
            state => {
                return Err(BusinessLogicError::InvalidProofState { state }.into());
            }
        }

        let exchange_instance = &self
            .config
            .exchange
            .get_fields(&proof.exchange)
            .map_err(|err| {
                ServiceError::MissingExchangeProtocol(format!("{}. {err}", proof.exchange))
            })?
            .r#type()
            .to_string();

        let exchange = self
            .protocol_provider
            .get_protocol(exchange_instance)
            .ok_or(MissingProviderError::ExchangeProtocol(
                exchange_instance.clone(),
            ))?;

        let url = exchange.share_proof(&proof).await?;

        let _ = self
            .history_repository
            .create_history(proof_requested_history_event(proof))
            .await;

        Ok(EntityShareResponseDTO { url })
    }

    pub async fn retract_proof(&self, proof_id: ProofId) -> Result<ProofId, ServiceError> {
        let proof = self
            .proof_repository
            .get_proof(
                &proof_id,
                &ProofRelations {
                    state: Some(Default::default()),
                    interaction: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Proof(proof_id))?;

        let last_state = proof
            .state
            .as_ref()
            // states come ordered from the DB, newest first
            .and_then(|states| states.first())
            .map(|last_state| &last_state.state)
            .ok_or_else(|| {
                ServiceError::MappingError(format!("Missing state for proof: {proof_id}"))
            })?;

        if !matches!(
            last_state,
            ProofStateEnum::Pending | ProofStateEnum::Requested,
        ) {
            return Err(BusinessLogicError::InvalidProofState {
                state: last_state.clone(),
            }
            .into());
        }

        let (interaction_id, interaction_data) = proof
            .interaction
            .and_then(|i| Some((i.id, i.data?)))
            .ok_or_else(|| {
                ServiceError::MappingError(format!("Missing interaction data in proof {proof_id}"))
            })?;

        if proof.exchange == "OPENID4VC" && self.config.transport.ble_enabled_for(&proof.transport)
        {
            let ble_peripheral = self.ble_peripheral.as_ref().ok_or_else(|| {
                ServiceError::Other(
                    "BLE peripheral is enabled in config but missing in services".to_string(),
                )
            })?;

            let is_advertising = ble_peripheral.is_advertising().await.map_err(|err| {
                ServiceError::Other(format!("BLE peripheral is advertising check error: {err}"))
            })?;

            if is_advertising {
                ble_peripheral.stop_advertisement().await.map_err(|err| {
                    ServiceError::Other(format!("BLE peripheral stop advertisement error: {err}"))
                })?;
            }

            let ble_interaction_data: BLEOpenID4VPInteractionData =
                serde_json::from_slice(&interaction_data).map_err(|err| {
                    ServiceError::Other(format!(
                        "Failed deserializing BLEOpenID4VPInteractionData: {err}"
                    ))
                })?;

            let service = "00000001-5026-444A-9E0E-D6F2450F3A77".to_owned();
            // todo: add an enum for different characteristic values
            let characteristic = "0000000B-5026-444A-9E0E-D6F2450F3A77".to_owned();
            let data = &[1];

            ble_peripheral
                .notify_characteristic_data(
                    ble_interaction_data.peer.device_info.address,
                    service,
                    characteristic,
                    data,
                )
                .await
                .map_err(|err| {
                    ServiceError::Other(format!(
                        "BLE peripheral error notifying characteristic data: {err}"
                    ))
                })?;

            ble_peripheral.stop_server().await.map_err(|err| {
                ServiceError::Other(format!("BLE peripheral error stopping server: {err}"))
            })?;
        }

        self.proof_repository
            .update_proof(UpdateProofRequest {
                id: proof_id,
                holder_did_id: None,
                verifier_did_id: None,
                state: Some(ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Created,
                }),
                interaction: Some(None),
                redirect_uri: None,
            })
            .await?;

        self.interaction_repository
            .delete_interaction(&interaction_id)
            .await?;

        Ok(proof_id)
    }

    // ============ Private methods

    /// Get latest proof state
    async fn get_proof_with_state(
        &self,
        id: &ProofId,
    ) -> Result<(Proof, ProofStateEnum), ServiceError> {
        let proof = self
            .proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Proof(*id))?;

        let proof_states = proof
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = proof_states
            .first()
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?
            .state
            .to_owned();
        Ok((proof, latest_state))
    }
}
