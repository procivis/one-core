use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use dto::OpenID4VPBleData;
use model::BLEOpenID4VPInteractionData;
use one_providers::common_models::key::Key;
use one_providers::credential_formatter::model::{DetailCredential, FormatPresentationCtx};
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::crypto::imp::utilities;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::key_storage::provider::KeyProvider;
use one_providers::revocation::provider::RevocationMethodProvider;
use openidvc_ble::oidc_ble_holder::OpenID4VCBLEHolder;
use openidvc_ble::oidc_ble_verifier::OpenID4VCBLEVerifier;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use shared_types::CredentialId;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use self::dto::{
    OpenID4VCICredential, OpenID4VCICredentialDefinition, OpenID4VCICredentialOfferClaim,
    OpenID4VCICredentialOfferClaimValue, OpenID4VCICredentialOfferCredentialDTO,
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialValueDetails, OpenID4VCIProof,
    OpenID4VPInteractionData,
};
use self::mapper::{
    create_claims_from_credential_definition, create_credential_offer,
    create_open_id_for_vp_presentation_definition, create_open_id_for_vp_sharing_url_encoded,
    create_presentation_submission, get_claim_name_by_json_path, get_credential_offer_url,
    map_offered_claims_to_credential_schema, parse_mdoc_schema_claims, parse_procivis_schema_claim,
    presentation_definition_from_interaction_data,
};
use self::model::{
    HolderInteractionData, JwePayload, OpenID4VCInteractionContent, OpenID4VPInteractionContent,
};
use self::validator::validate_interaction_data;
use super::dto::{PresentedCredential, ShareResponse, SubmitIssuerResponse, UpdateResponse};
use super::mapper::interaction_from_handle_invitation;
use super::{
    deserialize_interaction_data, serialize_interaction_data, ExchangeProtocolError,
    ExchangeProtocolImpl, StorageAccess,
};
use crate::config::core_config::{self, TransportType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Credential, CredentialRole, CredentialState, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType, LayoutType,
    UpdateCredentialSchemaRequest,
};
use crate::model::did::{Did, DidRelations, DidType};
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, UpdateProofRequest};
use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::provider::credential_formatter::mapper::format_presentation_ctx_from_interaction_data;
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, CredentialGroupItem, PresentationDefinitionResponseDTO,
};
use crate::provider::exchange_protocol::mapper::{
    get_relevant_credentials_to_credential_schemas, proof_from_handle_invitation,
};
use crate::repository::error::DataLayerError;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialSchemaDetailResponseDTO,
};
use crate::service::credential_schema::mapper::from_create_request;
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{
    OpenID4VCICredentialResponseDTO, OpenID4VCIDiscoveryResponseDTO,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
    OpenID4VPDirectPostResponseDTO,
};
use crate::service::ssi_holder::dto::InvitationResponseDTO;
use crate::util::oidc::{
    detect_correct_format, map_core_to_oidc_format, map_from_oidc_format_to_core,
};
use crate::util::proof_formatter::OpenID4VCIProofJWTFormatter;

mod mdoc;
#[cfg(test)]
mod test;

pub mod dto;
pub(crate) mod mapper;
pub mod model;
pub(crate) mod openidvc_ble;
mod validator;

const CREDENTIAL_OFFER_URL_SCHEME: &str = "openid-credential-offer";
const CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY: &str = "credential_offer";
const CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY: &str = "credential_offer_uri";
const PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY: &str = "presentation_definition";
const PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY: &str = "presentation_definition_uri";
const PRESENTATION_DEFINITION_BLE_NAME: &str = "name";
const PRESENTATION_DEFINITION_BLE_KEY: &str = "key";

pub(crate) struct OpenID4VC {
    client: reqwest::Client,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    base_url: Option<String>,
    params: OpenID4VCParams,
    config: Arc<core_config::CoreConfig>,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
    ble_central: Option<Arc<dyn BleCentral>>,
}

enum InvitationType {
    CredentialIssuance,
    ProofRequestHttp,
    ProofRequestBle,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCParams {
    pub(crate) pre_authorized_code_expires_in: u64,
    pub(crate) token_expires_in: u64,
    pub(crate) refresh_expires_in: u64,
    pub(crate) credential_offer_by_value: Option<bool>,
    pub(crate) client_metadata_by_value: Option<bool>,
    pub(crate) presentation_definition_by_value: Option<bool>,
    pub(crate) allow_insecure_http_transport: Option<bool>,
}

impl OpenID4VC {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_url: Option<String>,
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        params: OpenID4VCParams,
        config: Arc<core_config::CoreConfig>,
        ble_peripheral: Option<Arc<dyn BlePeripheral>>,
        ble_central: Option<Arc<dyn BleCentral>>,
    ) -> Self {
        Self {
            base_url,
            proof_repository,
            interaction_repository,
            formatter_provider,
            revocation_provider,
            key_provider,
            key_algorithm_provider,
            client: reqwest::Client::new(),
            params,
            config,
            ble_peripheral,
            ble_central,
        }
    }

    fn detect_invitation_type(&self, url: &Url) -> Option<InvitationType> {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        if query_has_key(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY)
            || query_has_key(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY)
        {
            return Some(InvitationType::CredentialIssuance);
        }

        if query_has_key(PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY)
            || query_has_key(PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY)
        {
            return Some(InvitationType::ProofRequestHttp);
        }

        if url.scheme() == "openid4vp"
            && query_has_key(PRESENTATION_DEFINITION_BLE_NAME)
            && query_has_key(PRESENTATION_DEFINITION_BLE_KEY)
        {
            return Some(InvitationType::ProofRequestBle);
        }

        None
    }

    async fn handle_proof_invitation_ble(
        &self,
        url: Url,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        if !self
            .config
            .transport
            .ble_enabled_for(&TransportType::Ble.to_string())
        {
            return Err(ExchangeProtocolError::Disabled(
                "BLE transport is disabled".to_string(),
            ));
        }

        let Some(ble_central) = self.ble_central.clone() else {
            return Err(ExchangeProtocolError::Failed(
                "BLE central not available".to_string(),
            ));
        };

        let query = url.query().ok_or(ExchangeProtocolError::InvalidRequest(
            "Query cannot be empty".to_string(),
        ))?;

        let OpenID4VPBleData { name, key } = serde_qs::from_str(query)
            .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

        let mut ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            ble_central,
            None,
        );

        if !ble_holder.enabled().await? {
            return Err(ExchangeProtocolError::Disabled(
                "BLE adapter is disabled".into(),
            ));
        }

        let now = OffsetDateTime::now_utc();
        let interaction = Interaction {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            host: None,
            data: None,
        };
        let interaction_id = self
            .interaction_repository
            .create_interaction(interaction.clone())
            .await
            .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

        let proof_id = Uuid::new_v4().into();
        let proof = proof_from_handle_invitation(
            &proof_id,
            "OPENID4VC",
            None,
            None,
            interaction,
            now,
            None,
            "BLE",
        );

        ble_holder
            .handle_invitation(name, key, proof.id, interaction_id)
            .await?;

        Ok(InvitationResponseDTO::ProofRequest {
            interaction_id,
            proof: Box::new(proof),
        })
    }
}

#[async_trait]
impl ExchangeProtocolImpl for OpenID4VC {
    type VCInteractionContext = OpenID4VCInteractionContent;
    type VPInteractionContext = Option<OpenID4VPInteractionContent>;

    fn can_handle(&self, url: &Url) -> bool {
        self.detect_invitation_type(url).is_some()
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        let invitation_type =
            self.detect_invitation_type(&url)
                .ok_or(ExchangeProtocolError::Failed(
                    "No OpenID4VC query params detected".to_string(),
                ))?;

        match invitation_type {
            InvitationType::CredentialIssuance => {
                handle_credential_invitation(url, organisation, &self.client, storage_access).await
            }
            InvitationType::ProofRequestHttp => {
                handle_proof_invitation(
                    url,
                    self.params
                        .allow_insecure_http_transport
                        .is_some_and(|value| value),
                    &self.client,
                    storage_access,
                )
                .await
            }
            InvitationType::ProofRequestBle => self.handle_proof_invitation_ble(url).await,
        }
    }

    async fn reject_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        let interaction_data: OpenID4VPInteractionData =
            deserialize_interaction_data(proof.interaction.as_ref())?;

        let tokens: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.presentation.to_owned())
            .collect();

        let formats: HashSet<&str> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.credential_schema.format.as_str())
            .collect();

        let (format, oidc_format) = if formats.contains("MDOC") {
            if formats.len() > 1 {
                return Err(ExchangeProtocolError::Failed(
                    "Currently for a proof MDOC cannot be used with other formats".to_string(),
                ));
            };

            ("MDOC", "mso_mdoc")
        } else if formats.contains("JSON_LD") {
            ("JSON_LD_CLASSIC", "ldp_vp")
        } else {
            ("JWT", "jwt_vp_json")
        };

        let presentation_formatter = self
            .formatter_provider
            .get_formatter(format)
            .ok_or_else(|| ExchangeProtocolError::Failed("Formatter not found".to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.to_owned(), jwk_key_id)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let presentation_submission = create_presentation_submission(
            &interaction_data,
            credential_presentations,
            oidc_format,
        )?;

        let response_uri = interaction_data.response_uri.clone();
        let mut params: HashMap<&str, String> = HashMap::new();

        if format == "MDOC" {
            let mdoc_generated_nonce = utilities::generate_nonce();

            let mut ctx = format_presentation_ctx_from_interaction_data(interaction_data.clone());
            ctx.format_nonce = Some(mdoc_generated_nonce.clone());

            let client_metadata =
                interaction_data
                    .client_metadata
                    .ok_or(ExchangeProtocolError::Failed(
                        "Missing client_metadata for MDOC openid4vp".to_string(),
                    ))?;

            let state = interaction_data.state.ok_or(ExchangeProtocolError::Failed(
                "Missing state in openid4vp".to_string(),
            ))?;

            let vp_token = presentation_formatter
                .format_presentation(
                    &tokens,
                    &holder_did.did.clone().into(),
                    &key.key_type,
                    auth_fn,
                    ctx,
                )
                .await
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

            let payload = JwePayload {
                aud: response_uri.clone(),
                exp: (OffsetDateTime::now_utc() + Duration::minutes(10)),
                vp_token,
                presentation_submission,
                state,
            };

            let response = mdoc::build_jwe(
                payload,
                client_metadata,
                &mdoc_generated_nonce,
                &interaction_data.nonce,
            )
            .map_err(|err| {
                ExchangeProtocolError::Failed(format!("Failed to build mdoc response jwe: {err}"))
            })?;

            params.insert("response", response);
        } else {
            let ctx = FormatPresentationCtx {
                nonce: Some(interaction_data.nonce),
                ..Default::default()
            };

            let vp_token = presentation_formatter
                .format_presentation(
                    &tokens,
                    &holder_did.did.clone().into(),
                    &key.key_type,
                    auth_fn,
                    ctx,
                )
                .await
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

            params.insert("vp_token", vp_token);
            params.insert(
                "presentation_submission",
                serde_json::to_string(&presentation_submission)
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
            );

            if let Some(state) = interaction_data.state {
                params.insert("state", state);
            }
        }

        let response = self
            .client
            .post(response_uri)
            .form(&params)
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;

        let response: Result<OpenID4VPDirectPostResponseDTO, _> = response.json().await;

        if let Ok(value) = response {
            Ok(UpdateResponse {
                result: (),
                update_proof: Some(UpdateProofRequest {
                    id: proof.id,
                    redirect_uri: Some(value.redirect_uri),
                    holder_did_id: None,
                    verifier_did_id: None,
                    state: None,
                    interaction: None,
                }),
                create_did: None,
                update_credential: None,
                update_credential_schema: None,
            })
        } else {
            Ok(UpdateResponse {
                result: (),
                update_proof: None,
                create_did: None,
                update_credential: None,
                update_credential_schema: None,
            })
        }
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        storage_access: &StorageAccess,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        let schema = credential
            .schema
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed("schema is None".to_string()))?;

        let format = map_core_to_oidc_format(&schema.format)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let interaction_data: HolderInteractionData =
            deserialize_interaction_data(credential.interaction.as_ref())?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.to_owned(), jwk_key_id)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url,
            holder_did,
            key.key_type.to_owned(),
            auth_fn,
        )
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let (credential_definition, doctype) = match format.as_str() {
            "mso_mdoc" => (None, Some(schema.schema_id.to_owned())),
            _ => (
                Some(OpenID4VCICredentialDefinition {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
                }),
                None,
            ),
        };
        let body = OpenID4VCICredential {
            format,
            credential_definition,
            doctype,
            proof: OpenID4VCIProof {
                proof_type: "jwt".to_string(),
                jwt: proof_jwt,
            },
        };

        let response = self
            .client
            .post(interaction_data.credential_endpoint)
            .bearer_auth(interaction_data.access_token)
            .json(&body)
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response = response
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response_value: OpenID4VCICredentialResponseDTO = response
            .json()
            .await
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        let real_format = detect_correct_format(schema, &response_value.credential)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        // revocation method must be updated based on the issued credential (unknown in credential offer)
        let response_credential = self
            .formatter_provider
            .get_formatter(&real_format)
            .ok_or_else(|| {
                ExchangeProtocolError::Failed(format!("{} formatter not found", schema.format))
            })?
            .extract_credentials_unverified(&response_value.credential)
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        // Revocation method should be the same for every credential in list
        let revocation_method = if let Some(credential_status) = response_credential.status.first()
        {
            let (_, revocation_method) = self
                .revocation_provider
                .get_revocation_method_by_status_type(&credential_status.r#type)
                .ok_or(ExchangeProtocolError::Failed(format!(
                    "Revocation method not found for status type {}",
                    credential_status.r#type
                )))?;
            Some(revocation_method)
        } else {
            None
        };

        // issuer_did must be set based on issued credential (unknown in credential offer)
        let issuer_did_value =
            response_credential
                .issuer_did
                .ok_or(ExchangeProtocolError::Failed(
                    "issuer_did missing".to_string(),
                ))?;

        let now = OffsetDateTime::now_utc();
        let (issuer_did_id, create_did) = match storage_access
            .get_did_by_value(&issuer_did_value, &DidRelations::default())
            .await
            .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?
        {
            Some(did) => (did.id, None),
            None => {
                let id = Uuid::new_v4().into();
                let did_method = match issuer_did_value.as_str() {
                    mdl if mdl.starts_with("did:mdl") => "MDL",
                    key if key.starts_with("did:key") => "KEY",
                    jwk if jwk.starts_with("did:jwk") => "JWK",
                    ion if ion.starts_with("did:ion") => "ION",
                    x509 if x509.starts_with("did:x509") => "X509",
                    other => {
                        tracing::warn!("Unmapped did-method for issuer did: {other}");
                        "UNKNOWN"
                    }
                };

                (
                    id,
                    Some(Did {
                        id,
                        name: format!("issuer {id}"),
                        created_date: now,
                        last_modified: now,
                        organisation: schema.organisation.to_owned(),
                        did: issuer_did_value.into(),
                        did_type: DidType::Remote,
                        did_method: did_method.to_string(),
                        keys: None,
                        deactivated: false,
                    }),
                )
            }
        };

        let redirect_uri = response_value.redirect_uri.clone();

        Ok(UpdateResponse {
            result: response_value.into(),
            update_proof: None,
            create_did,
            update_credential_schema: Some(UpdateCredentialSchemaRequest {
                id: schema.id,
                revocation_method,
                format: Some(real_format),
                claim_schemas: None,
            }),
            update_credential: Some(UpdateCredentialRequest {
                id: credential.id,
                issuer_did_id: Some(issuer_did_id),
                redirect_uri: Some(redirect_uri),
                credential: None,
                holder_did_id: None,
                state: None,
                interaction: None,
                key: None,
            }),
        })
    }

    async fn reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    async fn share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        let interaction_id = Uuid::new_v4();
        let interaction_content = OpenID4VCInteractionContent {
            pre_authorized_code_used: false,
            access_token: format!(
                "{}.{}",
                interaction_id,
                utilities::generate_alphanumeric(32),
            ),
            access_token_expires_at: None,
            refresh_token: None,
            refresh_token_expires_at: None,
        };

        let mut url = Url::parse(&format!("{CREDENTIAL_OFFER_URL_SCHEME}://"))
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
        let mut query = url.query_pairs_mut();

        if self
            .params
            .credential_offer_by_value
            .is_some_and(|by_value| by_value)
        {
            let offer = create_credential_offer(
                self.base_url.to_owned(),
                &interaction_id,
                credential,
                &self.config,
            )?;

            let offer_string = serde_json::to_string(&offer)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

            query.append_pair(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY, &offer_string);
        } else {
            let offer_url = get_credential_offer_url(self.base_url.to_owned(), credential)?;
            query.append_pair(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY, &offer_url);
        }

        Ok(ShareResponse {
            url: query.finish().to_string(),
            id: interaction_id,
            context: interaction_content,
        })
    }

    async fn share_proof(
        &self,
        proof: &Proof,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        let interaction_id = Uuid::new_v4();

        // Pass the expected presentation content to interaction for verification
        let presentation_definition =
            create_open_id_for_vp_presentation_definition(interaction_id, proof, &self.config)?;

        if proof.transport == TransportType::Ble.to_string() {
            if !self.config.transport.ble_enabled_for(&proof.transport) {
                return Err(ExchangeProtocolError::Disabled(
                    "BLE transport is disabled".to_string(),
                ));
            }

            if let Some(ble_peripheral) = self.ble_peripheral.clone() {
                let ble_verifier = OpenID4VCBLEVerifier::new(
                    ble_peripheral.clone(),
                    self.proof_repository.clone(),
                )?;

                if !ble_verifier.enabled().await? {
                    return Err(ExchangeProtocolError::Disabled(
                        "BLE adapter is disabled".into(),
                    ));
                }

                return ble_verifier
                    .share_proof(presentation_definition, proof.id)
                    .await
                    .map(|url| ShareResponse {
                        url,
                        id: interaction_id,
                        context: None,
                    });
            } else {
                return Err(ExchangeProtocolError::Failed(
                    "BLE central not available".to_string(),
                ));
            }
        }

        let interaction_content = OpenID4VPInteractionContent {
            nonce: utilities::generate_alphanumeric(32),
            presentation_definition,
        };

        let encoded_offer = create_open_id_for_vp_sharing_url_encoded(
            self.base_url.clone(),
            interaction_id,
            interaction_content.nonce.clone(),
            proof,
            self.params
                .client_metadata_by_value
                .is_some_and(|value| value),
            self.params
                .presentation_definition_by_value
                .is_some_and(|value| value),
            &*self.key_algorithm_provider,
            &self.config,
        )?;

        Ok(ShareResponse {
            url: format!("openid4vp://?{encoded_offer}"),
            id: interaction_id,
            context: Some(interaction_content),
        })
    }

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
        _interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let presentation_definition = {
            if proof.transport == TransportType::Ble.to_string() {
                deserialize_interaction_data::<BLEOpenID4VPInteractionData>(
                    proof.interaction.as_ref(),
                )?
                .presentation_definition
            } else {
                deserialize_interaction_data::<OpenID4VPInteractionData>(
                    proof.interaction.as_ref(),
                )?
                .presentation_definition
                .ok_or(ExchangeProtocolError::Failed(
                    "presentation_definition is None".to_string(),
                ))?
            }
        };

        let mut credential_groups: Vec<CredentialGroup> = vec![];
        let mut group_id_to_schema_id: HashMap<String, String> = HashMap::new();

        let mut allowed_oidc_formats = HashSet::new();

        for input_descriptor in presentation_definition.input_descriptors {
            input_descriptor.format.keys().for_each(|key| {
                allowed_oidc_formats.insert(key.to_owned());
            });
            let validity_credential_nbf = input_descriptor.constraints.validity_credential_nbf;

            let mut fields = input_descriptor.constraints.fields;

            let schema_id_filter_index = fields
                .iter()
                .position(|field| {
                    field.filter.is_some()
                        && field.path.contains(&"$.credentialSchema.id".to_string())
                })
                .ok_or(ExchangeProtocolError::Failed(
                    "schema_id filter not found".to_string(),
                ))?;

            let schema_id_filter = fields.remove(schema_id_filter_index).filter.ok_or(
                ExchangeProtocolError::Failed("schema_id filter not found".to_string()),
            )?;

            group_id_to_schema_id.insert(input_descriptor.id.clone(), schema_id_filter.r#const);
            credential_groups.push(CredentialGroup {
                id: input_descriptor.id,
                name: input_descriptor.name,
                purpose: input_descriptor.purpose,
                claims: fields
                    .iter()
                    .filter(|requested| requested.id.is_some())
                    .map(|requested_claim| {
                        Ok(CredentialGroupItem {
                            id: requested_claim
                                .id
                                .ok_or(ExchangeProtocolError::Failed(
                                    "requested_claim id is None".to_string(),
                                ))?
                                .to_string(),
                            key: get_claim_name_by_json_path(&requested_claim.path)?,
                            required: !requested_claim.optional.is_some_and(|optional| optional),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                applicable_credentials: vec![],
                validity_credential_nbf,
            });
        }

        let mut allowed_schema_formats = HashSet::new();
        allowed_oidc_formats
            .iter()
            .try_for_each(|oidc_format| {
                let schema_type = map_from_oidc_format_to_core(oidc_format)?;

                self.config.format.iter().for_each(|(key, fields)| {
                    if fields.r#type.to_string().starts_with(&schema_type) {
                        allowed_schema_formats.insert(key);
                    }
                });
                Ok(())
            })
            .map_err(|e: ServiceError| ExchangeProtocolError::Failed(e.to_string()))?;

        let (credentials, credential_groups) = get_relevant_credentials_to_credential_schemas(
            storage_access,
            credential_groups,
            group_id_to_schema_id,
            &allowed_schema_formats,
        )
        .await?;
        presentation_definition_from_interaction_data(
            proof.id,
            credentials,
            credential_groups,
            &self.config,
        )
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        unimplemented!()
    }
}

async fn resolve_credential_offer(
    client: &reqwest::Client,
    invitation_url: Url,
) -> Result<OpenID4VCICredentialOfferDTO, ExchangeProtocolError> {
    let query_pairs: HashMap<_, _> = invitation_url.query_pairs().collect();
    let credential_offer_param = query_pairs.get(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY);
    let credential_offer_reference_param =
        query_pairs.get(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY);

    if credential_offer_param.is_some() && credential_offer_reference_param.is_some() {
        return Err(ExchangeProtocolError::Failed(
            format!("Detected both {CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY} and {CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY}"),
        ));
    }

    if let Some(credential_offer) = credential_offer_param {
        serde_json::from_str(credential_offer).map_err(|error| {
            ExchangeProtocolError::Failed(format!("Failed decoding credential offer {error}"))
        })
    } else if let Some(credential_offer_reference) = credential_offer_reference_param {
        let credential_offer_url = Url::parse(credential_offer_reference).map_err(|error| {
            ExchangeProtocolError::Failed(format!("Failed decoding credential offer url {error}"))
        })?;

        // TODO: forbid plain-text http requests in production
        // let url_scheme = credential_offer_url.scheme();
        // if url_scheme != "https" {
        //     return Err(ExchangeProtocolError::Failed(format!(
        //         "Invalid {CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY} url scheme: {url_scheme}"
        //     )));
        // }

        Ok(client
            .get(credential_offer_url)
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .await
            .map_err(|error| {
                ExchangeProtocolError::Failed(format!(
                    "Failed decoding credential offer json {error}"
                ))
            })?)
    } else {
        Err(ExchangeProtocolError::Failed(
            "Missing credential offer param".to_string(),
        ))
    }
}

async fn handle_credential_invitation(
    invitation_url: Url,
    organisation: Organisation,
    client: &reqwest::Client,
    storage_access: &StorageAccess,
) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
    let credential_offer = resolve_credential_offer(client, invitation_url).await?;

    let credential_issuer_endpoint: Url =
        credential_offer.credential_issuer.parse().map_err(|_| {
            ExchangeProtocolError::Failed(format!(
                "Invalid credential issuer url {}",
                credential_offer.credential_issuer
            ))
        })?;

    let (oicd_discovery, issuer_metadata) =
        get_discovery_and_issuer_metadata(client, credential_issuer_endpoint.to_owned()).await?;

    let token_response: OpenID4VCITokenResponseDTO = client
        .post(&oicd_discovery.token_endpoint)
        .form(&OpenID4VCITokenRequestDTO::PreAuthorizedCode {
            pre_authorized_code: credential_offer.grants.code.pre_authorized_code.clone(),
        })
        .send()
        .await
        .context("send error")
        .map_err(ExchangeProtocolError::Transport)?
        .error_for_status()
        .context("status error")
        .map_err(ExchangeProtocolError::Transport)?
        .json()
        .await
        .context("parsing error")
        .map_err(ExchangeProtocolError::Transport)?;

    // OID4VC credential offer query param should always contain one credential for the moment
    let credential = credential_offer.credentials.first().ok_or_else(|| {
        ExchangeProtocolError::Failed("Credential offer is missing credentials".to_string())
    })?;

    let credential_schema_name = get_credential_schema_name(&issuer_metadata, credential)?;
    let (schema_id, schema_type) = find_schema_data(&issuer_metadata, credential);

    let holder_data = HolderInteractionData {
        issuer_url: issuer_metadata.credential_issuer,
        credential_endpoint: issuer_metadata.credential_endpoint,
        access_token: token_response.access_token,
        access_token_expires_at: OffsetDateTime::from_unix_timestamp(token_response.expires_in.0)
            .ok(),
        refresh_token: token_response.refresh_token,
        refresh_token_expires_at: token_response
            .refresh_token_expires_in
            .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok()),
    };
    let data = serialize_interaction_data(&holder_data)?;

    let interaction =
        create_and_store_interaction(storage_access, credential_issuer_endpoint, data).await?;
    let interaction_id = interaction.id;

    let claim_keys = build_claim_keys(credential)?;

    let credential_id: CredentialId = Uuid::new_v4().into();
    let (claims, credential_schema) = match storage_access
        .get_schema(
            &schema_id,
            &CredentialSchemaRelations {
                claim_schemas: Some(ClaimSchemaRelations::default()),
                organisation: Some(Default::default()),
            },
        )
        .await
        .map_err(ExchangeProtocolError::StorageAccessError)?
    {
        Some(credential_schema) => {
            if credential_schema.schema_type != schema_type {
                return Err(ExchangeProtocolError::IncorrectCredentialSchemaType);
            }

            let claims = map_offered_claims_to_credential_schema(
                &credential_schema,
                credential_id,
                &claim_keys,
            )?;

            (claims, credential_schema)
        }
        None => {
            let (claims, credential_schema) = match schema_type {
                CredentialSchemaType::ProcivisOneSchema2024 => {
                    let procivis_schema = fetch_procivis_schema(&schema_id)
                        .await
                        .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                    let schema = from_create_request(
                        CreateCredentialSchemaRequestDTO {
                            name: procivis_schema.name,
                            format: procivis_schema.format,
                            revocation_method: procivis_schema.revocation_method,
                            organisation_id: organisation.id,
                            claims: procivis_schema
                                .claims
                                .into_iter()
                                .map(parse_procivis_schema_claim)
                                .collect(),
                            wallet_storage_type: procivis_schema.wallet_storage_type,
                            layout_type: procivis_schema.layout_type.unwrap_or(LayoutType::Card),
                            layout_properties: procivis_schema.layout_properties,
                            schema_id: Some(schema_id),
                        },
                        organisation,
                        "",
                        "JWT",
                        None,
                    )
                    .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                    let credential_schema = CredentialSchema {
                        schema_type,
                        ..schema
                    };

                    let claims = map_offered_claims_to_credential_schema(
                        &credential_schema,
                        credential_id,
                        &claim_keys,
                    )?;

                    (claims, credential_schema)
                }
                CredentialSchemaType::Mdoc => {
                    let credential_format = map_from_oidc_format_to_core(&credential.format)
                        .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                    let metadata_credential = issuer_metadata
                        .credentials_supported
                        .into_iter()
                        .find(|credential| {
                            credential
                                .doctype
                                .as_ref()
                                .is_some_and(|doctype| doctype == &schema_id)
                        });

                    let element_order = metadata_credential
                        .as_ref()
                        .and_then(|credential| credential.order.to_owned());

                    let claim_schemas =
                        metadata_credential.and_then(|credential| credential.claims);
                    let claims_specified = claim_schemas.is_some();

                    let credential_schema = from_create_request(
                        CreateCredentialSchemaRequestDTO {
                            name: credential_schema_name,
                            format: credential_format,
                            revocation_method: "NONE".to_string(),
                            organisation_id: organisation.id,
                            claims: if let Some(schemas) = claim_schemas {
                                parse_mdoc_schema_claims(schemas, element_order)
                            } else {
                                vec![]
                            },
                            wallet_storage_type: credential.wallet_storage_type.to_owned(),
                            layout_type: LayoutType::Card,
                            layout_properties: None,
                            schema_id: Some(schema_id),
                        },
                        organisation,
                        "",
                        "MDOC",
                        None,
                    )
                    .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                    if claims_specified {
                        let claims = map_offered_claims_to_credential_schema(
                            &credential_schema,
                            credential_id,
                            &claim_keys,
                        )?;

                        (claims, credential_schema)
                    } else {
                        let (claim_schemas, claims): (Vec<_>, Vec<_>) =
                            create_claims_from_credential_definition(credential_id, &claim_keys)?;

                        (
                            claims,
                            CredentialSchema {
                                claim_schemas: Some(claim_schemas),
                                ..credential_schema
                            },
                        )
                    }
                }
                _ => {
                    let credential_format = map_from_oidc_format_to_core(&credential.format)
                        .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                    let (claim_schemas, claims): (Vec<_>, Vec<_>) =
                        create_claims_from_credential_definition(credential_id, &claim_keys)?;

                    let now = OffsetDateTime::now_utc();
                    let credential_schema = CredentialSchema {
                        id: Uuid::new_v4().into(),
                        deleted_at: None,
                        created_date: now,
                        last_modified: now,
                        name: credential_schema_name,
                        format: credential_format,
                        wallet_storage_type: credential.wallet_storage_type.to_owned(),
                        revocation_method: "NONE".to_string(),
                        claim_schemas: Some(claim_schemas),
                        organisation: Some(organisation),
                        layout_type: LayoutType::Card,
                        layout_properties: None,
                        schema_type,
                        schema_id,
                    };

                    (claims, credential_schema)
                }
            };

            storage_access
                .create_credential_schema(credential_schema.clone())
                .await
                .map_err(ExchangeProtocolError::StorageAccessError)?;

            (claims, credential_schema)
        }
    };

    let credential = create_credential(credential_id, credential_schema, claims, interaction, None)
        .await
        .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

    Ok(InvitationResponseDTO::Credential {
        interaction_id,
        credentials: vec![credential],
    })
}

fn build_claim_keys(
    credential: &OpenID4VCICredentialOfferCredentialDTO,
) -> Result<HashMap<String, OpenID4VCICredentialValueDetails>, ExchangeProtocolError> {
    if let Some(credential_definition) = &credential.credential_definition {
        let credential_subject = credential_definition
            .credential_subject
            .as_ref()
            .ok_or_else(|| {
                ExchangeProtocolError::Failed("Missing credential subject".to_string())
            })?;

        return Ok(credential_subject.keys.to_owned());
    }

    if let Some(credential_claims) = credential.claims.as_ref() {
        return Ok(build_claims_keys_for_mdoc(credential_claims));
    }

    Err(ExchangeProtocolError::Failed(
        "Inconsistent credential offer missing both credential definition and claims fields"
            .to_string(),
    ))
}

fn build_claims_keys_for_mdoc(
    claims: &HashMap<String, OpenID4VCICredentialOfferClaim>,
) -> HashMap<String, OpenID4VCICredentialValueDetails> {
    fn build<'a>(
        normalized_claims: &mut HashMap<String, OpenID4VCICredentialValueDetails>,
        claims: &'a HashMap<String, OpenID4VCICredentialOfferClaim>,
        path: &mut Vec<&'a str>,
    ) {
        for (key, offer_claim) in claims {
            path.push(key);

            match &offer_claim.value {
                OpenID4VCICredentialOfferClaimValue::Nested(claims) => {
                    build(normalized_claims, claims, path);
                }
                OpenID4VCICredentialOfferClaimValue::String(value) => {
                    let key = path.join("/");

                    let value = OpenID4VCICredentialValueDetails {
                        value: value.to_owned(),
                        value_type: offer_claim.value_type.to_owned(),
                    };

                    normalized_claims.insert(key, value);
                }
            }

            path.pop();
        }
    }

    let mut claim_keys = HashMap::with_capacity(claims.len());
    let mut path = vec![];

    build(&mut claim_keys, claims, &mut path);

    claim_keys
}

fn find_schema_data(
    issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
    credential: &OpenID4VCICredentialOfferCredentialDTO,
) -> (String /* schema_id */, CredentialSchemaType) {
    if credential.format == "mso_mdoc" {
        // doctype is the schema_id for MDOC
        if let Some(doctype) = credential.doctype.to_owned() {
            return (doctype, CredentialSchemaType::Mdoc);
        }
    }

    let credential_schema = issuer_metadata
        .credentials_supported
        .first() // This is not interoperable, but since in this case we only try to detect our own schema, we know there's always only one
        .and_then(|credential| credential.credential_definition.as_ref())
        .and_then(|definition| definition.credential_schema.to_owned());

    match credential_schema {
        None => (
            Uuid::new_v4().to_string(),
            CredentialSchemaType::FallbackSchema2024,
        ),
        Some(schema) => (schema.id, schema.r#type.into()),
    }
}

async fn fetch_procivis_schema(
    schema_id: &str,
) -> Result<CredentialSchemaDetailResponseDTO, reqwest::Error> {
    reqwest::get(schema_id)
        .await?
        .error_for_status()?
        .json()
        .await
}

fn get_credential_schema_name(
    issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
    credential: &OpenID4VCICredentialOfferCredentialDTO,
) -> Result<String, ExchangeProtocolError> {
    let display_name = issuer_metadata
        .credentials_supported
        .first()
        .and_then(|credential| credential.display.as_ref())
        .and_then(|displays| displays.first())
        .map(|display| display.name.to_owned());

    let credential_schema_name = match display_name {
        Some(display_name) => display_name,
        // fallback to doctype for mdoc
        None if credential.format == "mso_mdoc" => {
            let doctype = credential
                .doctype
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed(
                    "docType not specified for MDOC".to_string(),
                ))?;

            doctype.to_owned()
        }
        // fallback to credential type for other formats
        None => {
            let credential_definition =
                credential.credential_definition.as_ref().ok_or_else(|| {
                    ExchangeProtocolError::Failed(format!(
                        "Missing credential definition for format: {}",
                        credential.format
                    ))
                })?;

            credential_definition
                .r#type
                .last()
                .ok_or_else(|| {
                    ExchangeProtocolError::Failed(
                        "Credential definition has no type specified".to_string(),
                    )
                })?
                .to_owned()
        }
    };

    Ok(credential_schema_name)
}

async fn create_and_store_interaction(
    storage_access: &StorageAccess,
    credential_issuer_endpoint: Url,
    data: Vec<u8>,
) -> Result<Interaction, ExchangeProtocolError> {
    let now = OffsetDateTime::now_utc();

    let interaction =
        interaction_from_handle_invitation(credential_issuer_endpoint, Some(data), now);

    let _ = storage_access
        .create_interaction(interaction.clone())
        .await
        .map_err(ExchangeProtocolError::StorageAccessError)?;

    Ok(interaction)
}

async fn create_credential(
    credential_id: CredentialId,
    credential_schema: CredentialSchema,
    claims: Vec<Claim>,
    interaction: Interaction,
    redirect_uri: Option<String>,
) -> Result<Credential, DataLayerError> {
    let now = OffsetDateTime::now_utc();

    Ok(Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "OPENID4VC".to_string(),
        redirect_uri,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Pending,
            suspend_end_date: None,
        }]),
        claims: Some(claims),
        issuer_did: None,
        holder_did: None,
        schema: Some(credential_schema),
        interaction: Some(interaction),
        revocation_list: None,
        key: None,
    })
}

async fn get_discovery_and_issuer_metadata(
    client: &reqwest::Client,
    credential_issuer_endpoint: Url,
) -> Result<
    (
        OpenID4VCIDiscoveryResponseDTO,
        OpenID4VCIIssuerMetadataResponseDTO,
    ),
    ExchangeProtocolError,
> {
    async fn fetch<T: DeserializeOwned>(
        client: &reqwest::Client,
        endpoint: impl reqwest::IntoUrl,
    ) -> Result<T, ExchangeProtocolError> {
        let response = client
            .get(endpoint)
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;

        response
            .json()
            .await
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)
    }

    let oicd_discovery = fetch(
        client,
        format!("{credential_issuer_endpoint}/.well-known/openid-configuration"),
    );
    let issuer_metadata = fetch(
        client,
        format!("{credential_issuer_endpoint}/.well-known/openid-credential-issuer"),
    );
    tokio::try_join!(oicd_discovery, issuer_metadata)
}

async fn interaction_data_from_query(
    query: &str,
    client: &reqwest::Client,
    allow_insecure_http_transport: bool,
) -> Result<OpenID4VPInteractionData, ExchangeProtocolError> {
    let mut interaction_data: OpenID4VPInteractionData = serde_qs::from_str(query)
        .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

    if interaction_data.client_metadata.is_some() && interaction_data.client_metadata_uri.is_some()
    {
        return Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata and client_metadata_uri cannot be set together".to_string(),
        ));
    }

    if interaction_data.presentation_definition.is_some()
        && interaction_data.presentation_definition_uri.is_some()
    {
        return Err(ExchangeProtocolError::InvalidRequest(
            "presentation_definition and presentation_definition_uri cannot be set together"
                .to_string(),
        ));
    }

    if let Some(client_metadata_uri) = &interaction_data.client_metadata_uri {
        if !allow_insecure_http_transport && client_metadata_uri.scheme() != "https" {
            return Err(ExchangeProtocolError::InvalidRequest(
                "client_metadata_uri must use HTTPS scheme".to_string(),
            ));
        }

        let client_metadata = client
            .get(client_metadata_uri.to_owned())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .await
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        interaction_data.client_metadata = Some(client_metadata);
    }

    if let Some(presentation_definition_uri) = &interaction_data.presentation_definition_uri {
        if !allow_insecure_http_transport && presentation_definition_uri.scheme() != "https" {
            return Err(ExchangeProtocolError::InvalidRequest(
                "presentation_definition_uri must use HTTPS scheme".to_string(),
            ));
        }

        let presentation_definition = client
            .get(presentation_definition_uri.to_owned())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .await
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        interaction_data.presentation_definition = Some(presentation_definition);
    }

    Ok(interaction_data)
}

async fn handle_proof_invitation(
    url: Url,
    allow_insecure_http_transport: bool,
    client: &reqwest::Client,
    storage_access: &StorageAccess,
) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
    let query = url.query().ok_or(ExchangeProtocolError::InvalidRequest(
        "Query cannot be empty".to_string(),
    ))?;

    let interaction_data =
        interaction_data_from_query(query, client, allow_insecure_http_transport).await?;
    validate_interaction_data(&interaction_data)?;
    let data = serialize_interaction_data(&interaction_data)?;

    let now = OffsetDateTime::now_utc();
    let interaction =
        create_and_store_interaction(storage_access, interaction_data.response_uri, data).await?;

    let interaction_id = interaction.id.to_owned();

    let proof_id = Uuid::new_v4().into();
    let proof = proof_from_handle_invitation(
        &proof_id,
        "OPENID4VC",
        interaction_data.redirect_uri,
        None,
        interaction,
        now,
        None,
        "HTTP",
    );

    Ok(InvitationResponseDTO::ProofRequest {
        interaction_id,
        proof: Box::new(proof),
    })
}
