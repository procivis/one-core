use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
pub use mappers::create_presentation_submission;
use mappers::presentation_definition_from_interaction_data;
use one_crypto::utilities;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use shared_types::{CredentialId, KeyId};
use time::{Duration, OffsetDateTime};
use url::Url;
use utils::{
    deserialize_interaction_data, interaction_data_from_query, serialize_interaction_data,
    validate_interaction_data,
};
use uuid::Uuid;

use super::mapper::{
    create_credential, create_open_id_for_vp_presentation_definition,
    create_open_id_for_vp_sharing_url_encoded, get_claim_name_by_json_path,
    get_credential_offer_url, interaction_from_handle_invitation,
    map_offered_claims_to_credential_schema, proof_from_handle_invitation,
};
use super::model::{
    DatatypeType, HolderInteractionData, InvitationResponseDTO, JwePayload, OpenID4VCICredential,
    OpenID4VCICredentialDefinition, OpenID4VCICredentialOfferClaim,
    OpenID4VCICredentialOfferCredentialDTO, OpenID4VCICredentialOfferDTO,
    OpenID4VCICredentialValueDetails, OpenID4VCIDiscoveryResponseDTO,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCIProof, OpenID4VCITokenRequestDTO,
    OpenID4VCITokenResponseDTO, OpenID4VCInteractionContent, OpenID4VPDirectPostResponseDTO,
    OpenID4VPFormat, OpenID4VPInteractionContent, OpenID4VPInteractionData, PresentedCredential,
    ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use super::proof_formatter::OpenID4VCIProofJWTFormatter;
use super::service::{
    create_credential_offer, credentials_format, FnMapExternalFormatToExternalDetailed,
};
use super::{
    ExchangeProtocolError, ExchangeProtocolImpl, FormatMapper, HandleInvitationOperationsAccess,
    StorageAccess, TypeToDescriptorMapper,
};
use crate::model::credential::{Credential, UpdateCredentialRequest};
use crate::model::credential_schema::UpdateCredentialSchemaRequest;
use crate::model::did::{Did, DidType};
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    OID4VPHandover, SessionTranscript,
};
use crate::provider::credential_formatter::model::{DetailCredential, FormatPresentationCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, CredentialGroupItem, PresentationDefinitionResponseDTO,
};
use crate::provider::exchange_protocol::iso_mdl::common::to_cbor;
use crate::provider::exchange_protocol::mapper::get_relevant_credentials_to_credential_schemas;
use crate::provider::exchange_protocol::openid4vc::model::OpenID4VCICredentialOfferClaimValue;
use crate::provider::exchange_protocol::openid4vc::validator::throw_if_latest_proof_state_not_eq;
use crate::provider::http_client::HttpClient;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::service::key::dto::PublicKeyJwkDTO;

pub mod mappers;
mod mdoc;
mod utils;

#[cfg(test)]
mod test;

const CREDENTIAL_OFFER_URL_SCHEME: &str = "openid-credential-offer";
const CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY: &str = "credential_offer";
const CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY: &str = "credential_offer_uri";
const PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY: &str = "presentation_definition";
const PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY: &str = "presentation_definition_uri";

pub struct OpenID4VCHTTP {
    client: Arc<dyn HttpClient>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    base_url: Option<String>,
    params: OpenID4VCParams,
}

enum InvitationType {
    CredentialIssuance,
    ProofRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCParams {
    pub pre_authorized_code_expires_in: u64,
    pub token_expires_in: u64,
    pub refresh_expires_in: u64,
    pub credential_offer_by_value: Option<bool>,
    pub client_metadata_by_value: Option<bool>,
    pub presentation_definition_by_value: Option<bool>,
    pub allow_insecure_http_transport: Option<bool>,
}

impl OpenID4VCHTTP {
    pub fn new(
        base_url: Option<String>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        client: Arc<dyn HttpClient>,
        params: OpenID4VCParams,
    ) -> Self {
        Self {
            base_url,
            formatter_provider,
            revocation_provider,
            key_provider,
            client,
            params,
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
            return Some(InvitationType::ProofRequest);
        }

        None
    }
}

#[async_trait]
impl ExchangeProtocolImpl for OpenID4VCHTTP {
    type VCInteractionContext = OpenID4VCInteractionContent;
    type VPInteractionContext = OpenID4VPInteractionContent;

    fn can_handle(&self, url: &Url) -> bool {
        self.detect_invitation_type(url).is_some()
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        let invitation_type =
            self.detect_invitation_type(&url)
                .ok_or(ExchangeProtocolError::Failed(
                    "No OpenID4VC query params detected".to_string(),
                ))?;

        match invitation_type {
            InvitationType::CredentialIssuance => {
                handle_credential_invitation(
                    url,
                    organisation,
                    &self.client,
                    storage_access,
                    handle_invitation_operations,
                )
                .await
            }
            InvitationType::ProofRequest => {
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
        // LOCAL_CREDENTIAL_FORMAT -> oidc_vc_format
        format_map: HashMap<String, String>,
        // oidc_vp_format -> LOCAL_PRESENTATION_FORMAT
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        let interaction_data: OpenID4VPInteractionData =
            deserialize_interaction_data(proof.interaction.as_ref())?;

        let tokens: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.presentation.to_owned())
            .collect();

        let formats: HashMap<&str, &str> = credential_presentations
            .iter()
            .map(|presented_credential| {
                format_map
                    .get(presented_credential.credential_schema.format.as_str())
                    .map(|mapped| {
                        (
                            mapped.as_str(),
                            presented_credential.credential_schema.format.as_str(),
                        )
                    })
            })
            .collect::<Option<_>>()
            .ok_or_else(|| ExchangeProtocolError::Failed("missing format mapping".into()))?;

        let (format, oidc_format) = if let Some(&value) = formats.get("mso_mdoc") {
            if formats.len() > 1 {
                return Err(ExchangeProtocolError::Failed(
                    "Currently for a proof MDOC cannot be used with other formats".to_string(),
                ));
            };

            (value.to_owned(), "mso_mdoc".to_owned())
        } else if let Some(&value) = formats.get("ldp_vc") {
            (value.to_owned(), "ldp_vp".to_owned())
        } else {
            format_map
                .iter()
                .find(|(_, v)| v.as_str() == "jwt_vc_json" || v.as_str() == "vc+sd-jwt")
                .map(|(k, _)| (k.to_owned(), "jwt_vp_json".to_owned()))
                .ok_or_else(|| {
                    ExchangeProtocolError::Failed("no jwt_vp_json format in map".into())
                })?
        };

        let presentation_format =
            presentation_format_map
                .get(&oidc_format)
                .ok_or(ExchangeProtocolError::Failed(format!(
                    "Missing presentation format for `{oidc_format}`"
                )))?;

        let presentation_formatter = self
            .formatter_provider
            .get_formatter(presentation_format)
            .ok_or_else(|| ExchangeProtocolError::Failed("Formatter not found".to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.to_owned(), jwk_key_id)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let presentation_definition_id = interaction_data
            .presentation_definition
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "presentation_definition is None".to_string(),
            ))?
            .id;

        let token_formats: Vec<_> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.credential_schema.format.to_owned())
            .collect();

        let presentation_submission = create_presentation_submission(
            presentation_definition_id,
            credential_presentations,
            &oidc_format,
            format_map.clone(),
        )?;

        let response_uri = interaction_data.response_uri.clone();
        let mut params: HashMap<&str, String> = HashMap::new();

        if format == "MDOC" {
            let mdoc_generated_nonce = utilities::generate_nonce();

            let ctx = FormatPresentationCtx {
                mdoc_session_transcript: Some(
                    to_cbor(&SessionTranscript {
                        handover: OID4VPHandover::compute(
                            &interaction_data.client_id,
                            &interaction_data.response_uri,
                            &interaction_data.nonce,
                            &mdoc_generated_nonce,
                        )
                        .into(),
                        device_engagement_bytes: None,
                        e_reader_key_bytes: None,
                    })
                    .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?,
                ),
                ..Default::default()
            };

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
                .format_presentation(&tokens, &holder_did.did, &key.key_type, auth_fn, ctx)
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
                token_formats: Some(token_formats),
                vc_format_map: format_map,
                ..Default::default()
            };

            let vp_token = presentation_formatter
                .format_presentation(&tokens, &holder_did.did, &key.key_type, auth_fn, ctx)
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
            .post(response_uri.as_str())
            .form(&params)
            .context("form error")
            .map_err(ExchangeProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;

        let response: Result<OpenID4VPDirectPostResponseDTO, _> = response.json();

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
        credential_format: &str,
        storage_access: &StorageAccess,
        map_external_format_to_external_detailed: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        let schema = credential
            .schema
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed("schema is None".to_string()))?;

        let interaction_data: HolderInteractionData =
            deserialize_interaction_data(credential.interaction.as_ref())?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.to_owned(), jwk_key_id)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url,
            &holder_did.clone(),
            key.key_type.to_owned(),
            auth_fn,
        )
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let (credential_definition, doctype) = match credential_format {
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
            format: credential_format.to_owned(),
            credential_definition,
            doctype,
            proof: OpenID4VCIProof {
                proof_type: "jwt".to_string(),
                jwt: proof_jwt,
            },
        };

        let response = self
            .client
            .post(interaction_data.credential_endpoint.as_str())
            .bearer_auth(&interaction_data.access_token)
            .json(&body)
            .context("json error")
            .map_err(ExchangeProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response = response
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response_value: SubmitIssuerResponse = response
            .json()
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        let real_format =
            map_external_format_to_external_detailed(&schema.format, &response_value.credential)
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

        let layout = schema.layout_properties.clone();

        let (layout_type, layout_properties) = if let (None, Some(metadata)) = (
            layout,
            response_credential
                .credential_schema
                .and_then(|schema| schema.metadata),
        ) {
            (Some(metadata.layout_type), Some(metadata.layout_properties))
        } else {
            (None, None)
        };

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
            .get_did_by_value(&issuer_did_value)
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
                    _other => {
                        //tracing::warn!("Unmapped did-method for issuer did: {other}");
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
                        did: issuer_did_value,
                        did_type: DidType::Remote,
                        did_method: did_method.to_string(),
                        keys: None,
                        deactivated: false,
                        organisation: schema.organisation.clone(),
                    }),
                )
            }
        };

        let redirect_uri = response_value.redirect_uri.clone();

        Ok(UpdateResponse {
            result: response_value,
            update_proof: None,
            create_did,
            update_credential_schema: Some(UpdateCredentialSchemaRequest {
                id: schema.id,
                revocation_method,
                format: Some(real_format),
                claim_schemas: None,
                layout_type,
                layout_properties,
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

    async fn validate_proof_for_submission(
        &self,
        proof: &Proof,
    ) -> Result<(), ExchangeProtocolError> {
        throw_if_latest_proof_state_not_eq(proof, ProofStateEnum::Pending)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
    }

    async fn share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
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

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "credential schema missing".to_string(),
            ))?;

        let wallet_storage_type = credential_schema.wallet_storage_type.clone();

        let claims = credential
            .claims
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed("Missing claims".to_owned()))?
            .iter()
            .map(|claim| claim.to_owned())
            .collect::<Vec<_>>();

        let credentials = credentials_format(wallet_storage_type, credential_format, &claims)
            .map_err(|e| ExchangeProtocolError::Other(e.into()))?;

        let url = self
            .base_url
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed("Missing base_url".to_owned()))?;

        if self
            .params
            .credential_offer_by_value
            .is_some_and(|by_value| by_value)
        {
            let offer = create_credential_offer(
                url,
                &interaction_id.to_string(),
                &credential_schema.id,
                credentials,
            )
            .map_err(|e| ExchangeProtocolError::Other(e.into()))?;

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
        format_to_type_mapper: FormatMapper, // Credential schema format to format type mapper
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        let interaction_id = Uuid::new_v4();

        // Pass the expected presentation content to interaction for verification
        let presentation_definition = create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof,
            type_to_descriptor.clone(),
            format_to_type_mapper.clone(),
        )?;

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
            key_id,
            encryption_key_jwk,
            vp_formats,
            type_to_descriptor,
            format_to_type_mapper,
        )?;

        Ok(ShareResponse {
            url: format!("openid4vp://?{encoded_offer}"),
            id: interaction_id,
            context: interaction_content,
        })
    }

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
        _interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
        types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let presentation_definition =
            deserialize_interaction_data::<OpenID4VPInteractionData>(proof.interaction.as_ref())?
                .presentation_definition
                .ok_or(ExchangeProtocolError::Failed(
                    "presentation_definition is None".to_string(),
                ))?;

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

        let allowed_schema_formats: HashSet<_> = allowed_oidc_formats
            .iter()
            .map(|oidc_format| {
                format_map
                    .get(oidc_format)
                    .ok_or_else(|| {
                        ExchangeProtocolError::Failed(format!("unknown format {oidc_format}"))
                    })
                    .map(String::as_str)
            })
            .collect::<Result<_, _>>()?;

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
            &types,
        )
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    async fn retract_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        Ok(())
    }
}

async fn handle_credential_invitation(
    invitation_url: Url,
    organisation: Organisation,
    client: &Arc<dyn HttpClient>,
    storage_access: &StorageAccess,
    handle_invitation_operations: &HandleInvitationOperationsAccess,
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
        .context("form error")
        .map_err(ExchangeProtocolError::Transport)?
        .send()
        .await
        .context("send error")
        .map_err(ExchangeProtocolError::Transport)?
        .error_for_status()
        .context("status error")
        .map_err(ExchangeProtocolError::Transport)?
        .json()
        .context("parsing error")
        .map_err(ExchangeProtocolError::Transport)?;

    // OID4VC credential offer query param should always contain one credential for the moment
    let credential: &OpenID4VCICredentialOfferCredentialDTO =
        credential_offer.credentials.first().ok_or_else(|| {
            ExchangeProtocolError::Failed("Credential offer is missing credentials".to_string())
        })?;

    let credential_schema_name = handle_invitation_operations
        .get_credential_schema_name(&issuer_metadata, credential)
        .await?;

    let schema_data = handle_invitation_operations
        .find_schema_data(&issuer_metadata, credential)
        .await;

    let holder_data = HolderInteractionData {
        issuer_url: issuer_metadata.credential_issuer.clone(),
        credential_endpoint: issuer_metadata.credential_endpoint.clone(),
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

    let claim_keys: HashMap<String, OpenID4VCICredentialValueDetails> =
        build_claim_keys(credential)?;

    let credential_id: CredentialId = Uuid::new_v4().into();
    let (claims, credential_schema) = match storage_access
        .get_schema(
            &schema_data.schema_id,
            &schema_data.schema_type,
            organisation.id,
        )
        .await
        .map_err(ExchangeProtocolError::StorageAccessError)?
    {
        Some(credential_schema) => {
            if credential_schema.schema_type.to_string() != schema_data.schema_type {
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
            let response = handle_invitation_operations
                .create_new_schema(
                    &schema_data,
                    &claim_keys,
                    &credential_id,
                    credential,
                    &issuer_metadata,
                    &credential_schema_name,
                    organisation,
                )
                .await?;
            (response.claims, response.schema)
        }
    };

    let credential = create_credential(credential_id, credential_schema, claims, interaction, None);

    Ok(InvitationResponseDTO::Credential {
        interaction_id,
        credentials: vec![credential],
    })
}

async fn resolve_credential_offer(
    client: &Arc<dyn HttpClient>,
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
            .get(credential_offer_url.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
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

async fn handle_proof_invitation(
    url: Url,
    allow_insecure_http_transport: bool,
    client: &Arc<dyn HttpClient>,
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

async fn get_discovery_and_issuer_metadata(
    client: &Arc<dyn HttpClient>,
    credential_issuer_endpoint: Url,
) -> Result<
    (
        OpenID4VCIDiscoveryResponseDTO,
        OpenID4VCIIssuerMetadataResponseDTO,
    ),
    ExchangeProtocolError,
> {
    async fn fetch<T: DeserializeOwned>(
        client: &Arc<dyn HttpClient>,
        endpoint: String,
    ) -> Result<T, ExchangeProtocolError> {
        client
            .get(&endpoint)
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
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

pub fn build_claims_keys_for_mdoc(
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
