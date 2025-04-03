use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use mappers::map_credential_formats_to_presentation_format;
use one_crypto::utilities;
use shared_types::KeyId;
use time::{Duration, OffsetDateTime};
use url::Url;
use utils::{
    deserialize_interaction_data, interaction_data_from_query, serialize_interaction_data,
    validate_interaction_data,
};
use uuid::Uuid;

use super::mapper::{
    create_open_id_for_vp_presentation_definition, create_open_id_for_vp_sharing_url_encoded,
    create_presentation_submission,
};
use super::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, ClientIdScheme,
    InvitationResponseDTO, JwePayload, OpenID4VPClientMetadataJwkDTO,
    OpenID4VPDirectPostResponseDTO, OpenID4VPHolderInteractionData,
    OpenID4VPVerifierInteractionContent, OpenID4VpParams, OpenID4VpPresentationFormat,
    PresentationSubmissionMappingDTO, PresentedCredential, ShareResponse, UpdateResponse,
};
use super::{FormatMapper, StorageAccess, TypeToDescriptorMapper, VerificationProtocolError};
use crate::model::did::Did;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::provider::credential_formatter::model::FormatPresentationCtx;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::mapper::{
    interaction_from_handle_invitation, proof_from_handle_invitation,
};
use crate::provider::verification_protocol::openid4vc::openidvc_http::jwe_presentation::ec_key_from_metadata;
use crate::provider::verification_protocol::openid4vc::openidvc_http::mdoc::mdoc_presentation_context;
use crate::service::key::dto::PublicKeyJwkDTO;

mod jwe_presentation;
pub mod mappers;
mod utils;
mod x509;

mod mdoc;
#[cfg(test)]
mod test;

const PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY: &str = "presentation_definition";
const PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY: &str = "presentation_definition_uri";
const REQUEST_URI_QUERY_PARAM_KEY: &str = "request_uri";
const REQUEST_QUERY_PARAM_KEY: &str = "request";

pub(crate) struct OpenID4VCHTTP {
    client: Arc<dyn HttpClient>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    base_url: Option<String>,
    params: OpenID4VpParams,
}

#[allow(clippy::too_many_arguments)]
impl OpenID4VCHTTP {
    pub(crate) fn new(
        base_url: Option<String>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        client: Arc<dyn HttpClient>,
        params: OpenID4VpParams,
    ) -> Self {
        Self {
            base_url,
            formatter_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            client,
            params,
        }
    }

    pub(crate) fn can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.params.url_scheme == url.scheme()
            && (query_has_key(PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY)
                || query_has_key(PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY)
                || query_has_key(REQUEST_URI_QUERY_PARAM_KEY)
                || query_has_key(REQUEST_QUERY_PARAM_KEY))
    }

    pub(crate) async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        if !self.can_handle(&url) {
            return Err(VerificationProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ));
        }

        handle_proof_invitation(
            url,
            self.params.allow_insecure_http_transport,
            &self.client,
            storage_access,
            Some(organisation),
            &self.key_algorithm_provider,
            &self.did_method_provider,
            &self.params,
        )
        .await
    }

    pub(crate) async fn holder_reject_proof(
        &self,
        _proof: &Proof,
    ) -> Result<(), VerificationProtocolError> {
        Err(VerificationProtocolError::OperationNotSupported)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .to_owned();

        let interaction_data: OpenID4VPHolderInteractionData =
            deserialize_interaction_data(interaction.data)?;

        let tokens: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.presentation.to_owned())
            .collect();

        let (format, oidc_format) =
            map_credential_formats_to_presentation_format(&credential_presentations)?;

        let presentation_formatter = self
            .formatter_provider
            .get_formatter(&format)
            .ok_or_else(|| VerificationProtocolError::Failed("Formatter not found".to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(
                &key.to_owned(),
                jwk_key_id,
                self.key_algorithm_provider.clone(),
            )
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let presentation_definition_id = interaction_data
            .presentation_definition
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "presentation_definition is None".to_string(),
            ))?
            .id
            .to_owned();

        let token_formats: Vec<_> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.credential_schema.format.to_owned())
            .collect();

        let presentation_submission = create_presentation_submission(
            presentation_definition_id,
            credential_presentations,
            &oidc_format,
        )?;

        let response_uri =
            interaction_data
                .response_uri
                .clone()
                .ok_or(VerificationProtocolError::Failed(
                    "response_uri is None".to_string(),
                ))?;
        let verifier_nonce =
            interaction_data
                .nonce
                .clone()
                .ok_or(VerificationProtocolError::Failed(
                    "nonce is None".to_string(),
                ))?;

        let holder_nonce = utilities::generate_nonce();
        let ctx = if format == "MDOC" {
            mdoc_presentation_context(
                &interaction_data,
                &response_uri,
                &verifier_nonce,
                &holder_nonce,
            )?
        } else {
            FormatPresentationCtx {
                nonce: Some(verifier_nonce.clone()),
                token_formats: Some(token_formats),
                ..Default::default()
            }
        };
        let vp_token = presentation_formatter
            .format_presentation(&tokens, &holder_did.did, &key.key_type, auth_fn, ctx)
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let encryption_info = self
            .encryption_info_from_metadata(&interaction_data)
            .await?;
        if encryption_info.is_none() && format == "MDOC" {
            return Err(VerificationProtocolError::Failed(
                "MDOC presentation requires encryption but no verifier EC keys are available"
                    .to_string(),
            ));
        }
        let params = if let Some((verifier_key, alg)) = encryption_info {
            encrypted_params(
                interaction_data,
                presentation_submission,
                &holder_nonce,
                vp_token,
                verifier_key,
                alg,
                &*self.key_algorithm_provider,
            )
            .await?
        } else {
            unencrypted_params(interaction_data, &presentation_submission, vp_token)?
        };

        let response = self
            .client
            .post(response_uri.as_str())
            .form(&params)
            .context("form error")
            .map_err(VerificationProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(VerificationProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(VerificationProtocolError::Transport)?;

        let response: Result<OpenID4VPDirectPostResponseDTO, _> = response.json();

        if let Ok(value) = response {
            Ok(UpdateResponse {
                update_proof: Some(UpdateProofRequest {
                    redirect_uri: Some(value.redirect_uri),
                    ..Default::default()
                }),
            })
        } else {
            Ok(UpdateResponse { update_proof: None })
        }
    }

    async fn encryption_info_from_metadata(
        &self,
        interaction_data: &OpenID4VPHolderInteractionData,
    ) -> Result<
        Option<(
            OpenID4VPClientMetadataJwkDTO,
            AuthorizationEncryptedResponseContentEncryptionAlgorithm,
        )>,
        VerificationProtocolError,
    > {
        let Some(mut client_metadata) = interaction_data.client_metadata.clone() else {
            // metadata_uri (if any) has been resolved before, no need to check
            return Ok(None);
        };

        if !matches!(
            client_metadata.authorization_encrypted_response_alg,
            Some(AuthorizationEncryptedResponseAlgorithm::EcdhEs)
        ) {
            // Encrypted presentations not supported
            return Ok(None);
        }

        let encryption_alg = match client_metadata.authorization_encrypted_response_enc.clone() {
            // Encrypted presentations not supported
            None => return Ok(None),
            Some(alg) => alg,
        };

        if client_metadata.jwks.keys.is_empty() {
            if let Some(ref uri) = client_metadata.jwks_uri {
                let jwks = self
                    .client
                    .get(uri)
                    .send()
                    .await
                    .context("send error")
                    .map_err(VerificationProtocolError::Transport)?
                    .error_for_status()
                    .context("status error")
                    .map_err(VerificationProtocolError::Transport)?;

                client_metadata.jwks = jwks
                    .json()
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
            }
        }
        let Some(verifier_key) = ec_key_from_metadata(client_metadata) else {
            return Ok(None);
        };
        Ok(Some((verifier_key, encryption_alg)))
    }

    pub(crate) async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper, // Credential schema format to format type mapper
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
        client_id_scheme: ClientIdScheme,
    ) -> Result<ShareResponse<OpenID4VPVerifierInteractionContent>, VerificationProtocolError> {
        let interaction_id = Uuid::new_v4();

        // Pass the expected presentation content to interaction for verification
        let presentation_definition = create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof,
            type_to_descriptor,
            format_to_type_mapper,
            &*self.formatter_provider,
        )?;

        let Some(base_url) = &self.base_url else {
            return Err(VerificationProtocolError::Failed("Missing base_url".into()));
        };
        let response_uri = format!("{base_url}/ssi/oidc-verifier/v1/response");
        let nonce = utilities::generate_alphanumeric(32);

        let client_id = match client_id_scheme {
            ClientIdScheme::RedirectUri | ClientIdScheme::VerifierAttestation => {
                response_uri.to_owned()
            }
            ClientIdScheme::X509SanDns => {
                let base_url = Url::parse(base_url)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

                base_url
                    .domain()
                    .ok_or(VerificationProtocolError::Failed(
                        "Invalid base_url".to_string(),
                    ))?
                    .to_string()
            }
            ClientIdScheme::Did => proof
                .verifier_did
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "proof is missing verifier_did, required for did client_id_scheme".to_string(),
                ))?
                .did
                .to_string(),
        };

        let interaction_content = OpenID4VPVerifierInteractionContent {
            nonce: nonce.to_owned(),
            presentation_definition,
            client_id: client_id.to_owned(),
            client_id_scheme: Some(client_id_scheme),
            response_uri: Some(response_uri),
        };

        let encoded_offer = create_open_id_for_vp_sharing_url_encoded(
            base_url,
            &self.params,
            client_id,
            interaction_id,
            &interaction_content,
            nonce,
            proof,
            key_id,
            encryption_key_jwk,
            vp_formats,
            client_id_scheme,
            &self.key_algorithm_provider,
            &*self.key_provider,
            &*self.did_method_provider,
        )
        .await?;

        Ok(ShareResponse {
            url: format!("{}://?{encoded_offer}", self.params.url_scheme),
            interaction_id,
            context: interaction_content,
        })
    }
}

fn unencrypted_params(
    interaction_data: OpenID4VPHolderInteractionData,
    presentation_submission: &PresentationSubmissionMappingDTO,
    vp_token: String,
) -> Result<HashMap<&'static str, String>, VerificationProtocolError> {
    let mut params: HashMap<&str, String> = HashMap::new();
    params.insert("vp_token", vp_token);
    params.insert(
        "presentation_submission",
        serde_json::to_string(&presentation_submission)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
    );

    if let Some(state) = interaction_data.state {
        params.insert("state", state);
    }
    Ok(params)
}

async fn encrypted_params(
    interaction_data: OpenID4VPHolderInteractionData,
    presentation_submission: PresentationSubmissionMappingDTO,
    holder_nonce: &str,
    vp_token: String,
    verifier_key: OpenID4VPClientMetadataJwkDTO,
    encryption_algorithm: AuthorizationEncryptedResponseContentEncryptionAlgorithm,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<HashMap<&'static str, String>, VerificationProtocolError> {
    let aud = interaction_data
        .response_uri
        .ok_or(VerificationProtocolError::Failed(
            "response_uri is None".to_string(),
        ))?;
    let verifier_nonce = interaction_data
        .nonce
        .ok_or(VerificationProtocolError::Failed(
            "nonce is None".to_string(),
        ))?;
    let payload = JwePayload {
        aud,
        exp: OffsetDateTime::now_utc() + Duration::minutes(10),
        vp_token,
        presentation_submission,
        state: interaction_data.state,
    };

    let response = jwe_presentation::build_jwe(
        payload,
        verifier_key,
        holder_nonce,
        &verifier_nonce,
        encryption_algorithm,
        key_algorithm_provider,
    )
    .await
    .map_err(|err| {
        VerificationProtocolError::Failed(format!("Failed to build mdoc response jwe: {err}"))
    })?;
    Ok(HashMap::from_iter([("response", response)]))
}

#[allow(clippy::too_many_arguments)]
async fn handle_proof_invitation(
    url: Url,
    allow_insecure_http_transport: bool,
    client: &Arc<dyn HttpClient>,
    storage_access: &StorageAccess,
    organisation: Option<Organisation>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    params: &OpenID4VpParams,
) -> Result<InvitationResponseDTO, VerificationProtocolError> {
    let query = url
        .query()
        .ok_or(VerificationProtocolError::InvalidRequest(
            "Query cannot be empty".to_string(),
        ))?;

    let interaction_data = interaction_data_from_query(
        query,
        client,
        allow_insecure_http_transport,
        key_algorithm_provider,
        did_method_provider,
        params,
    )
    .await?;
    validate_interaction_data(&interaction_data)?;
    let data = serialize_interaction_data(&interaction_data)?;

    let now = OffsetDateTime::now_utc();
    let interaction = create_and_store_interaction(
        storage_access,
        interaction_data
            .response_uri
            .ok_or(VerificationProtocolError::Failed(
                "response_uri is None".to_string(),
            ))?,
        data,
        organisation,
    )
    .await?;

    let interaction_id = interaction.id.to_owned();

    let proof_id = Uuid::new_v4().into();
    let proof = proof_from_handle_invitation(
        &proof_id,
        "OPENID4VP_DRAFT20",
        interaction_data.redirect_uri,
        None,
        interaction,
        now,
        None,
        "HTTP",
        ProofStateEnum::Requested,
    );

    Ok(InvitationResponseDTO {
        interaction_id,
        proof,
    })
}

async fn create_and_store_interaction(
    storage_access: &StorageAccess,
    credential_issuer_endpoint: Url,
    data: Vec<u8>,
    organisation: Option<Organisation>,
) -> Result<Interaction, VerificationProtocolError> {
    let now = OffsetDateTime::now_utc();

    let interaction = interaction_from_handle_invitation(
        credential_issuer_endpoint,
        Some(data),
        now,
        organisation,
    );

    storage_access
        .create_interaction(interaction.clone())
        .await
        .map_err(VerificationProtocolError::StorageAccessError)?;

    Ok(interaction)
}
