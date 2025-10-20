use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use futures::future::BoxFuture;
use mappers::create_openidvp20_authorization_request;
use model::OpenID4Vp20Params;
use one_crypto::utilities;
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use url::Url;
use utils::{interaction_data_from_openid4vp_20_query, validate_interaction_data};
use uuid::Uuid;

use super::jwe_presentation::{self, ec_key_from_metadata};
use super::mapper::{
    explode_validity_credentials, key_and_did_from_formatted_creds,
    map_presented_credentials_to_presentation_format_type,
};
use super::mdoc::{mdoc_draft_handover, mdoc_presentation_context};
use crate::config::core_config::{
    CoreConfig, DidType, FormatType, IdentifierType, TransportType, VerificationProtocolType,
};
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::proto::certificate_validator::CertificateValidator;
use crate::provider::credential_formatter::model::{DetailCredential, HolderBindingCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, FormatPresentationCtx, FormattedPresentation,
};
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::verification_protocol::dto::{
    FormattedCredentialPresentation, InvitationResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::mapper::{
    interaction_from_handle_invitation, proof_from_handle_invitation,
};
use crate::provider::verification_protocol::openid4vp::mapper::{
    create_open_id_for_vp_presentation_definition, create_presentation_submission,
    generate_client_metadata_draft,
};
use crate::provider::verification_protocol::openid4vp::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, ClientIdScheme, JwePayload,
    OpenID4VPClientMetadata, OpenID4VPClientMetadataJwkDTO, OpenID4VPDirectPostResponseDTO,
    OpenID4VPHolderInteractionData, OpenID4VPVerifierInteractionContent, PexSubmission,
    PresentationSubmissionMappingDTO, VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::{
    FormatMapper, StorageAccess, TypeToDescriptorMapper, VerificationProtocolError,
    get_client_id_scheme,
};
use crate::provider::verification_protocol::{
    VerificationProtocol, deserialize_interaction_data, serialize_interaction_data,
};
use crate::service::oid4vp_draft20::proof_request::generate_authorization_request_params_draft20;
use crate::service::proof::dto::ShareProofRequestParamsDTO;

pub mod mappers;
pub(crate) mod model;
mod utils;

#[cfg(test)]
mod test;

const PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY: &str = "presentation_definition";
const CLIENT_ID_SCHEME_QUERY_PARAM_KEY: &str = "client_id_scheme";
const PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY: &str = "presentation_definition_uri";
const REQUEST_URI_QUERY_PARAM_KEY: &str = "request_uri";
const REQUEST_QUERY_PARAM_KEY: &str = "request";

pub(crate) struct OpenID4VP20HTTP {
    client: Arc<dyn HttpClient>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    base_url: Option<String>,
    params: OpenID4Vp20Params,
    config: Arc<CoreConfig>,
}

impl OpenID4VP20HTTP {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        base_url: Option<String>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        client: Arc<dyn HttpClient>,
        params: OpenID4Vp20Params,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            base_url,
            credential_formatter_provider,
            presentation_formatter_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            certificate_validator,
            client,
            params,
            config,
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
        let Some(OpenID4VPClientMetadata::Draft(mut client_metadata)) =
            interaction_data.client_metadata.clone()
        else {
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

        if client_metadata
            .jwks
            .as_ref()
            .map(|jwks| jwks.keys.is_empty())
            .unwrap_or(true)
            && let Some(ref uri) = client_metadata.jwks_uri
        {
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
        let Some(verifier_key) = ec_key_from_metadata(client_metadata.into()) else {
            return Ok(None);
        };
        Ok(Some((verifier_key, encryption_alg)))
    }
}

#[allow(clippy::too_many_arguments)]
#[async_trait::async_trait]
impl VerificationProtocol for OpenID4VP20HTTP {
    async fn retract_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        Ok(())
    }
    fn holder_can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.params.url_scheme == url.scheme()
            && query_has_key(CLIENT_ID_SCHEME_QUERY_PARAM_KEY)
            && (query_has_key(PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY)
                || query_has_key(PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY)
                || query_has_key(REQUEST_URI_QUERY_PARAM_KEY)
                || query_has_key(REQUEST_QUERY_PARAM_KEY))
    }

    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        context: serde_json::Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        let interaction_data: OpenID4VPHolderInteractionData =
            serde_json::from_value(context).map_err(VerificationProtocolError::JsonError)?;

        let presentation_definition =
            interaction_data
                .presentation_definition
                .ok_or(VerificationProtocolError::Failed(
                    "Presentation definition not found".to_string(),
                ))?;

        super::get_presentation_definition_with_local_credentials(
            presentation_definition,
            proof,
            interaction_data.client_metadata,
            storage_access,
            &self.config,
        )
        .await
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        let did_methods = vec![DidType::Key, DidType::Jwk, DidType::Web, DidType::WebVh];
        let mut verifier_identifier_types = HashSet::new();
        let schemes = &self.params.verifier.supported_client_id_schemes;

        if [
            ClientIdScheme::Did,
            ClientIdScheme::RedirectUri,
            ClientIdScheme::VerifierAttestation,
        ]
        .iter()
        .any(|scheme| schemes.contains(scheme))
        {
            verifier_identifier_types.insert(IdentifierType::Did);
        }

        if schemes.contains(&ClientIdScheme::X509SanDns) {
            verifier_identifier_types.insert(IdentifierType::Certificate);
        }

        VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Http],
            did_methods,
            verifier_identifier_types: verifier_identifier_types.into_iter().collect(),
            supported_presentation_definition: vec![PresentationDefinitionVersion::V1],
        }
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError> {
        todo!()
    }

    fn holder_get_holder_binding_context(
        &self,
        _proof: &Proof,
        context: serde_json::Value,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError> {
        let interaction_data: OpenID4VPHolderInteractionData =
            serde_json::from_value(context).map_err(VerificationProtocolError::JsonError)?;

        Ok(Some(HolderBindingCtx {
            nonce: interaction_data
                .nonce
                .ok_or(VerificationProtocolError::Failed(
                    "missing nonce".to_string(),
                ))?,
            audience: interaction_data.client_id,
        }))
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        _transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        if !self.holder_can_handle(&url) {
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
            &self.certificate_validator,
            &self.params,
        )
        .await
    }

    async fn holder_reject_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        // Rejection not supported and handled as no-op on holder side
        Ok(())
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        let (key, jwk_key_id, did) = key_and_did_from_formatted_creds(&credential_presentations)?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .to_owned();

        let credential_presentations = explode_validity_credentials(credential_presentations);
        let interaction_data: OpenID4VPHolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let format = map_presented_credentials_to_presentation_format_type(
            &credential_presentations,
            &self.config,
        )?;

        let presentation_formatter = self
            .presentation_formatter_provider
            .get_presentation_formatter(&format.to_string())
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

        let holder_nonce = utilities::generate_alphanumeric(32);
        let ctx = if format == FormatType::Mdoc {
            mdoc_presentation_context(mdoc_draft_handover(
                &interaction_data.client_id,
                &response_uri,
                &verifier_nonce,
                &holder_nonce,
            )?)?
        } else {
            FormatPresentationCtx {
                nonce: Some(verifier_nonce.clone()),
                ..Default::default()
            }
        };

        let credentials = credential_presentations
            .iter()
            .map(|presented_credential| {
                let credential_format = self
                    .config
                    .format
                    .get_fields(&presented_credential.credential_schema.format)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
                    .r#type;
                Ok(CredentialToPresent {
                    raw_credential: presented_credential.presentation.to_owned(),
                    credential_format,
                })
            })
            .collect::<Result<Vec<_>, VerificationProtocolError>>()?;

        let FormattedPresentation {
            vp_token,
            oidc_format,
        } = presentation_formatter
            .format_presentation(credentials, auth_fn, &did.did, ctx)
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let presentation_submission = create_presentation_submission(
            presentation_definition_id,
            credential_presentations,
            &oidc_format,
            &self.config,
        )?;

        let encryption_info = self
            .encryption_info_from_metadata(&interaction_data)
            .await?;
        if encryption_info.is_none() && format == FormatType::Mdoc {
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

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        type_to_descriptor: TypeToDescriptorMapper,
        _callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse<serde_json::Value>, VerificationProtocolError> {
        let interaction_id = Uuid::new_v4();

        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "missing proof schema".to_string(),
            ))?;

        // Pass the expected presentation content to interaction for verification
        let presentation_definition = create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof_schema,
            type_to_descriptor,
            format_to_type_mapper,
            &*self.credential_formatter_provider,
        )?;

        let Some(base_url) = &self.base_url else {
            return Err(VerificationProtocolError::Failed("Missing base_url".into()));
        };
        let response_uri = format!("{base_url}/ssi/openid4vp/draft-20/response");
        let nonce = utilities::generate_alphanumeric(32);

        let verifier_identifier =
            proof
                .clone()
                .verifier_identifier
                .ok_or(VerificationProtocolError::Failed(
                    "Missing verifier identifier".to_string(),
                ))?;

        let client_id_scheme = get_client_id_scheme(
            params,
            &self.params.verifier.supported_client_id_schemes,
            verifier_identifier,
        )?;

        if !self
            .params
            .verifier
            .supported_client_id_schemes
            .contains(&client_id_scheme)
        {
            return Err(VerificationProtocolError::InvalidRequest(
                "Unsupported client_id_scheme".into(),
            ));
        }

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
                .verifier_identifier
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "proof is missing verifier_identifier, required for did client_id_scheme"
                        .to_string(),
                ))?
                .did
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "proof is missing verifier_did, required for did client_id_scheme".to_string(),
                ))?
                .did
                .to_string(),
        };

        let client_metadata = generate_client_metadata_draft(
            proof,
            &*self.key_algorithm_provider,
            &*self.key_provider,
        )?;

        let authorization_request = generate_authorization_request_params_draft20(
            proof,
            &interaction_id,
            nonce.clone(),
            presentation_definition.clone(),
            client_id.clone(),
            response_uri.clone(),
            client_id_scheme,
            client_metadata.clone(),
        )?;

        let encryption_key = client_metadata
            .jwks
            .as_ref()
            .and_then(|jwks| jwks.keys.first().cloned());

        let interaction_content = OpenID4VPVerifierInteractionContent {
            nonce,
            presentation_definition: Some(presentation_definition),
            client_id: client_id.to_owned(),
            client_id_scheme: Some(client_id_scheme),
            response_uri: Some(response_uri),
            dcql_query: None,
            encryption_key,
        };

        let request = create_openidvp20_authorization_request(
            base_url,
            &self.params,
            client_id,
            proof,
            client_id_scheme,
            &self.key_algorithm_provider,
            &*self.key_provider,
            authorization_request,
        )
        .await?;

        let encoded_offer = serde_urlencoded::to_string(request)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        Ok(ShareResponse {
            url: format!("{}://?{encoded_offer}", self.params.url_scheme),
            interaction_id,
            context: serde_json::to_value(&interaction_content)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
        })
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        _proof: &Proof,
        _context: Value,
        _storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        Err(VerificationProtocolError::OperationNotSupported)
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
        aud: Some(aud),
        exp: Some(OffsetDateTime::now_utc() + Duration::minutes(10)),
        submission_data: VpSubmissionData::Pex(PexSubmission {
            vp_token,
            presentation_submission,
        }),
        state: interaction_data.state,
    };

    let response = jwe_presentation::build_jwe(
        payload,
        verifier_key.jwk.into(),
        verifier_key.key_id,
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
    certificate_validator: &Arc<dyn CertificateValidator>,
    params: &OpenID4Vp20Params,
) -> Result<InvitationResponseDTO, VerificationProtocolError> {
    let query = url
        .query()
        .ok_or(VerificationProtocolError::InvalidRequest(
            "Query cannot be empty".to_string(),
        ))?;

    let interaction_data = interaction_data_from_openid4vp_20_query(
        query,
        client,
        allow_insecure_http_transport,
        key_algorithm_provider,
        did_method_provider,
        certificate_validator,
        params,
    )
    .await?;
    validate_interaction_data(&interaction_data)?;
    let data = serialize_interaction_data(&interaction_data)?;

    let now = OffsetDateTime::now_utc();
    let interaction = create_and_store_interaction(storage_access, data, organisation).await?;

    let interaction_id = interaction.id.to_owned();

    let proof_id = Uuid::new_v4().into();
    let proof = proof_from_handle_invitation(
        &proof_id,
        VerificationProtocolType::OpenId4VpDraft20.as_ref(),
        interaction_data.redirect_uri,
        None,
        interaction,
        now,
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
    data: Vec<u8>,
    organisation: Option<Organisation>,
) -> Result<Interaction, VerificationProtocolError> {
    let now = OffsetDateTime::now_utc();

    let interaction = interaction_from_handle_invitation(Some(data), now, organisation);

    storage_access
        .create_interaction(interaction.clone())
        .await
        .map_err(VerificationProtocolError::StorageAccessError)?;

    Ok(interaction)
}
