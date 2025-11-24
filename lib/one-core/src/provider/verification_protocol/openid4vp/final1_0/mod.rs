use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use dcql::create_dcql_query;
use futures::future::BoxFuture;
use mappers::{create_openid4vp_final1_0_authorization_request, encode_client_id_with_scheme};
use model::Params;
use one_crypto::utilities;
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use url::Url;
use utils::{interaction_data_from_openid4vp_query, validate_interaction_data};
use uuid::Uuid;

use super::jwe_presentation::{self, ec_key_from_metadata};
use super::mapper::{format_to_type, unencrypted_params};
use super::mdoc::mdoc_presentation_context;
use crate::config::core_config::{
    CoreConfig, DidType, FormatType, IdentifierType, TransportType, VerificationProtocolType,
};
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::provider::credential_formatter::model::{DetailCredential, HolderBindingCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{CredentialToPresent, FormatPresentationCtx};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::Handover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::openid4vp_final1_0::OID4VPFinal1_0Handover;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::verification_protocol::dto::{
    FormattedCredentialPresentation, InvitationResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, PresentationReference,
    ShareResponse, UpdateResponse, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::mapper::{
    interaction_from_handle_invitation, proof_from_handle_invitation,
};
use crate::provider::verification_protocol::openid4vp::dcql::{
    get_presentation_definition_for_dcql_query, get_presentation_definition_v2,
};
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::create_open_id_for_vp_client_metadata_final1_0;
use crate::provider::verification_protocol::openid4vp::model::{
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, ClientIdScheme, DcqlSubmission,
    JwePayload, OpenID4VPClientMetadata, OpenID4VPClientMetadataJwkDTO,
    OpenID4VPDirectPostResponseDTO, OpenID4VPHolderInteractionData,
    OpenID4VPVerifierInteractionContent, VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::{
    FormatMapper, StorageAccess, TypeToDescriptorMapper, VerificationProtocolError,
    get_client_id_scheme,
};
use crate::provider::verification_protocol::{
    VerificationProtocol, deserialize_interaction_data, serialize_interaction_data,
};
use crate::service::oid4vp_final1_0::proof_request::{
    generate_authorization_request_params_final1_0, select_key_agreement_key_from_proof,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;

pub(super) mod dcql;
pub mod mappers;
pub mod model;
#[cfg(test)]
mod test;
mod utils;

const DCQL_QUERY_VALUE_QUERY_PARAM_KEY: &str = "dcql_query";
const REQUEST_URI_QUERY_PARAM_KEY: &str = "request_uri";
const REQUEST_QUERY_PARAM_KEY: &str = "request";
const CLIENT_ID_SCHEME_QUERY_PARAM_KEY: &str = "client_id_scheme";
const PROXIMITY_QUERY_PARAM_KEY: &str = "key";

pub(crate) struct OpenID4VPFinal1_0 {
    client: Arc<dyn HttpClient>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    base_url: Option<String>,
    params: Params,
    config: Arc<CoreConfig>,
}

struct EncryptionInfo {
    verifier_key: OpenID4VPClientMetadataJwkDTO,
    supported_algorithms: Vec<AuthorizationEncryptedResponseContentEncryptionAlgorithm>,
}

impl OpenID4VPFinal1_0 {
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
        params: Params,
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
    ) -> Result<Option<EncryptionInfo>, VerificationProtocolError> {
        let Some(OpenID4VPClientMetadata::Final1_0(mut client_metadata)) =
            interaction_data.client_metadata.clone()
        else {
            // metadata_uri (if any) has been resolved before, no need to check
            return Ok(None);
        };

        let supported_encryption_algs = match client_metadata
            .encrypted_response_enc_values_supported
            .clone()
        {
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
        Ok(Some(EncryptionInfo {
            verifier_key,
            supported_algorithms: supported_encryption_algs,
        }))
    }

    async fn dcql_submission_data(
        &self,
        credential_presentations: Vec<FormattedCredentialPresentation>,
        interaction_data: &OpenID4VPHolderInteractionData,
    ) -> Result<(VpSubmissionData, Option<EncryptionInfo>), VerificationProtocolError> {
        let mut vp_token = HashMap::new();
        let encryption_info = self.encryption_info_from_metadata(interaction_data).await?;

        // For DCQL each credential gets a presentation individually
        for credential_presentation in credential_presentations {
            let credential_format = format_to_type(&credential_presentation, &self.config)?;
            let presentation_format = match credential_format {
                // W3C SD-JWT will be enveloped using JWT presentation formatter
                FormatType::SdJwt => FormatType::Jwt,
                FormatType::SdJwtVc => FormatType::SdJwtVc,
                FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => FormatType::JsonLdClassic,
                FormatType::Mdoc => FormatType::Mdoc,
                FormatType::Jwt | FormatType::PhysicalCard => FormatType::Jwt,
            };

            if encryption_info.is_none() && presentation_format == FormatType::Mdoc {
                return Err(VerificationProtocolError::Failed(
                    "MDOC presentation requires encryption but no verifier EC keys are available"
                        .to_string(),
                ));
            }

            let presentation_formatter = self
                .presentation_formatter_provider
                .get_presentation_formatter(&presentation_format.to_string())
                .ok_or_else(|| {
                    VerificationProtocolError::Failed("Formatter not found".to_string())
                })?;

            let auth_fn = self
                .key_provider
                .get_signature_provider(
                    &credential_presentation.key,
                    credential_presentation.jwk_key_id,
                    self.key_algorithm_provider.clone(),
                )
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

            let mut credentials = vec![CredentialToPresent {
                raw_credential: credential_presentation.presentation,
                credential_format,
            }];
            if let Some(validity_credential) =
                credential_presentation.validity_credential_presentation
            {
                credentials.push(CredentialToPresent {
                    raw_credential: validity_credential,
                    credential_format,
                })
            }
            let formatted_presentation = presentation_formatter
                .format_presentation(
                    credentials,
                    auth_fn,
                    &credential_presentation.holder_did.did,
                    format_presentation_context(interaction_data, presentation_format)?,
                )
                .await
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
            let PresentationReference::Dcql {
                credential_query_id,
            } = credential_presentation.reference
            else {
                return Err(VerificationProtocolError::Failed(
                    "Incompatible presentation reference".to_string(),
                ));
            };
            vp_token
                .entry(credential_query_id)
                .and_modify(|presentations: &mut Vec<String>| {
                    presentations.push(formatted_presentation.vp_token.to_owned())
                })
                .or_insert(vec![formatted_presentation.vp_token]);
        }
        Ok((
            VpSubmissionData::Dcql(DcqlSubmission { vp_token }),
            encryption_info,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
#[async_trait::async_trait]
impl VerificationProtocol for OpenID4VPFinal1_0 {
    async fn retract_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        Ok(())
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
            audience: encode_client_id_with_scheme(
                interaction_data.client_id,
                interaction_data.client_id_scheme,
            ),
        }))
    }

    fn holder_can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.params.url_scheme == url.scheme()
            && !query_has_key(PROXIMITY_QUERY_PARAM_KEY) // Ensure we do not match proximity URLs
            && (!query_has_key(CLIENT_ID_SCHEME_QUERY_PARAM_KEY)
                || query_has_key(DCQL_QUERY_VALUE_QUERY_PARAM_KEY)
                || query_has_key(REQUEST_URI_QUERY_PARAM_KEY)
                || query_has_key(REQUEST_QUERY_PARAM_KEY))
    }

    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        context: Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        let interaction_data: OpenID4VPHolderInteractionData =
            serde_json::from_value(context).map_err(VerificationProtocolError::JsonError)?;

        let dcql_query = interaction_data
            .dcql_query
            .ok_or(VerificationProtocolError::Failed(
                "missing dcql_query".to_string(),
            ))?;

        get_presentation_definition_for_dcql_query(
            dcql_query,
            proof,
            storage_access,
            &*self.credential_formatter_provider,
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
            supported_presentation_definition: vec![PresentationDefinitionVersion::V2],
        }
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError> {
        todo!()
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
        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .to_owned();

        let interaction_data: OpenID4VPHolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;
        let holder_nonce = utilities::generate_alphanumeric(32);

        let (submission_data, encryption_info) = self
            .dcql_submission_data(credential_presentations, &interaction_data)
            .await?;

        let response_uri =
            interaction_data
                .response_uri
                .clone()
                .ok_or(VerificationProtocolError::Failed(
                    "response_uri is None".to_string(),
                ))?;

        let params = if let Some(EncryptionInfo {
            verifier_key,
            supported_algorithms,
        }) = encryption_info
        {
            encrypted_params(
                interaction_data,
                submission_data,
                &holder_nonce,
                verifier_key,
                supported_algorithms,
                &*self.key_algorithm_provider,
            )
            .await?
        } else {
            unencrypted_params(&submission_data, interaction_data.state.clone())?
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
        _type_to_descriptor: TypeToDescriptorMapper,
        _callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse<serde_json::Value>, VerificationProtocolError> {
        let interaction_id = Uuid::new_v4();

        let Some(base_url) = &self.base_url else {
            return Err(VerificationProtocolError::Failed("Missing base_url".into()));
        };
        let response_uri = format!("{base_url}/ssi/openid4vp/final-1.0/response");
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

        let client_id_without_prefix = match client_id_scheme {
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

        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "Proof schema not found".to_string(),
            ))?;

        let key_agreement_key = select_key_agreement_key_from_proof(
            proof,
            &*self.key_algorithm_provider,
            &self.config,
        )?;

        let client_metadata = create_open_id_for_vp_client_metadata_final1_0(key_agreement_key)?;
        let encryption_key = client_metadata
            .jwks
            .as_ref()
            .and_then(|jwks| jwks.keys.first())
            .cloned();

        let authorization_request = generate_authorization_request_params_final1_0(
            nonce.clone(),
            create_dcql_query(
                proof_schema,
                &format_to_type_mapper,
                &*self.credential_formatter_provider,
            )?,
            encode_client_id_with_scheme(client_id_without_prefix.clone(), client_id_scheme),
            response_uri.clone(),
            &interaction_id,
            client_metadata,
        )?;

        let interaction_content = OpenID4VPVerifierInteractionContent {
            nonce,
            presentation_definition: None,
            client_id: authorization_request.client_id.clone(),
            dcql_query: authorization_request.dcql_query.clone(),
            encryption_key,
            client_id_scheme: Some(client_id_scheme),
            response_uri: Some(response_uri),
        };

        let authorization_request = create_openid4vp_final1_0_authorization_request(
            base_url,
            &self.params,
            client_id_without_prefix,
            proof,
            client_id_scheme,
            &self.key_algorithm_provider,
            &*self.key_provider,
            authorization_request,
        )
        .await?;

        let encoded_authorization_request = serde_urlencoded::to_string(authorization_request)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        Ok(ShareResponse {
            url: format!(
                "{}://?{encoded_authorization_request}",
                self.params.url_scheme
            ),
            interaction_id,
            context: serde_json::to_value(&interaction_content)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
        })
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        context: Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        let interaction_data: OpenID4VPHolderInteractionData =
            serde_json::from_value(context).map_err(VerificationProtocolError::JsonError)?;

        let dcql_query = interaction_data
            .dcql_query
            .ok_or(VerificationProtocolError::Failed(
                "missing dcql_query".to_string(),
            ))?;

        get_presentation_definition_v2(
            dcql_query,
            proof,
            storage_access,
            &*self.credential_formatter_provider,
            &self.config,
        )
        .await
    }
}

fn format_presentation_context(
    interaction_data: &OpenID4VPHolderInteractionData,
    presentation_format: FormatType,
) -> Result<FormatPresentationCtx, VerificationProtocolError> {
    let verifier_nonce =
        interaction_data
            .nonce
            .clone()
            .ok_or(VerificationProtocolError::Failed(
                "nonce is None".to_string(),
            ))?;
    let response_uri =
        interaction_data
            .response_uri
            .clone()
            .ok_or(VerificationProtocolError::Failed(
                "response_uri is None".to_string(),
            ))?;
    let ctx = if presentation_format == FormatType::Mdoc {
        let Some(OpenID4VPClientMetadata::Final1_0(metadata)) = &interaction_data.client_metadata
        else {
            return Err(VerificationProtocolError::Failed(
                "missing or invalid client_metadata".to_string(),
            ));
        };

        let encryption_key = metadata
            .jwks
            .as_ref()
            .and_then(|jwks| jwks.keys.first())
            .map(|key| key.jwk.clone().into());

        mdoc_presentation_context(Handover::OID4VPFinal1_0(
            OID4VPFinal1_0Handover::compute(
                &encode_client_id_with_scheme(
                    interaction_data.client_id.clone(),
                    interaction_data.client_id_scheme,
                ),
                response_uri.as_str(),
                &verifier_nonce,
                encryption_key.as_ref(),
            )
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
        ))?
    } else {
        FormatPresentationCtx {
            nonce: Some(verifier_nonce),
            ..Default::default()
        }
    };
    Ok(ctx)
}

async fn encrypted_params(
    interaction_data: OpenID4VPHolderInteractionData,
    submission_data: VpSubmissionData,
    holder_nonce: &str,
    verifier_key: OpenID4VPClientMetadataJwkDTO,
    encryption_algorithms: Vec<AuthorizationEncryptedResponseContentEncryptionAlgorithm>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<HashMap<String, String>, VerificationProtocolError> {
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
        submission_data,
        state: interaction_data.state,
    };

    // All algorithms defined in the AuthorizationEncryptedResponseContentEncryptionAlgorithm enum are supported
    // we pick the first one
    let selected_encryption_alg =
        encryption_algorithms
            .first()
            .cloned()
            .ok_or(VerificationProtocolError::Failed(
                "metadata contains no encrypted_response_enc_values_supported entries".to_string(),
            ))?;

    let response = jwe_presentation::build_jwe(
        payload,
        verifier_key.jwk.into(),
        verifier_key.key_id,
        holder_nonce,
        &verifier_nonce,
        selected_encryption_alg,
        key_algorithm_provider,
    )
    .await
    .map_err(|err| {
        VerificationProtocolError::Failed(format!("Failed to build response jwe: {err}"))
    })?;
    Ok(HashMap::from_iter([("response".to_owned(), response)]))
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
    params: &Params,
) -> Result<InvitationResponseDTO, VerificationProtocolError> {
    let query = url
        .query()
        .ok_or(VerificationProtocolError::InvalidRequest(
            "Query cannot be empty".to_string(),
        ))?;

    let holder_interaction_data = {
        let (interaction_data, verifier_details) = interaction_data_from_openid4vp_query(
            query,
            client,
            allow_insecure_http_transport,
            key_algorithm_provider,
            did_method_provider,
            certificate_validator,
            params,
        )
        .await?;

        let mut holder_state: OpenID4VPHolderInteractionData = interaction_data.try_into()?;
        holder_state.verifier_details = verifier_details;
        holder_state
    };

    validate_interaction_data(&holder_interaction_data)?;
    let data = serialize_interaction_data(&holder_interaction_data)?;

    let Some(_) = holder_interaction_data.response_uri else {
        return Err(VerificationProtocolError::Failed(
            "response_uri is missing".to_string(),
        ));
    };

    let now = OffsetDateTime::now_utc();
    let interaction = create_and_store_interaction(storage_access, data, organisation).await?;

    let interaction_id = interaction.id.to_owned();

    let proof_id = Uuid::new_v4().into();
    let proof = proof_from_handle_invitation(
        &proof_id,
        VerificationProtocolType::OpenId4VpFinal1_0.as_ref(),
        holder_interaction_data.redirect_uri,
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
