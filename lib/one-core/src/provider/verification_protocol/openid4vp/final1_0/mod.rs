use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use futures::future::BoxFuture;
use indexmap::IndexMap;
use mappers::{create_openid4vp_final1_0_authorization_request, encode_client_id_with_scheme};
use model::Params;
use one_crypto::jwe::Header as JweHeader;
use one_crypto::utilities;
use one_dto_mapper::convert_inner;
use proc_macros::Provider;
use serde_json::Value;
use shared_types::{TransactionDataId, TransactionDataType};
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vp::dcql::CredentialQueryId;
use standardized_types::openid4vp::{
    ClientIdPrefix, DirectPostResponse, ResponseMode, VpTokenResponse,
};
use time::Duration;
use url::Url;
use utils::validate_interaction_data;
use uuid::Uuid;

use super::mapper::{format_to_type, unencrypted_params};
use super::mdoc::mdoc_presentation_context;
use crate::config::core_config::{
    CoreConfig, DidType, FormatType, IdentifierType, TransportType, VerificationProtocolType,
};
use crate::error::ContextWithErrorCode;
use crate::model::did::Did;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::model::relation::Related;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{CredentialToPresent, FormatPresentationCtx};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::Handover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::openid4vp_final1_0::OID4VPFinal1_0Handover;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::transaction_data::processed_transaction_data::ProcessedTransactionData;
use crate::provider::transaction_data::provider::TransactionDataProvider;
use crate::provider::transaction_data::{
    Features, agreed_hash_algorithm, assign_entries_to_distinct_credentials,
};
use crate::provider::verification_protocol::dto::{
    Feature, FormattedCredentialPresentation, InvitationResponseDTO,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::mapper::{
    interaction_from_handle_invitation, proof_from_handle_invitation,
};
use crate::provider::verification_protocol::openid4vp::dcql::get_presentation_definition_v2;
use crate::provider::verification_protocol::openid4vp::final1_0::dcql::create_dcql_query;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::{
    create_open_id_for_vp_client_metadata_final1_0, transaction_data_from_interaction,
};
use crate::provider::verification_protocol::openid4vp::model::{
    CommonVerifierInteractionContent, HolderTxData, JwePayload, OpenID4VPHolderInteractionData,
    OpenID4VPVerifierInteractionContent, ValidatedHolderTxData, VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::{
    FormatMapper, VerificationProtocolError, get_client_id_scheme,
};
use crate::provider::verification_protocol::{
    VerificationProtocol, deserialize_interaction_data, serialize_interaction_data,
};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::oid4vp_final1_0::proof_request::{
    generate_authorization_request_params_final1_0, select_key_agreement_key_from_proof,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;
use crate::util::jwe::{build_jwe, select_recipient_jwk};

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

#[derive(Provider)]
pub(crate) struct OpenID4VPFinal1_0 {
    config_id: String,
    client: Arc<dyn HttpClient>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    wrp_validator: Arc<dyn WRPValidator>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
    transaction_data_provider: Arc<dyn TransactionDataProvider>,
    base_url: Option<String>,
    params: Params,
    config: Arc<CoreConfig>,
}

struct EncryptionInfo {
    verifier_key: PublicJwk,
    supported_algorithms: Vec<EncryptionAlgorithm>,
}

impl OpenID4VPFinal1_0 {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config_id: String,
        base_url: Option<String>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        credential_repository: Arc<dyn CredentialRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        wrp_validator: Arc<dyn WRPValidator>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
        transaction_data_provider: Arc<dyn TransactionDataProvider>,
        client: Arc<dyn HttpClient>,
        params: serde_json::Value,
        config: Arc<CoreConfig>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_id,
            base_url,
            credential_formatter_provider,
            presentation_formatter_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            certificate_validator,
            credential_repository,
            credential_schema_repository,
            interaction_repository,
            wrp_validator,
            client,
            params,
            config,
            ecosystem_provider,
            transaction_data_provider,
        })
    }

    async fn encryption_info_from_metadata(
        &self,
        interaction_data: &OpenID4VPHolderInteractionData,
    ) -> Result<Option<EncryptionInfo>, VerificationProtocolError> {
        let Some(mut client_metadata) = interaction_data.client_metadata.clone() else {
            return Err(VerificationProtocolError::InvalidRequest(
                "failed to parse interaction_data".to_string(),
            ));
        };

        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-encrypted-responses
        // When a response_mode requires encryption (direct_post.jwt),
        // this MUST be present for anything other than the default single value of A128GCM.
        // Otherwise, this SHOULD be absent.
        let supported_encryption_algs = client_metadata
            .encrypted_response_enc_values_supported
            .clone()
            .unwrap_or(vec![EncryptionAlgorithm::A128GCM]);

        if client_metadata
            .jwks
            .as_ref()
            .map(|jwks| jwks.keys.is_empty())
            .unwrap_or(true)
            && let Some(ref uri) = client_metadata.jwks_uri
        {
            let jwks = async { self.client.get(uri).send().await?.error_for_status() }
                .await
                .error_while("fetching JWKs")?;

            client_metadata.jwks = jwks.json().error_while("parsing JWKs")?;
        }
        let Some(verifier_key) = select_recipient_jwk(
            client_metadata.jwks.into_iter().flat_map(|jwks| jwks.keys),
            self.key_algorithm_provider.as_ref(),
        ) else {
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

        let response_mode =
            interaction_data
                .response_mode
                .ok_or(VerificationProtocolError::InvalidRequest(
                    "response_mode is None".to_string(),
                ))?;

        // As per https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1
        // the response should be encrypted only if the response type is direct_post.jwt
        let encryption_info = match response_mode {
            ResponseMode::DirectPost => None,
            ResponseMode::DirectPostJwt => Some(
                self.encryption_info_from_metadata(interaction_data)
                    .await?
                    .ok_or(VerificationProtocolError::InvalidRequest(
                        "direct_post.jwt requires encryption, but no verifier keys are available"
                            .to_string(),
                    ))?,
            ),
        };

        // May contain more entries than `credential_presentations`: presentations carrying
        // conflicting transaction data are duplicated (and appended) if the verifier accepts
        // multiple presentations for the given credential query.
        let presentations_with_tx_data = assign_transaction_data(
            credential_presentations,
            interaction_data,
            &*self.transaction_data_provider,
        )?;

        // For DCQL each credential gets a presentation individually
        for PresentationWithTxData {
            credential_presentation,
            transaction_data,
        } in presentations_with_tx_data
        {
            let credential_query_id = credential_presentation.credential_query_id.clone();

            // Look up the credential query to check require_cryptographic_holder_binding
            let require_holder_binding = interaction_data
                .dcql_query
                .credentials
                .iter()
                .find(|cq| cq.id == credential_query_id)
                .map(|cq| cq.require_cryptographic_holder_binding)
                .unwrap_or(true);

            if require_holder_binding {
                let credential_format =
                    format_to_type(&credential_presentation, &self.config).await?;
                let presentation_format = match credential_format {
                    FormatType::SdJwt => FormatType::SdJwt,
                    FormatType::SdJwtVc => FormatType::SdJwtVc,
                    FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => {
                        FormatType::JsonLdClassic
                    }
                    FormatType::Mdoc => FormatType::Mdoc,
                    FormatType::Jwt => FormatType::Jwt,
                };

                let presentation_formatter = self
                    .presentation_formatter_provider
                    .get_presentation_formatter(&presentation_format.to_string())
                    .ok_or_else(|| {
                        VerificationProtocolError::Failed("Formatter not found".to_string())
                    })?;

                let auth_fn = self.key_provider.get_signature_provider(
                    &credential_presentation.key,
                    credential_presentation.jwk_key_id,
                    self.key_algorithm_provider.clone(),
                )?;
                let mut aggregated_tx_data = None;
                if !transaction_data.is_empty() {
                    // the entries share one Key Binding JWT claim, so one algorithm is
                    // agreed for all of them before any is hashed
                    let hash_algorithm = agreed_hash_algorithm(
                        transaction_data.iter().map(|tx_data| tx_data.data.as_str()),
                    )
                    .error_while("agreeing on a transaction data hash algorithm")?;

                    for tx_data in transaction_data {
                        let data = self
                            .transaction_data_provider
                            .get_transaction_data_by_name(&tx_data.r#type)?;
                        let processed = data
                            .process_transaction_data(
                                &tx_data.data,
                                credential_format,
                                hash_algorithm,
                            )
                            .await
                            .error_while("processing transaction data")?;
                        let Some(existing) = aggregated_tx_data.as_mut() else {
                            aggregated_tx_data = Some(processed);
                            continue;
                        };
                        existing
                            .merge(processed)
                            .error_while("merging transaction data")?;
                    }
                }

                let credentials = CredentialToPresent {
                    credential_token: credential_presentation.presentation,
                    credential_format,
                };
                let formatted_presentation = presentation_formatter
                    .format_presentation(
                        vec![credentials],
                        auth_fn,
                        format_presentation_context(
                            interaction_data,
                            presentation_format,
                            self.params.use_legacy_did_client_id_scheme,
                            credential_presentation.holder_did,
                            aggregated_tx_data,
                        )?,
                    )
                    .await
                    .error_while("formatting presentation")?;

                vp_token
                    .entry(credential_query_id.to_string())
                    .and_modify(|presentations: &mut Vec<String>| {
                        presentations.push(formatted_presentation.vp_token.to_owned())
                    })
                    .or_insert(vec![formatted_presentation.vp_token]);
            } else {
                // No holder binding — send bare credential tokens without VP wrapper
                let tokens = vp_token.entry(credential_query_id.to_string()).or_default();
                tokens.push(credential_presentation.presentation);
            }
        }
        Ok((
            VpSubmissionData::Dcql(VpTokenResponse { vp_token }),
            encryption_info,
        ))
    }

    async fn handle_proof_invitation<'a>(
        &self,
        url: Url,
        organisation: Organisation,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
        let query = url
            .query()
            .ok_or(VerificationProtocolError::InvalidRequest(
                "Query cannot be empty".to_string(),
            ))?;

        let proof_id = Uuid::new_v4().into();
        let mut holder_interaction_data = {
            let (authorization_request, verifier_details) =
                self.request_from_openid4vp_query(query).await?;

            let mut interaction_data: OpenID4VPHolderInteractionData =
                authorization_request.try_into()?;
            interaction_data.verifier_details = verifier_details;
            if let Some(predefined_metadata) = &self.params.predefined_vp_formats_supported
                && let Some(metadata) = interaction_data.client_metadata.as_mut()
            {
                metadata.vp_formats_supported = predefined_metadata.clone();
            }
            interaction_data
        };

        validate_interaction_data(&holder_interaction_data)?;
        self.process_transaction_data(&mut holder_interaction_data)?;
        let data = serialize_interaction_data(&holder_interaction_data)?;

        let Some(_) = holder_interaction_data.response_uri else {
            return Err(VerificationProtocolError::Failed(
                "response_uri is missing".to_string(),
            ));
        };

        let now = crate::clock::now_utc();
        let interaction =
            create_and_store_interaction(self.interaction_repository.as_ref(), data, organisation)
                .await?;
        let interaction_id = interaction.id;

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
            ecosystem_artifact: ProtocolArtifact::HolderProof {
                verifier_details: Cow::Owned(holder_interaction_data.verifier_details),
                dcql_query: holder_interaction_data.dcql_query,
                verifier_info: holder_interaction_data.verifier_info,
                proof_id,
            },
        })
    }

    fn process_transaction_data(
        &self,
        holder_interaction_data: &mut OpenID4VPHolderInteractionData,
    ) -> Result<(), VerificationProtocolError> {
        if let HolderTxData::Unvalidated(transaction_data) =
            &holder_interaction_data.transaction_data
        {
            let mut validated_tx_data = IndexMap::with_capacity(transaction_data.len());
            for (idx, tx_data) in transaction_data.iter().enumerate() {
                let (transaction_data_type, data) = self
                    .transaction_data_provider
                    .get_transaction_data(tx_data)?;
                let validated = data
                    .validate_transaction_data(tx_data)
                    .error_while("validating transaction data")?;

                for credential_query_id in &validated.credential_ids {
                    let Some(query) = holder_interaction_data
                        .dcql_query
                        .credentials
                        .iter()
                        .find(|c| &c.id == credential_query_id)
                    else {
                        return Err(VerificationProtocolError::InvalidRequest(format!(
                            "Invalid transaction data at index {idx}: credential query id `{}` not found in DCQL query",
                            credential_query_id
                        )));
                    };
                    if !query.require_cryptographic_holder_binding {
                        return Err(VerificationProtocolError::InvalidRequest(format!(
                            "Invalid transaction data at index {idx}: referenced credential query `{}` does not require cryptographic holder binding",
                            credential_query_id
                        )));
                    }
                }

                validated_tx_data.insert(
                    TransactionDataId::from(Uuid::new_v4()),
                    ValidatedHolderTxData {
                        raw: tx_data.clone(),
                        credential_query_ids: convert_inner(validated.credential_ids),
                        transaction_data_type,
                    },
                );
            }
            holder_interaction_data.transaction_data = HolderTxData::Validated(validated_tx_data);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl VerificationProtocol for OpenID4VPFinal1_0 {
    async fn retract_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        Ok(())
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

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        let did_methods = vec![DidType::Key, DidType::Jwk, DidType::Web, DidType::WebVh];
        let mut verifier_identifier_types = HashSet::new();
        let schemes = &self.params.verifier.supported_client_id_schemes;
        let mut features = vec![];

        if self.params.common.webhook_task.is_some() {
            features.push(Feature::SupportsWebhooks);
        }

        if [
            ClientIdPrefix::DecentralizedIdentifier,
            ClientIdPrefix::RedirectUri,
            ClientIdPrefix::VerifierAttestation,
        ]
        .iter()
        .any(|scheme| schemes.contains(scheme))
        {
            verifier_identifier_types.insert(IdentifierType::Did);
        }

        if schemes.contains(&ClientIdPrefix::X509SanDns)
            || schemes.contains(&ClientIdPrefix::X509Hash)
        {
            verifier_identifier_types.insert(IdentifierType::Certificate);
        }

        VerificationProtocolCapabilities {
            features,
            supported_transports: vec![TransportType::Http],
            did_methods,
            verifier_identifier_types: verifier_identifier_types.into_iter().collect(),
            supported_presentation_definition: vec![PresentationDefinitionVersion::V2],
            supported_encryption_algorithms: vec![
                EncryptionAlgorithm::A128GCM,
                EncryptionAlgorithm::A256GCM,
                EncryptionAlgorithm::A128CBCHS256,
                EncryptionAlgorithm::A256CBCHS512,
            ],
        }
    }

    async fn holder_handle_invitation<'a>(
        &self,
        url: Url,
        organisation: Organisation,
        _transport: String,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
        if !self.holder_can_handle(&url) {
            return Err(VerificationProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ));
        }

        self.handle_proof_invitation(url, organisation).await
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
            .as_ref()
            .await?;

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

        let response = async {
            self.client
                .post(response_uri.as_str())
                .form(&params)?
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("posting submission")?;

        let response: Result<DirectPostResponse, _> = response.json();

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
        _callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError> {
        let interaction_id = Uuid::new_v4().into();

        let Some(base_url) = &self.base_url else {
            return Err(VerificationProtocolError::Failed("Missing base_url".into()));
        };
        let response_uri = format!("{base_url}/ssi/openid4vp/final-1.0/response");
        let nonce = utilities::generate_alphanumeric(32);

        let verifier_identifier = proof
            .verifier_identifier
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "Missing verifier identifier".to_string(),
            ))?
            .as_ref()
            .await?;

        let client_id_scheme = get_client_id_scheme(
            params,
            &self.params.verifier.supported_client_id_schemes,
            &verifier_identifier,
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
            ClientIdPrefix::RedirectUri | ClientIdPrefix::VerifierAttestation => {
                response_uri.to_owned()
            }
            ClientIdPrefix::X509SanDns => {
                let base_url = Url::parse(base_url)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

                base_url
                    .domain()
                    .ok_or(VerificationProtocolError::Failed(
                        "Invalid base_url".to_string(),
                    ))?
                    .to_string()
            }
            ClientIdPrefix::X509Hash => {
                let verifier_certificate = proof
                    .verifier_certificate
                    .as_ref()
                    .ok_or(VerificationProtocolError::Failed(
                        "verifier_certificate is None".to_string(),
                    ))?
                    .as_ref()
                    .await?;

                let fingerprint = hex::decode(&verifier_certificate.fingerprint)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

                Base64UrlSafeNoPadding::encode_to_string(fingerprint)?
            }
            ClientIdPrefix::DecentralizedIdentifier => {
                let verifier_identifier = proof
                    .verifier_identifier
                    .as_ref()
                    .ok_or(VerificationProtocolError::Failed(
                        "verifier_identifier is None".to_string(),
                    ))?
                    .as_ref()
                    .await?;

                let Identifier {
                    data: IdentifierData::Did(verifier_did),
                    ..
                } = verifier_identifier.as_ref()
                else {
                    return Err(VerificationProtocolError::Failed(
                        "proof is missing verifier DID, required for did client_id_scheme"
                            .to_string(),
                    ));
                };

                verifier_did.as_ref().await?.did.to_string()
            }
        };

        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "Proof schema not found".to_string(),
            ))?
            .as_ref()
            .await?;

        let key_agreement_key = select_key_agreement_key_from_proof(
            proof,
            &*self.key_provider,
            &*self.key_algorithm_provider,
        )
        .await?;

        let client_metadata = create_open_id_for_vp_client_metadata_final1_0(
            key_agreement_key,
            self.get_capabilities().supported_encryption_algorithms,
        )?;
        let encryption_key = client_metadata
            .jwks
            .as_ref()
            .and_then(|jwks| jwks.keys.first())
            .cloned();

        let authorization_request = generate_authorization_request_params_final1_0(
            nonce.clone(),
            create_dcql_query(
                &proof_schema,
                &format_to_type_mapper,
                &*self.credential_formatter_provider,
            )
            .await?,
            vec![],
            encode_client_id_with_scheme(
                client_id_without_prefix.clone(),
                client_id_scheme,
                self.params.use_legacy_did_client_id_scheme,
            ),
            response_uri.clone(),
            &interaction_id,
            client_metadata,
            vec![],
        )?;

        let transaction_data = transaction_data_from_interaction(proof).await?;
        let interaction_content = OpenID4VPVerifierInteractionContent {
            nonce,
            client_id: authorization_request.client_id.clone(),
            presentation_definition: None,
            dcql_query: Some(authorization_request.dcql_query.clone()),
            encryption_key,
            client_id_scheme: Some(client_id_scheme),
            response_uri: Some(response_uri),
            common: CommonVerifierInteractionContent { transaction_data },
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

        let encoded_authorization_request = serde_urlencoded::to_string(authorization_request)?;

        let expires_at = self
            .params
            .verifier
            .interaction_expires_in_seconds
            .map(|interaction_expires_in| crate::clock::now_utc() + interaction_expires_in);

        Ok(ShareResponse {
            url: format!(
                "{}://?{encoded_authorization_request}",
                self.params.url_scheme
            ),
            interaction_id,
            interaction_data: Some(serialize_interaction_data(&interaction_content)?),
            expires_at,
        })
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        context: Value,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        let interaction_data: OpenID4VPHolderInteractionData = serde_json::from_value(context)?;

        get_presentation_definition_v2(
            interaction_data.dcql_query,
            proof,
            &*self.credential_repository,
            &*self.credential_schema_repository,
            &*self.credential_formatter_provider,
            &*self.ecosystem_provider,
            &*self.wrp_validator,
            &self.config,
            interaction_data.verifier_details.as_ref(),
            &interaction_data.verifier_info,
            Some(interaction_data.transaction_data.validated()?),
        )
        .await
    }

    fn config_name(&self) -> &str {
        &self.config_id
    }
}

fn format_presentation_context(
    interaction_data: &OpenID4VPHolderInteractionData,
    presentation_format: FormatType,
    use_legacy_did_client_id_scheme: bool,
    holder_did: Option<Did>,
    transaction_data: Option<ProcessedTransactionData>,
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
        let Some(metadata) = &interaction_data.client_metadata else {
            return Err(VerificationProtocolError::Failed(
                "missing or invalid client_metadata".to_string(),
            ));
        };

        let encryption_key = if interaction_data.response_mode == Some(ResponseMode::DirectPostJwt)
        {
            metadata
                .jwks
                .as_ref()
                .and_then(|jwks| jwks.keys.first())
                .cloned()
        } else {
            None
        };

        let handover = OID4VPFinal1_0Handover::compute(
            &encode_client_id_with_scheme(
                interaction_data.client_id.clone(),
                interaction_data.client_id_scheme,
                use_legacy_did_client_id_scheme,
            ),
            response_uri.as_str(),
            &verifier_nonce,
            encryption_key.as_ref(),
        )
        .error_while("computing handover")?;
        mdoc_presentation_context(Handover::OID4VPFinal1_0(handover), transaction_data)?
    } else {
        FormatPresentationCtx {
            nonce: Some(verifier_nonce),
            audience: Some(encode_client_id_with_scheme(
                interaction_data.client_id.clone(),
                interaction_data.client_id_scheme,
                use_legacy_did_client_id_scheme,
            )),
            holder_did: holder_did.map(|did| did.did),
            transaction_data,
            ..Default::default()
        }
    };
    Ok(ctx)
}

async fn encrypted_params(
    interaction_data: OpenID4VPHolderInteractionData,
    submission_data: VpSubmissionData,
    holder_nonce: &str,
    verifier_key: PublicJwk,
    encryption_algorithms: Vec<EncryptionAlgorithm>,
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
        exp: Some(crate::clock::now_utc() + Duration::minutes(10)),
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

    let payload = payload
        .try_into_json()
        .map_err(VerificationProtocolError::Other)?;

    let response = build_jwe(
        &payload,
        &verifier_key,
        JweHeader {
            key_id: verifier_key.kid().map(String::from),
            zip: None,
            partyuinfo_data: Some(holder_nonce.as_bytes().to_vec()),
            partyvinfo_data: Some(verifier_nonce.as_bytes().to_vec()),
        },
        selected_encryption_alg,
        key_algorithm_provider,
    )
    .await?;
    Ok(HashMap::from_iter([("response".to_owned(), response)]))
}

async fn create_and_store_interaction(
    interaction_repository: &dyn InteractionRepository,
    data: Vec<u8>,
    organisation: impl Into<Related<Organisation>>,
) -> Result<Interaction, VerificationProtocolError> {
    let now = crate::clock::now_utc();

    let interaction = interaction_from_handle_invitation(Some(data), now, organisation);

    interaction_repository
        .create_interaction(interaction.clone())
        .await
        .error_while("creating interaction")?;

    Ok(interaction)
}

struct PresentationWithTxData {
    credential_presentation: FormattedCredentialPresentation,
    transaction_data: Vec<AssignedTransactionData>,
}

impl PresentationWithTxData {
    fn duplicate(&self, transaction_data: AssignedTransactionData) -> PresentationWithTxData {
        Self {
            credential_presentation: self.credential_presentation.clone(),
            transaction_data: vec![transaction_data],
        }
    }

    fn has_tx_data_of_type(&self, r#type: &TransactionDataType) -> bool {
        self.transaction_data.iter().any(|tx| &tx.r#type == r#type)
    }

    fn has_pinned_tx_data_of_type(&self, r#type: &TransactionDataType) -> bool {
        self.transaction_data
            .iter()
            .any(|tx| &tx.r#type == r#type && tx.manually_assigned)
    }
}

struct AssignedTransactionData {
    data: String,
    r#type: TransactionDataType,
    query_ids: Vec<CredentialQueryId>,
    manually_assigned: bool,
}

impl From<ValidatedHolderTxData> for AssignedTransactionData {
    fn from(tx_data: ValidatedHolderTxData) -> Self {
        Self {
            data: tx_data.raw,
            r#type: tx_data.transaction_data_type,
            query_ids: tx_data.credential_query_ids,
            manually_assigned: false,
        }
    }
}

fn assign_transaction_data(
    credential_presentations: Vec<FormattedCredentialPresentation>,
    interaction_data: &OpenID4VPHolderInteractionData,
    transaction_data_provider: &dyn TransactionDataProvider,
) -> Result<Vec<PresentationWithTxData>, VerificationProtocolError> {
    let mut transaction_data = interaction_data.transaction_data.validated()?;

    // Assign transaction data entries to credential presentations. Explicit
    // client selections (across all credentials) are honored first, then any
    // remaining entries are auto-assigned to the first applicable credential.
    // Entries whose evidence would clash with an already assigned entry of the
    // same type are moved onto a duplicate of the presentation (only possible
    // if DCQL multiple is true).
    let mut assignments: Vec<_> = credential_presentations
        .into_iter()
        .map(|credential_presentation| PresentationWithTxData {
            credential_presentation,
            transaction_data: vec![],
        })
        .collect();
    let mut presentation_duplicates = vec![];

    // explicit transaction data selections
    for credential_presentation in assignments
        .iter_mut()
        .filter(|p| !p.credential_presentation.transaction_data_ids.is_empty())
    {
        let presentation = &credential_presentation.credential_presentation;
        for tx_id in &presentation.transaction_data_ids {
            let Some(tx_data) = transaction_data.shift_remove(tx_id) else {
                return Err(VerificationProtocolError::InvalidTransactionDataAssignment(
                    format!("unknown or already-selected transaction data id {tx_id}"),
                ));
            };
            if !tx_data
                .credential_query_ids
                .contains(&presentation.credential_query_id)
            {
                return Err(VerificationProtocolError::InvalidTransactionDataAssignment(
                    format!(
                        "transaction data {tx_id} is not applicable to the selected credential"
                    ),
                ));
            }

            let conflict_free = conflict_free_tx_data_type(transaction_data_provider, &tx_data)?;
            let mut data: AssignedTransactionData = tx_data.into();
            data.manually_assigned = true;
            if conflict_free || !credential_presentation.has_tx_data_of_type(&data.r#type) {
                // No conflict of transaction data evidence
                credential_presentation.transaction_data.push(data);
            } else if dcql_multiple(interaction_data, presentation) {
                // There is a conflict, but verifiers allows multiple -> duplicate presentation
                presentation_duplicates.push(credential_presentation.duplicate(data));
            } else {
                return Err(VerificationProtocolError::InvalidTransactionDataAssignment(
                    format!(
                        "only one transaction data entry of type {} can be assigned to credential query {}",
                        data.r#type, presentation.credential_query_id
                    ),
                ));
            }
        }
    }
    // append already, so that the duplicates can be used to auto assign other conflicting tx data
    assignments.append(&mut presentation_duplicates);

    // auto-assign remaining transaction data entries
    for (id, tx_data) in transaction_data {
        let conflict_free = conflict_free_tx_data_type(transaction_data_provider, &tx_data)?;

        // Attaching to an existing presentation is preferred over duplicating one. It is
        // possible, if the presentation is applicable to the transaction data and either
        // * the transaction data does not clash with data of the same type (i.e. is conflict free)
        // * or no transaction data of the given type is assigned to the presentation yet
        if let Some(assignment) = assignments.iter_mut().find(|p| {
            applicable(&tx_data, p)
                && (conflict_free || !p.has_tx_data_of_type(&tx_data.transaction_data_type))
        }) {
            assignment.transaction_data.push(tx_data.into());
        }
        // Try to make room by moving other tx_data assignments around
        else if let Some(slot) = reshuffle_existing_assignments(
            &tx_data.credential_query_ids,
            &tx_data.transaction_data_type,
            &mut assignments,
        ) && let Some(assignment) = assignments.get_mut(slot)
        {
            assignment.transaction_data.push(tx_data.into());
        }
        // Otherwise the transaction data conflicts with all applicable presentations and can
        // only be assigned by duplicating one, which the verifier must accept via the DCQL
        // `multiple` flag.
        else if let Some(assignment) = assignments.iter().find(|p| {
            applicable(&tx_data, p) && dcql_multiple(interaction_data, &p.credential_presentation)
        }) {
            assignments.push(assignment.duplicate(tx_data.into()));
        } else {
            return Err(VerificationProtocolError::InvalidTransactionDataAssignment(
                format!(
                    "no valid presentation to assign transaction data {id} of type `{}`",
                    tx_data.transaction_data_type
                ),
            ));
        }
    }
    Ok(assignments)
}

/// Reshuffle existing assignments to different presentations, so that an additional entry of
/// `data_type`, applicable to the credential queries listed in `query_ids`, can be placed.
///
/// Reshuffling happens between presentations (identified by their index in `assignments`),
/// not between credential queries: a query without a submitted credential is no place to put
/// an entry, and several presentations may answer the same credential query. Presentations
/// carrying a pinned entry of `data_type` are excluded entirely, as they can neither give up
/// their entry nor take another one.
///
/// Returns the index of the presentation the new entry can be assigned to, or `None` if no
/// arrangement gives every entry a presentation of its own (in which case `assignments`
/// remains untouched).
fn reshuffle_existing_assignments(
    query_ids: &[CredentialQueryId],
    data_type: &TransactionDataType,
    assignments: &mut [PresentationWithTxData],
) -> Option<usize> {
    // presentations able to carry an entry of `data_type`, with their credential query id
    let slots: Vec<(usize, CredentialQueryId)> = assignments
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.has_pinned_tx_data_of_type(data_type))
        .map(|(slot, p)| {
            (
                slot,
                p.credential_presentation.credential_query_id.to_owned(),
            )
        })
        .collect();
    let applicable_slots = |query_ids: &[CredentialQueryId]| -> Vec<usize> {
        slots
            .iter()
            .filter(|(_, query_id)| query_ids.contains(query_id))
            .map(|(slot, _)| *slot)
            .collect()
    };

    // The entries to be moved around, at most one per slot. All of them are auto-assigned,
    // as presentations with a pinned entry of this type are not eligible slots.
    let mut movable = Vec::with_capacity(slots.len());
    let mut applicable_credentials = Vec::with_capacity(slots.len() + 1);
    for (slot, _) in &slots {
        if let Some(presentation) = assignments.get(*slot)
            && let Some((entry, tx_data)) = presentation
                .transaction_data
                .iter()
                .enumerate()
                .find(|(_, tx)| &tx.r#type == data_type)
        {
            movable.push((*slot, entry));
            applicable_credentials.push(applicable_slots(&tx_data.query_ids));
        }
    }
    // last element is the new entry
    applicable_credentials.push(applicable_slots(query_ids));

    let new_assignments = assign_entries_to_distinct_credentials(&applicable_credentials)?;

    // retrieve the slot of the new entry (which is the last one, see above)
    let result = new_assignments.last().copied();

    // Move the other ones, if necessary. Removing before inserting keeps the entry indices
    // valid: each presentation gives up at most one entry, and received ones are appended.
    let mut moved = Vec::with_capacity(movable.len());
    for ((slot, entry), new_slot) in movable.into_iter().zip(new_assignments) {
        if slot != new_slot
            && let Some(presentation) = assignments.get_mut(slot)
            && entry < presentation.transaction_data.len()
        {
            moved.push((new_slot, presentation.transaction_data.remove(entry)));
        }
    }
    for (slot, tx_data) in moved {
        if let Some(presentation) = assignments.get_mut(slot) {
            presentation.transaction_data.push(tx_data);
        }
    }

    result
}

fn applicable(tx_data: &ValidatedHolderTxData, presentation: &PresentationWithTxData) -> bool {
    tx_data
        .credential_query_ids
        .contains(&presentation.credential_presentation.credential_query_id)
}

fn conflict_free_tx_data_type(
    transaction_data_provider: &dyn TransactionDataProvider,
    tx_data: &ValidatedHolderTxData,
) -> Result<bool, VerificationProtocolError> {
    let provider =
        transaction_data_provider.get_transaction_data_by_name(&tx_data.transaction_data_type)?;
    let conflict_free = provider
        .get_capabilities()
        .features
        .contains(&Features::SupportsMultipleTxDataPerPresentation);
    Ok(conflict_free)
}

/// Whether the relevant DCQL credential query has the `multiple` flag set to true.
fn dcql_multiple(
    interaction_data: &OpenID4VPHolderInteractionData,
    presentation: &FormattedCredentialPresentation,
) -> bool {
    interaction_data
        .dcql_query
        .credentials
        .iter()
        .find(|cq| cq.id == presentation.credential_query_id)
        .is_some_and(|cq| cq.multiple)
}
