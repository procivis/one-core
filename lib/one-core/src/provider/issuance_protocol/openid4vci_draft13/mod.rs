//! Implementation of OpenID4VCI.
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use indexmap::IndexMap;
use one_crypto::encryption::encrypt_string;
use one_dto_mapper::convert_inner;
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use shared_types::{CertificateId, CredentialId, DidValue, IdentifierId};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::dto::IssuanceProtocolCapabilities;
use super::{
    HandleInvitationOperationsAccess, IssuanceProtocol, IssuanceProtocolError, StorageAccess,
};
use crate::common_mapper::{DidRole, NESTED_CLAIM_MARKER};
use crate::common_validator::{validate_expiration_time, validate_issuance_time};
use crate::config::core_config::{CoreConfig, DatatypeType, DidType as ConfigDidType};
use crate::model::certificate::{Certificate, CertificateRelations, CertificateState};
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Clearable, Credential, CredentialRelations, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType,
    UpdateCredentialSchemaRequest,
};
use crate::model::did::{Did, DidRelations, DidType, KeyRole};
use crate::model::history::HistoryAction;
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierState, IdentifierType};
use crate::model::interaction::Interaction;
use crate::model::key::{Key, KeyRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::revocation_list::{
    RevocationListPurpose, StatusListCredentialFormat, StatusListType,
};
use crate::model::validity_credential::{Mdoc, ValidityCredentialType};
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::model::{CertificateDetails, IssuerDetails};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::ContextType;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::error::TxCodeError;
use crate::provider::issuance_protocol::mapper::{
    get_issued_credential_update, interaction_from_handle_invitation,
};
use crate::provider::issuance_protocol::openid4vci_draft13::mapper::{
    create_credential, get_credential_offer_url, map_offered_claims_to_credential_schema,
};
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    ExtendedSubjectDTO, HolderInteractionData, InvitationResponseDTO, OpenID4VCICredential,
    OpenID4VCICredentialConfigurationData, OpenID4VCICredentialDefinitionRequestDTO,
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialSubjectItem,
    OpenID4VCICredentialValueDetails, OpenID4VCIDiscoveryResponseDTO,
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCIParams,
    OpenID4VCIProof, OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO, ShareResponse,
    SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::openid4vci_draft13::proof_formatter::OpenID4VCIProofJWTFormatter;
use crate::provider::issuance_protocol::openid4vci_draft13::service::{
    create_credential_offer, get_protocol_base_url,
};
use crate::provider::issuance_protocol::openid4vci_draft13::utils::{
    deserialize_interaction_data, serialize_interaction_data,
};
use crate::provider::issuance_protocol::openid4vci_draft13::validator::validate_issuer;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::model::CredentialAdditionalData;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::revocation::{RevocationMethod, token_status_list};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::oid4vci_draft13::service::credentials_format;
use crate::util::history::log_history_event_credential;
use crate::util::key_verification::KeyVerification;
use crate::util::oidc::map_from_oidc_format_to_core_detailed;
use crate::util::params::convert_params;
use crate::util::revocation_update::{get_or_create_revocation_list_id, process_update};
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;

pub mod error;
pub mod handle_invitation_operations;
pub(crate) mod mapper;
pub mod model;
pub mod proof_formatter;
pub mod service;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_issuance;
mod utils;
pub mod validator;

const CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY: &str = "credential_offer";
const CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY: &str = "credential_offer_uri";

pub(crate) struct OpenID4VCI13 {
    client: Arc<dyn HttpClient>,
    credential_repository: Arc<dyn CredentialRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    base_url: Option<String>,
    protocol_base_url: Option<String>,
    config: Arc<CoreConfig>,
    params: OpenID4VCIParams,
}

impl OpenID4VCI13 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        credential_repository: Arc<dyn CredentialRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCIParams,
    ) -> Self {
        let protocol_base_url = base_url.as_ref().map(|url| get_protocol_base_url(url));
        Self {
            client,
            credential_repository,
            validity_credential_repository,
            revocation_list_repository,
            history_repository,
            formatter_provider,
            revocation_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            base_url,
            protocol_base_url,
            config,
            params,
            certificate_validator,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_custom_version(
        client: Arc<dyn HttpClient>,
        credential_repository: Arc<dyn CredentialRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCIParams,
        protocol_version: &str,
    ) -> Self {
        let protocol_base_url = base_url
            .as_ref()
            .map(|url| format!("{url}/ssi/openid4vci/{protocol_version}"));
        Self {
            client,
            credential_repository,
            validity_credential_repository,
            revocation_list_repository,
            history_repository,
            formatter_provider,
            revocation_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            base_url,
            protocol_base_url,
            config,
            params,
            certificate_validator,
        }
    }

    async fn validate_credential_issuable(
        &self,
        credential_id: &CredentialId,
        latest_state: &CredentialStateEnum,
        credential_schema: &CredentialSchema,
    ) -> Result<(), IssuanceProtocolError> {
        match (latest_state, credential_schema.format.as_str()) {
            (CredentialStateEnum::Accepted, "MDOC") => {
                let mdoc_validity_credential = self
                    .validity_credential_repository
                    .get_latest_by_credential_id(*credential_id, ValidityCredentialType::Mdoc)
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
                    .ok_or_else(|| {
                        IssuanceProtocolError::Failed(format!(
                            "Missing verifiable credential for MDOC: {credential_id}"
                        ))
                    })?;

                let can_be_updated_at =
                    mdoc_validity_credential.created_date + self.mso_minimum_refresh_time()?;

                if can_be_updated_at > OffsetDateTime::now_utc() {
                    return Err(IssuanceProtocolError::InvalidRequest("expired".to_string()));
                }
            }
            (CredentialStateEnum::Offered, _) => {}
            _ => {
                return Err(IssuanceProtocolError::InvalidRequest(
                    "invalid state".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn mso_minimum_refresh_time(&self) -> Result<Duration, IssuanceProtocolError> {
        self.config
            .format
            .get::<mdoc_formatter::Params>("MDOC")
            .map(|p| p.mso_minimum_refresh_time)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))
    }

    async fn process_revocation_method(
        &self,
        credential: &mut Credential,
        credential_schema: &CredentialSchema,
        revocation_method: &Arc<dyn RevocationMethod>,
    ) -> Result<Option<CredentialAdditionalData>, IssuanceProtocolError> {
        if credential_schema.revocation_method != StatusListType::BitstringStatusList.to_string()
            && credential_schema.revocation_method != StatusListType::TokenStatusList.to_string()
        {
            // TODO ONE-5920: Early exit to avoid mandating issuer did for MSO MDOC suspension. Clean up, once certificates are properly supported for TokenStatusList as well.
            return Ok(None);
        }

        let issuer_did = credential
            .issuer_identifier
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "issuer_identifier is None".to_string(),
            ))?
            .did
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "issuer_did is None".to_string(),
            ))?;
        let did_document = self
            .did_method_provider
            .resolve(&issuer_did.did)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        let key_id = did_document
            .find_verification_method(None, Some(KeyRole::AssertionMethod))
            .ok_or(IssuanceProtocolError::Failed(
                "invalid issuer did".to_string(),
            ))?
            .id
            .to_owned();

        let credentials_by_issuer_did = convert_inner(
            self.credential_repository
                .get_credentials_by_issuer_did_id(&issuer_did.id, &CredentialRelations::default())
                .await
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
        );
        // TODO: refactor this when refactoring the formatters as it makes no sense for to construct this for LVVC
        let credential_data = if credential_schema.revocation_method
            == StatusListType::BitstringStatusList.to_string()
        {
            let crate::provider::revocation::bitstring_status_list::Params { format } =
                convert_params(
                    revocation_method
                        .get_params()
                        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
                )
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

            let status_list_format = if format == StatusListCredentialFormat::JsonLdClassic
                && credential_schema.format == "JSON_LD_BBSPLUS"
            {
                "JSON_LD_BBSPLUS".to_string()
            } else {
                format.to_string()
            };

            let formatter = self
                .formatter_provider
                .get_formatter(&status_list_format)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "formatter not found: {status_list_format}"
                )))?;

            Some(CredentialAdditionalData {
                credentials_by_issuer_did: convert_inner(credentials_by_issuer_did.to_owned()),
                revocation_list_id: get_or_create_revocation_list_id(
                    &credentials_by_issuer_did,
                    issuer_did,
                    RevocationListPurpose::Revocation,
                    &*self.revocation_list_repository,
                    &self.key_provider,
                    &self.key_algorithm_provider,
                    &self.base_url,
                    &*formatter,
                    key_id.clone(),
                    &StatusListType::BitstringStatusList,
                    &format,
                )
                .await
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
                suspension_list_id: Some(
                    get_or_create_revocation_list_id(
                        &credentials_by_issuer_did,
                        issuer_did,
                        RevocationListPurpose::Suspension,
                        &*self.revocation_list_repository,
                        &self.key_provider,
                        &self.key_algorithm_provider,
                        &self.base_url,
                        &*formatter,
                        key_id,
                        &StatusListType::BitstringStatusList,
                        &format,
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
                ),
            })
        } else if credential_schema.revocation_method == StatusListType::TokenStatusList.to_string()
        {
            let token_status_list::Params { format } = convert_params(
                revocation_method
                    .get_params()
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
            )
            .unwrap_or_default();

            let formatter = self
                .formatter_provider
                .get_formatter(&format.to_string())
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "formatter not found: {format}"
                )))?;

            Some(CredentialAdditionalData {
                credentials_by_issuer_did: convert_inner(credentials_by_issuer_did.to_owned()),
                revocation_list_id: get_or_create_revocation_list_id(
                    &credentials_by_issuer_did,
                    issuer_did,
                    RevocationListPurpose::Revocation,
                    &*self.revocation_list_repository,
                    &self.key_provider,
                    &self.key_algorithm_provider,
                    &self.base_url,
                    &*formatter,
                    key_id.clone(),
                    &StatusListType::TokenStatusList,
                    &format,
                )
                .await
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
                suspension_list_id: None,
            })
        } else {
            None
        };

        Ok(credential_data)
    }

    async fn jwk_key_id_from_identifier(
        &self,
        issuer_identifier: &Identifier,
        key: &Key,
    ) -> Result<Option<String>, IssuanceProtocolError> {
        let Some(ref did) = issuer_identifier.did else {
            return Ok(None);
        };

        let did_document = self
            .did_method_provider
            .resolve(&did.did)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        let assertion_methods =
            did_document
                .assertion_method
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing assertion_method keys".to_owned(),
                ))?;

        let issuer_jwk_key_id = match assertion_methods
            .iter()
            .find(|id| id.contains(&key.id.to_string()))
            .cloned()
        {
            Some(id) => id,
            None => assertion_methods
                .first()
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing first assertion_method key".to_owned(),
                ))?
                .to_owned(),
        };
        Ok(Some(issuer_jwk_key_id))
    }
}

#[async_trait]
impl IssuanceProtocol for OpenID4VCI13 {
    fn holder_can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.params.url_scheme == url.scheme()
            && (query_has_key(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY)
                || query_has_key(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY))
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, IssuanceProtocolError> {
        if !self.holder_can_handle(&url) {
            return Err(IssuanceProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ));
        }

        handle_credential_invitation(
            url,
            organisation,
            &self.client,
            storage_access,
            handle_invitation_operations,
        )
        .await
    }

    async fn holder_accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError> {
        let schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("schema is None".to_string()))?;

        let mut interaction = credential
            .interaction
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .to_owned();

        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data)?;

        let token_endpoint =
            interaction_data
                .token_endpoint
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "token endpoint is missing".to_string(),
                ))?;

        let grants = interaction_data
            .grants
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "grants data is missing".to_string(),
            ))?;

        let token_response: OpenID4VCITokenResponseDTO = async {
            let has_sent_tx_code = tx_code.is_some();

            let request = self
                .client
                .post(token_endpoint.as_str())
                .form(&OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                    pre_authorized_code: grants.code.pre_authorized_code.clone(),
                    tx_code,
                })
                .context("Invalid token_endpoint request")
                .map_err(IssuanceProtocolError::Transport)?;

            let response = request
                .send()
                .await
                .context("Error during token_endpoint response")
                .map_err(IssuanceProtocolError::Transport)?;

            if response.status.is_client_error() && has_sent_tx_code {
                #[derive(Deserialize)]
                struct ErrorResponse {
                    error: OpenId4VciError,
                }

                #[derive(Deserialize)]
                #[serde(rename_all = "snake_case")]
                enum OpenId4VciError {
                    InvalidGrant,
                    InvalidRequest,
                }

                match serde_json::from_slice::<ErrorResponse>(&response.body).map(|r| r.error) {
                    Ok(OpenId4VciError::InvalidGrant) => {
                        return Err(IssuanceProtocolError::TxCode(TxCodeError::IncorrectCode));
                    }
                    Ok(OpenId4VciError::InvalidRequest) => {
                        return Err(IssuanceProtocolError::TxCode(TxCodeError::InvalidCodeUse));
                    }
                    Err(_) => {}
                }
            }

            response
                .error_for_status()
                .context("status error")
                .map_err(IssuanceProtocolError::Transport)?
                .json()
                .context("parsing error")
                .map_err(IssuanceProtocolError::Transport)
        }
        .await?;

        // only mdoc credentials support refreshing, do not store the tokens otherwise
        if format == "mso_mdoc" {
            let encrypted_access_token = encrypt_string(
                &token_response.access_token,
                &self.params.encryption,
            )
            .map_err(|err| {
                IssuanceProtocolError::Failed(format!("failed to encrypt access token: {err}"))
            })?;
            interaction_data.access_token = Some(encrypted_access_token);
            interaction_data.access_token_expires_at =
                OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();
            interaction_data.refresh_token = token_response
                .refresh_token
                .map(|token| encrypt_string(&token, &self.params.encryption))
                .transpose()
                .map_err(|err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt refresh token: {err}"))
                })?;
            interaction_data.refresh_token_expires_at = token_response
                .refresh_token_expires_in
                .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok());
        }

        let data = serialize_interaction_data(&interaction_data)?;
        interaction.data = Some(data);

        storage_access
            .update_interaction(interaction.into())
            .await
            .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(
                &key.to_owned(),
                jwk_key_id.clone(),
                self.key_algorithm_provider.clone(),
            )
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        // Very basic support for JWK as crypto binding method for EUDI
        let jwk = match interaction_data.cryptographic_binding_methods_supported {
            Some(methods) => {
                // Prefer kid-based holder binding proofs instead of using jwk because
                // that way the did does not need to be resolved.
                if methods
                    .iter()
                    .any(|method| holder_did.did.as_str().starts_with(method.as_str()))
                    // swiyu specific workaround: in the swiyu configuration did:jwk is specified, but jwk is expected instead
                    && methods != vec!["did:jwk".to_string()]
                {
                    None
                } else if methods.contains(&"jwk".to_string())
                    // swiyu specific workaround
                    || methods == vec!["did:jwk".to_string()]
                {
                    let resolved = self
                        .did_method_provider
                        .resolve(&holder_did.did)
                        .await
                        .map_err(|_| {
                            IssuanceProtocolError::Failed(
                                "Could not resolve did method".to_string(),
                            )
                        })?;

                    Some(
                        resolved
                            .verification_method
                            .first()
                            .ok_or(IssuanceProtocolError::Failed(
                                "Could find verification method in resolved did document"
                                    .to_string(),
                            ))?
                            .public_key_jwk
                            .clone()
                            .into(),
                    )
                } else {
                    None
                }
            }
            None => None,
        };

        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url,
            jwk_key_id,
            jwk,
            token_response.c_nonce,
            auth_fn,
        )
        .await
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let (credential_definition, doctype) = match format {
            "mso_mdoc" => (None, Some(schema.schema_id.to_owned())),
            _ => (
                Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
                }),
                None,
            ),
        };

        let body = OpenID4VCICredential {
            format: format.to_owned(),
            vct: (schema.schema_type == CredentialSchemaType::SdJwtVc)
                .then_some(schema.schema_id.to_owned()),
            doctype,
            proof: OpenID4VCIProof {
                proof_type: "jwt".to_string(),
                jwt: proof_jwt,
            },
            credential_definition,
        };

        let response = self
            .client
            .post(interaction_data.credential_endpoint.as_str())
            .bearer_auth(token_response.access_token.expose_secret())
            .json(&body)
            .context("json error")
            .map_err(IssuanceProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?;

        let response = response
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?;
        let response_value: SubmitIssuerResponse = response
            .json()
            .context("parsing error")
            .map_err(IssuanceProtocolError::Transport)?;

        fn detect_format_with_crypto_suite(
            credential_schema_format: &str,
            credential_content: &str,
        ) -> anyhow::Result<String> {
            let format = if credential_schema_format.starts_with("JSON_LD") {
                map_from_oidc_format_to_core_detailed("ldp_vc", Some(credential_content))
                    .map_err(|_| anyhow::anyhow!("Credential format not resolved"))?
            } else {
                credential_schema_format.to_owned()
            };
            Ok(format)
        }

        let real_format =
            detect_format_with_crypto_suite(&schema.format, &response_value.credential)
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let formatter = self
            .formatter_provider
            .get_formatter(&real_format)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!("{} formatter not found", schema.format))
            })?;

        let verification_fn = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });
        let response_credential = formatter
            .extract_credentials(
                &response_value.credential,
                credential.schema.as_ref(),
                verification_fn,
                None,
            )
            .await
            .map_err(|e| IssuanceProtocolError::CredentialVerificationFailed(e.into()))?;

        validate_issuance_time(&response_credential.valid_from, formatter.get_leeway())
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        validate_expiration_time(&response_credential.valid_until, formatter.get_leeway())
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        validate_issuer(
            credential,
            &response_credential,
            &*self.certificate_validator,
        )
        .await?;

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

        // Revocation method must be updated based on the issued credential (unknown in credential offer).
        // Revocation method should be the same for every credential in list.
        let revocation_method = if let Some(credential_status) = response_credential.status.first()
        {
            let (_, revocation_method) = self
                .revocation_provider
                .get_revocation_method_by_status_type(&credential_status.r#type)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "Revocation method not found for status type {}",
                    credential_status.r#type
                )))?;
            Some(revocation_method)
        } else {
            None
        };

        let organisation = schema
            .organisation
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "Missing credential schema organisation".to_string(),
            ))?;

        let identifier_updates = match response_credential.issuer {
            IssuerDetails::Did(did) => {
                prepare_did_identifier(
                    did,
                    organisation,
                    storage_access,
                    &*self.did_method_provider,
                )
                .await?
            }
            IssuerDetails::Certificate(CertificateDetails {
                chain,
                fingerprint,
                expiry,
            }) => {
                prepare_certificate_identifier(
                    chain,
                    fingerprint,
                    expiry,
                    organisation,
                    storage_access,
                )
                .await?
            }
        };
        let redirect_uri = response_value.redirect_uri.clone();

        Ok(UpdateResponse {
            result: response_value,
            create_did: identifier_updates.create_did,
            create_certificate: identifier_updates.create_certificate,
            create_identifier: identifier_updates.create_identifier,
            update_credential_schema: Some(UpdateCredentialSchemaRequest {
                id: schema.id,
                revocation_method,
                format: Some(real_format),
                claim_schemas: None,
                layout_type,
                layout_properties,
            }),
            update_credential: Some((
                credential.id,
                UpdateCredentialRequest {
                    issuer_identifier_id: Some(identifier_updates.issuer_identifier_id),
                    issuer_certificate_id: identifier_updates.issuer_certificate_id,
                    redirect_uri: Some(redirect_uri),
                    suspend_end_date: Clearable::DontTouch,
                    ..Default::default()
                },
            )),
        })
    }

    async fn holder_reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), IssuanceProtocolError> {
        Err(IssuanceProtocolError::OperationNotSupported)
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse<Value>, IssuanceProtocolError> {
        let interaction_id = Uuid::new_v4();

        let mut url = Url::parse(&format!("{}://", self.params.url_scheme))
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        let mut query = url.query_pairs_mut();

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "credential schema missing".to_string(),
            ))?;

        let protocol_base_url = self
            .protocol_base_url
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing base_url".to_owned()))?;

        let wallet_storage_type = credential_schema.wallet_storage_type.clone();

        let claims = credential
            .claims
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing claims".to_owned()))?
            .iter()
            .map(|claim| claim.to_owned())
            .collect::<Vec<_>>();

        let credential_subject = credentials_format(wallet_storage_type, &claims)
            .map_err(|e| IssuanceProtocolError::Other(e.into()))?;

        if self.params.credential_offer_by_value {
            let issuer_did = credential
                .issuer_identifier
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing issuer_identifier".to_owned(),
                ))?
                .did
                .as_ref()
                .map(|did| did.did.clone());
            let offer = create_credential_offer(
                protocol_base_url,
                &interaction_id.to_string(),
                issuer_did,
                &credential_schema.id,
                &credential_schema.schema_id,
                credential_subject,
            )
            .map_err(|e| IssuanceProtocolError::Other(e.into()))?;

            let offer_string = serde_json::to_string(&offer)
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

            query.append_pair(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY, &offer_string);
        } else {
            let offer_url = get_credential_offer_url(protocol_base_url.to_owned(), credential)?;
            query.append_pair(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY, &offer_url);
        }

        Ok(ShareResponse {
            url: query.finish().to_string(),
            interaction_id,
            context: json!(OpenID4VCIIssuerInteractionDataDTO {
                pre_authorized_code_used: false,
                access_token_hash: vec![],
                access_token_expires_at: None,
                refresh_token_hash: None,
                refresh_token_expires_at: None,
                nonce: None,
            }),
        })
    }

    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_did: Did,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        let Some(mut credential) = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    issuer_certificate: Some(CertificateRelations::default()),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
        else {
            return Err(IssuanceProtocolError::Failed(
                "Credential not found".to_string(),
            ));
        };

        credential.holder_identifier = Some(holder_identifier.clone());

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "credential_schema is None".to_string(),
            ))?
            .clone();
        let credential_state = credential.state;

        self.validate_credential_issuable(credential_id, &credential_state, &credential_schema)
            .await?;

        let format = credential_schema.format.to_owned();

        let revocation_method = self
            .revocation_provider
            .get_revocation_method(&credential_schema.revocation_method)
            .ok_or(IssuanceProtocolError::Failed(format!(
                "revocation method not found: {}",
                credential_schema.revocation_method
            )))?;

        let mut credential_additional_data = None;
        if credential_schema.revocation_method != "NONE" {
            credential_additional_data = self
                .process_revocation_method(&mut credential, &credential_schema, &revocation_method)
                .await?;
        }
        let (update, status) = revocation_method
            .add_issued_credential(&credential, credential_additional_data)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        if let Some(update) = update {
            process_update(
                update,
                &*self.validity_credential_repository,
                &*self.revocation_list_repository,
            )
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        }

        let credential_status = status
            .into_iter()
            .map(|revocation_info| revocation_info.credential_status)
            .collect();

        let key = credential
            .key
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing key".to_string()))?;

        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "missing issuer identifier".to_string(),
                ))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(
                &key.to_owned(),
                self.jwk_key_id_from_identifier(issuer_identifier, key)
                    .await?,
                self.key_algorithm_provider.clone(),
            )
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let redirect_uri = credential.redirect_uri.to_owned();

        let core_base_url = self.base_url.as_ref().ok_or(IssuanceProtocolError::Failed(
            "Missing core_base_url for credential issuance".to_string(),
        ))?;

        // TODO - remove organisation usage from here when moved to open core
        let credential_detail =
            credential_detail_response_from_model(credential.clone(), &self.config, None)
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let additional_contexts = revocation_method
            .get_json_ld_context()
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .url
            .map(|ctx| ctx.parse().map(|ctx| vec![ContextType::Url(ctx)]))
            .transpose()
            .map_err(|_err| {
                IssuanceProtocolError::Failed(
                    "Provided JSON-LD context URL is not a valid URL".to_owned(),
                )
            })?;
        let contexts = vcdm_v2_base_context(additional_contexts);
        let credential_data = credential_data_from_credential_detail_response(
            credential_detail,
            credential.issuer_certificate.clone(),
            holder_did.did,
            holder_key_id,
            core_base_url,
            credential_status,
            contexts,
        )
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let token = self
            .formatter_provider
            .get_formatter(&format)
            .ok_or(IssuanceProtocolError::Failed(format!(
                "formatter not found: {format}"
            )))?
            .format_credential(credential_data, auth_fn)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        match (credential_schema.schema_type, credential_state) {
            (CredentialSchemaType::Mdoc, CredentialStateEnum::Accepted) => {
                self.validity_credential_repository
                    .insert(
                        Mdoc {
                            id: Uuid::new_v4(),
                            created_date: OffsetDateTime::now_utc(),
                            credential: token.as_bytes().to_vec(),
                            linked_credential_id: *credential_id,
                        }
                        .into(),
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
            }
            (CredentialSchemaType::Mdoc, CredentialStateEnum::Offered) => {
                log_history_event_credential(
                    &*self.history_repository,
                    &credential,
                    HistoryAction::Issued,
                )
                .await;
                self.credential_repository
                    .update_credential(
                        *credential_id,
                        get_issued_credential_update(&token, holder_identifier.id),
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

                self.validity_credential_repository
                    .insert(
                        Mdoc {
                            id: Uuid::new_v4(),
                            created_date: OffsetDateTime::now_utc(),
                            credential: token.as_bytes().to_vec(),
                            linked_credential_id: *credential_id,
                        }
                        .into(),
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
            }
            _ => {
                log_history_event_credential(
                    &*self.history_repository,
                    &credential,
                    HistoryAction::Issued,
                )
                .await;
                self.credential_repository
                    .update_credential(
                        *credential_id,
                        get_issued_credential_update(&token, holder_identifier.id),
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
            }
        }

        Ok(SubmitIssuerResponse {
            credential: token,
            redirect_uri,
        })
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        IssuanceProtocolCapabilities {
            did_methods: vec![
                ConfigDidType::Key,
                ConfigDidType::Jwk,
                ConfigDidType::Web,
                ConfigDidType::MDL,
                ConfigDidType::WebVh,
            ],
        }
    }
}

async fn handle_credential_invitation(
    invitation_url: Url,
    organisation: Organisation,
    client: &Arc<dyn HttpClient>,
    storage_access: &StorageAccess,
    handle_invitation_operations: &HandleInvitationOperationsAccess,
) -> Result<InvitationResponseDTO, IssuanceProtocolError> {
    let credential_offer = resolve_credential_offer(client, invitation_url).await?;

    let issuer = match credential_offer.issuer_did {
        Some(issuer_did) => {
            let (_, identifier) = storage_access
                .get_or_create_did_and_identifier(
                    &Some(organisation.clone()),
                    &issuer_did,
                    DidRole::Issuer,
                )
                .await
                .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;
            Some(identifier)
        }
        None => None,
    };

    let tx_code = credential_offer.grants.code.tx_code.clone();

    let credential_issuer_endpoint: Url =
        credential_offer.credential_issuer.parse().map_err(|_| {
            IssuanceProtocolError::Failed(format!(
                "Invalid credential issuer url {}",
                credential_offer.credential_issuer
            ))
        })?;

    let (oicd_discovery, issuer_metadata) =
        get_discovery_and_issuer_metadata(client.as_ref(), &credential_issuer_endpoint).await?;

    // We only support one credential at the time now
    let configuration_id = credential_offer
        .credential_configuration_ids
        .first()
        .ok_or_else(|| {
            IssuanceProtocolError::Failed("Credential offer is missing credentials".to_string())
        })?;

    let credential_config = issuer_metadata
        .credential_configurations_supported
        .get(configuration_id)
        .ok_or_else(|| {
            IssuanceProtocolError::Failed(format!(
                "Credential configuration is missing for {configuration_id}"
            ))
        })?;

    let schema_data =
        handle_invitation_operations.find_schema_data(credential_config, configuration_id)?;

    let holder_data = HolderInteractionData {
        issuer_url: issuer_metadata.credential_issuer.clone(),
        credential_endpoint: issuer_metadata.credential_endpoint.clone(),
        token_endpoint: Some(oicd_discovery.token_endpoint),
        grants: Some(credential_offer.grants),
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        credential_signing_alg_values_supported: credential_config
            .credential_signing_alg_values_supported
            .clone(),
        cryptographic_binding_methods_supported: credential_config
            .cryptographic_binding_methods_supported
            .clone(),
    };
    let data = utils::serialize_interaction_data(&holder_data)?;

    let interaction = create_and_store_interaction(
        storage_access,
        credential_issuer_endpoint,
        data,
        Some(organisation.clone()),
    )
    .await?;
    let interaction_id = interaction.id;

    let claims_with_opt_values =
        build_claim_keys(credential_config, &credential_offer.credential_subject);

    let credential_id: CredentialId = Uuid::new_v4().into();
    let (claims, credential_schema) = match storage_access
        .get_schema(&schema_data.id, &schema_data.r#type, organisation.id)
        .await
        .map_err(IssuanceProtocolError::StorageAccessError)?
    {
        Some(credential_schema) => {
            if credential_schema.schema_type.to_string() != schema_data.r#type {
                return Err(IssuanceProtocolError::IncorrectCredentialSchemaType);
            }

            let claims_with_values = claims_with_opt_values.and_then(|claim_keys| {
                map_offered_claims_to_credential_schema(
                    &credential_schema,
                    credential_id,
                    &claim_keys,
                )
            });

            let claims = match (claims_with_values, credential_schema.external_schema) {
                (Ok(claims_with_values), _) => claims_with_values,
                (Err(_), true) => {
                    let claim_schemas = credential_schema.claim_schemas.as_ref().ok_or(
                        IssuanceProtocolError::Failed(
                            "Missing claim schemas for existing credential schema".to_string(),
                        ),
                    )?;

                    claim_schemas
                        .iter()
                        .filter_map(|claim_schema| {
                            let default_value = if claim_schema.schema.data_type
                                == DatatypeType::Boolean.to_string()
                            {
                                "false"
                            } else if claim_schema.schema.data_type
                                == DatatypeType::Number.to_string()
                            {
                                "0"
                            } else {
                                ""
                            };

                            if claim_schema.schema.data_type != DatatypeType::Object.to_string() {
                                Some(Claim {
                                    id: Uuid::new_v4(),
                                    credential_id,
                                    created_date: OffsetDateTime::now_utc(),
                                    last_modified: OffsetDateTime::now_utc(),
                                    value: default_value.to_string(),
                                    path: claim_schema.schema.key.clone(),
                                    schema: Some(claim_schema.schema.clone()),
                                })
                            } else {
                                None
                            }
                        })
                        .collect()
                }
                (Err(e), false) => Err(e)?,
            };

            (claims, credential_schema)
        }
        None => {
            let response = handle_invitation_operations
                .create_new_schema(
                    schema_data,
                    &claims_with_opt_values?,
                    &credential_id,
                    credential_config,
                    &issuer_metadata,
                    organisation.clone(),
                )
                .await?;
            (response.claims, response.schema)
        }
    };

    let credential = create_credential(
        credential_id,
        credential_schema,
        claims,
        interaction,
        None,
        issuer,
    );

    Ok(InvitationResponseDTO {
        interaction_id,
        credentials: vec![credential],
        tx_code,
    })
}

async fn resolve_credential_offer(
    client: &Arc<dyn HttpClient>,
    invitation_url: Url,
) -> Result<OpenID4VCICredentialOfferDTO, IssuanceProtocolError> {
    let query_pairs: HashMap<_, _> = invitation_url.query_pairs().collect();
    let credential_offer_param = query_pairs.get(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY);
    let credential_offer_reference_param =
        query_pairs.get(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY);

    if credential_offer_param.is_some() && credential_offer_reference_param.is_some() {
        return Err(IssuanceProtocolError::Failed(format!(
            "Detected both {CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY} and {CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY}"
        )));
    }

    if let Some(credential_offer) = credential_offer_param {
        serde_json::from_str(credential_offer).map_err(|error| {
            IssuanceProtocolError::Failed(format!("Failed decoding credential offer {error}"))
        })
    } else if let Some(credential_offer_reference) = credential_offer_reference_param {
        let credential_offer_url = Url::parse(credential_offer_reference).map_err(|error| {
            IssuanceProtocolError::Failed(format!("Failed decoding credential offer url {error}"))
        })?;

        Ok(client
            .get(credential_offer_url.as_str())
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?
            .json()
            .map_err(|error| {
                IssuanceProtocolError::Failed(format!(
                    "Failed decoding credential offer json {error}"
                ))
            })?)
    } else {
        Err(IssuanceProtocolError::Failed(
            "Missing credential offer param".to_string(),
        ))
    }
}

async fn get_discovery_and_issuer_metadata(
    client: &dyn HttpClient,
    credential_issuer_endpoint: &Url,
) -> Result<
    (
        OpenID4VCIDiscoveryResponseDTO,
        OpenID4VCIIssuerMetadataResponseDTO,
    ),
    IssuanceProtocolError,
> {
    async fn fetch<T: DeserializeOwned>(
        client: &dyn HttpClient,
        endpoint: String,
    ) -> Result<T, IssuanceProtocolError> {
        client
            .get(&endpoint)
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(IssuanceProtocolError::Transport)
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
    organisation: Option<Organisation>,
) -> Result<Interaction, IssuanceProtocolError> {
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
        .map_err(IssuanceProtocolError::StorageAccessError)?;

    Ok(interaction)
}

fn build_claim_keys(
    credential_configuration: &OpenID4VCICredentialConfigurationData,
    credential_subject: &Option<ExtendedSubjectDTO>,
) -> Result<IndexMap<String, OpenID4VCICredentialValueDetails>, IssuanceProtocolError> {
    let claim_object = match (
        &credential_configuration.credential_definition,
        &credential_configuration.claims,
    ) {
        (None, None) | (Some(_), Some(_)) => {
            return Err(IssuanceProtocolError::Failed(
                "Incorrect or missing credential claims".to_string(),
            ));
        }
        (None, Some(mdoc_claims)) => mdoc_claims,
        (Some(credential_definition), None) => credential_definition
            .credential_subject
            .as_ref()
            .ok_or_else(|| {
                IssuanceProtocolError::Failed("Missing credential subject".to_string())
            })?,
    };

    let keys = credential_subject
        .as_ref()
        .and_then(|cs| cs.keys.clone())
        .unwrap_or_default();

    if !keys.claims.is_empty() {
        return Ok(keys.claims);
    }
    // WORKAROUND
    // Logic somewhere later expects values to be provided at this point. We don't have them for e.g. external credentials
    // hence we fulfill mandatory fields with empty values. The logic will later be reworked to provide no claims in case
    // there is no credential definition
    let missing_keys = collect_mandatory_keys(claim_object, None);
    Ok(missing_keys
        .into_iter()
        .map(|(missing_claim_path, value_type)| {
            (
                missing_claim_path,
                OpenID4VCICredentialValueDetails {
                    value: "".to_owned(),
                    value_type,
                },
            )
        })
        .collect())
    //END OF WORKAROUND
}

fn collect_mandatory_keys(
    claim_object: &OpenID4VCICredentialSubjectItem,
    item_path: Option<&str>,
) -> Vec<(String, String)> {
    let mut item_paths = Vec::new();

    if let Some(claims) = claim_object.claims.as_ref() {
        for (key, object) in claims {
            let path = if let Some(item_path) = &item_path {
                format!("{item_path}{}{key}", NESTED_CLAIM_MARKER)
            } else {
                key.to_owned()
            };
            let paths = collect_mandatory_keys(object, Some(&path));

            item_paths.extend(paths);
        }
    }

    if let Some(arrays) = claim_object.arrays.as_ref() {
        for (key, object_definitions) in arrays {
            if let Some(object_fields) = object_definitions.first() {
                let path = if let Some(item_path) = &item_path {
                    format!(
                        "{item_path}{}{key}{}0",
                        NESTED_CLAIM_MARKER, NESTED_CLAIM_MARKER
                    )
                } else {
                    format!("{key}{}0", NESTED_CLAIM_MARKER)
                };
                let paths = collect_mandatory_keys(object_fields, Some(&path));

                item_paths.extend(paths);
            }
        }
    }

    // Break condition - we reached top claim and it suppose to have a value
    if claim_object.arrays.is_none() && claim_object.claims.is_none() {
        item_paths.push((
            item_path.unwrap_or_default().to_string(),
            claim_object
                .value_type
                .as_ref()
                .cloned()
                .unwrap_or("STRING".to_owned()),
        ));
    }

    item_paths
}

struct IdentifierUpdates {
    issuer_identifier_id: IdentifierId,
    issuer_certificate_id: Option<CertificateId>,
    create_did: Option<Did>,
    create_identifier: Option<Identifier>,
    create_certificate: Option<Certificate>,
}

async fn prepare_did_identifier(
    issuer_did_value: DidValue,
    organisation: &Organisation,
    storage_access: &StorageAccess,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<IdentifierUpdates, IssuanceProtocolError> {
    match storage_access
        .get_did_by_value(&issuer_did_value, organisation.id)
        .await
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?
    {
        Some(did) => {
            let identifier = storage_access
                .get_identifier_for_did(&did.id)
                .await
                .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

            Ok(IdentifierUpdates {
                issuer_identifier_id: identifier.id,
                issuer_certificate_id: None,
                create_did: None,
                create_identifier: None,
                create_certificate: None,
            })
        }
        None => {
            let now = OffsetDateTime::now_utc();
            let did_method = did_method_provider
                .get_did_method_id(&issuer_did_value)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "unsupported issuer did method: {issuer_did_value}"
                )))?;
            let id = Uuid::new_v4().into();
            let did = Did {
                id,
                name: format!("issuer {id}"),
                created_date: now,
                last_modified: now,
                did: issuer_did_value,
                did_type: DidType::Remote,
                did_method,
                keys: None,
                deactivated: false,
                organisation: Some(organisation.clone()),
                log: None,
            };

            let id: IdentifierId = Uuid::new_v4().into();
            Ok(IdentifierUpdates {
                issuer_identifier_id: id,
                issuer_certificate_id: None,
                create_did: Some(did.to_owned()),
                create_identifier: Some(Identifier {
                    id,
                    name: did.name.to_owned(),
                    created_date: now,
                    last_modified: now,
                    did: Some(did),
                    key: None,
                    certificates: None,
                    is_remote: true,
                    deleted_at: None,
                    r#type: IdentifierType::Did,
                    state: IdentifierState::Active,
                    organisation: Some(organisation.clone()),
                }),
                create_certificate: None,
            })
        }
    }
}

async fn prepare_certificate_identifier(
    chain: String,
    fingerprint: String,
    expiry: OffsetDateTime,
    organisation: &Organisation,
    storage_access: &StorageAccess,
) -> Result<IdentifierUpdates, IssuanceProtocolError> {
    match storage_access
        .get_certificate_by_fingerprint(&fingerprint, organisation.id)
        .await
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?
    {
        Some(certificate) => Ok(IdentifierUpdates {
            issuer_identifier_id: certificate.identifier_id,
            issuer_certificate_id: Some(certificate.id),
            create_did: None,
            create_identifier: None,
            create_certificate: None,
        }),

        None => {
            let now = OffsetDateTime::now_utc();
            let id = Uuid::new_v4().into();
            let identifier_id: IdentifierId = Uuid::new_v4().into();
            let certificate = Certificate {
                id,
                identifier_id,
                name: format!("issuer certificate {id}"),
                chain,
                fingerprint,
                state: CertificateState::Active,
                created_date: now,
                last_modified: now,
                organisation_id: Some(organisation.id),
                expiry_date: expiry,
                key: None,
            };

            Ok(IdentifierUpdates {
                issuer_identifier_id: identifier_id,
                issuer_certificate_id: Some(certificate.id),
                create_did: None,
                create_identifier: Some(Identifier {
                    id: identifier_id,
                    name: format!("issuer {identifier_id}"),
                    created_date: now,
                    last_modified: now,
                    did: None,
                    key: None,
                    certificates: None,
                    is_remote: true,
                    deleted_at: None,
                    r#type: IdentifierType::Certificate,
                    state: IdentifierState::Active,
                    organisation: Some(organisation.clone()),
                }),
                create_certificate: Some(certificate),
            })
        }
    }
}
