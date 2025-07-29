use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use super::VCAPIService;
use super::dto::{
    CredentialIssueOptions, CredentialIssueRequest, CredentialIssueResponse,
    CredentialVerifiyRequest, CredentialVerifyResponse, PresentationVerifyRequest,
    PresentationVerifyResponse,
};
use super::validation::{validate_verifiable_credential, validate_verifiable_presentation};
use crate::config::core_config::VerificationProtocolType;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::did::{DidRelations, KeyRole};
use crate::model::key::KeyRelations;
use crate::model::revocation_list::{RevocationListPurpose, StatusListType};
use crate::provider::caching_loader::json_ld_context::ContextCache;
use crate::provider::credential_formatter::model::CredentialData;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::ExtractPresentationCtx;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::bitstring_status_list;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::error::{MissingProviderError, ServiceError};
use crate::service::vc_api::model::LdCredential;
use crate::util::key_verification::KeyVerification;
use crate::util::revocation_update::get_or_create_revocation_list_id;

impl VCAPIService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        did_repository: Arc<dyn DidRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        json_ld_ctx_cache: ContextCache,
        base_url: Option<String>,
    ) -> Self {
        Self {
            credential_formatter_provider,
            presentation_formatter_provider,
            key_provider,
            did_repository,
            identifier_repository,
            did_method_provider,
            key_algorithm_provider,
            revocation_list_repository,
            certificate_validator,
            jsonld_ctx_cache: json_ld_ctx_cache,
            base_url,
        }
    }

    pub async fn issue_credential(
        &self,
        create_request: CredentialIssueRequest,
    ) -> Result<CredentialIssueResponse, ServiceError> {
        let CredentialIssueOptions {
            credential_format,
            revocation_method,
            ..
        } = create_request.options;
        let mut vcdm = create_request.credential;
        validate_verifiable_credential(&vcdm, &self.jsonld_ctx_cache).await?;

        let issuer_did_value = vcdm
            .issuer
            .to_did_value()
            .map_err(ServiceError::FormatterError)?;
        let issuer_did = self
            .did_repository
            .get_did_by_value(
                &issuer_did_value,
                None,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    organisation: None,
                },
            )
            .await?
            .ok_or(ServiceError::Other("Issuer DID not found".to_string()))?;
        let issuer_identifier = self
            .identifier_repository
            .get_from_did_id(issuer_did.id, &Default::default())
            .await?
            .ok_or(ServiceError::Other(
                "Issuer DID identifier not found".to_string(),
            ))?;

        let key = issuer_did
            .keys
            .as_ref()
            .ok_or(ServiceError::Other(
                "No local keys found for issuer DID".to_string(),
            ))?
            .first()
            .ok_or(ServiceError::Other("Issuer DID has empty keys".to_string()))?;

        let assertion_methods = self
            .did_method_provider
            .resolve(&issuer_did_value)
            .await?
            .assertion_method
            .ok_or(ServiceError::MappingError(
                "Missing assertion_method".to_owned(),
            ))?;

        let key_id = assertion_methods.first().ok_or(ServiceError::Other(
            "Could not find key in assertion method".to_string(),
        ))?;

        let auth_fn = self.key_provider.get_signature_provider(
            &key.key,
            Some(key_id.to_owned()),
            self.key_algorithm_provider.clone(),
        )?;

        let credential_format = credential_format.as_deref().unwrap_or("JSON_LD_CLASSIC");

        let formatter = self
            .credential_formatter_provider
            .get_credential_formatter(credential_format)
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::Formatter(credential_format.to_string()),
            ))?;

        if revocation_method.is_some() {
            let credential_status = &mut vcdm.credential_status;
            let revocation_list_id = get_or_create_revocation_list_id(
                &[Credential {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    issuance_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    deleted_at: None,
                    protocol: "OPENID4VCI_DRAFT13".to_owned(),
                    redirect_uri: None,
                    role: CredentialRole::Issuer,
                    state: CredentialStateEnum::Offered,
                    suspend_end_date: None,
                    profile: None,
                    claims: None,
                    issuer_identifier: Some(issuer_identifier.clone()),
                    issuer_certificate: None,
                    holder_identifier: None,
                    schema: None,
                    key: None,
                    interaction: None,
                    revocation_list: None,
                    credential_blob_id: None,
                }],
                issuer_identifier,
                RevocationListPurpose::Revocation,
                &*self.revocation_list_repository,
                &*self.key_provider,
                &self.key_algorithm_provider,
                &self.base_url,
                &*formatter,
                &StatusListType::BitstringStatusList,
                &crate::model::revocation_list::StatusListCredentialFormat::JsonLdClassic,
            )
            .await?;

            let status = bitstring_status_list::create_credential_status(
                &self.base_url,
                &revocation_list_id,
                0,
                "revocation",
            )?;

            credential_status.push(status);
        }

        let credential_data = CredentialData {
            holder_identifier: None, // For VC API verification, we don't have a full Identifier object
            vcdm,
            claims: vec![],
            holder_key_id: None,
            issuer_certificate: None,
        };
        let test = formatter.format_credential(credential_data, auth_fn).await;

        let mut verifiable_credential: LdCredential =
            serde_json::from_str(&test?).map_err(|e: serde_json::Error| {
                ServiceError::Other(format!("Failed to serialize verifiable credential: {e}"))
            })?;

        verifiable_credential
            .credential_subject
            .iter_mut()
            .for_each(|s| s.subject.clear());

        Ok(CredentialIssueResponse {
            verifiable_credential,
        })
    }

    pub async fn verify_credential(
        &self,
        verify_request: CredentialVerifiyRequest,
    ) -> Result<CredentialVerifyResponse, ServiceError> {
        validate_verifiable_credential(
            &verify_request.verifiable_credential,
            &self.jsonld_ctx_cache,
        )
        .await?;

        let format = if verify_request
            .verifiable_credential
            .proof
            .as_ref()
            .is_some_and(|proof| proof.cryptosuite == "bbs-2023")
        {
            "JSON_LD_BBSPLUS"
        } else {
            verify_request
                .options
                .credential_format
                .as_deref()
                .unwrap_or("JSON_LD_CLASSIC")
        };

        let formatter = self
            .credential_formatter_provider
            .get_credential_formatter(format)
            .ok_or(ServiceError::Other(format!(
                "Formatter not found for credential format {format}"
            )))?;

        let string_token =
            serde_json::to_string(&verify_request.verifiable_credential).map_err(|e| {
                ServiceError::Other(format!("Failed to serialize verifiable credential: {e}"))
            })?;

        let verification_fn = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });

        formatter
            .extract_credentials(&string_token, None, verification_fn, None)
            .await?;

        Ok(CredentialVerifyResponse {
            credential: verify_request.verifiable_credential,
            checks: vec![],
            warnings: vec![],
            errors: vec![],
        })
    }

    pub async fn verify_presentation(
        &self,
        verify_request: PresentationVerifyRequest,
    ) -> Result<PresentationVerifyResponse, ServiceError> {
        validate_verifiable_presentation(
            &verify_request.verifiable_presentation,
            &self.jsonld_ctx_cache,
        )
        .await?;

        const CREDENTIAL_FORMAT: &str = "JSON_LD_CLASSIC";

        let presentation_formatter = self
            .presentation_formatter_provider
            .get_presentation_formatter(CREDENTIAL_FORMAT)
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::Formatter(CREDENTIAL_FORMAT.to_string()),
            ))?;

        let string_token =
            serde_json::to_string(&verify_request.verifiable_presentation).map_err(|e| {
                ServiceError::Other(format!("Failed to serialize verifiable credential: {e}"))
            })?;

        let verification_fn = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });

        presentation_formatter
            .extract_presentation(
                &string_token,
                verification_fn,
                ExtractPresentationCtx {
                    verification_protocol_type: VerificationProtocolType::OpenId4VpDraft20,
                    nonce: None,
                    format_nonce: None,
                    issuance_date: None,
                    expiration_date: None,
                    client_id: None,
                    response_uri: None,
                    mdoc_session_transcript: None,
                },
            )
            .await?;

        Ok(PresentationVerifyResponse {
            checks: vec![],
            warnings: vec![],
            errors: vec![],
        })
    }
}
