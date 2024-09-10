use std::sync::Arc;

use one_providers::common_models::did::KeyRole;
use one_providers::credential_formatter::model::{
    CredentialData, CredentialSchemaData, ExtractPresentationCtx, PublishedClaim,
    PublishedClaimValue,
};
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::key_storage::provider::KeyProvider;
use one_providers::util::key_verification::KeyVerification;
use time::{Duration, OffsetDateTime};

use super::dto::{
    CredentialIssueOptions, CredentialIssueRequest, CredentialIssueResponse,
    CredentialVerifiyRequest, CredentialVerifyResponse, PresentationVerifyRequest,
    PresentationVerifyResponse,
};
use super::mapper::value_to_published_claim;
use super::validation::{validate_verifiable_credential, validate_verifiable_presentation};
use super::VCAPIService;
use crate::model::did::DidRelations;
use crate::model::key::KeyRelations;
use crate::repository::did_repository::DidRepository;
use crate::service::error::ServiceError;

impl VCAPIService {
    pub fn new(
        credential_formatter: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        did_repository: Arc<dyn DidRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            credential_formatter,
            key_provider,
            did_repository,
            did_method_provider,
            key_algorithm_provider,
        }
    }

    pub async fn issue_credential(
        &self,
        create_request: CredentialIssueRequest,
    ) -> Result<CredentialIssueResponse, ServiceError> {
        let CredentialIssueOptions {
            signature_algorithm,
            credential_format,
        } = create_request
            .options
            .ok_or(ServiceError::Other("Options are missing".to_string()))?;

        validate_verifiable_credential(&create_request.credential)?;

        let issuer_did = create_request.credential.issuer.to_did_value().into();
        let issuer = self
            .did_repository
            .get_did_by_value(
                &issuer_did,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    organisation: None,
                },
            )
            .await?
            .ok_or(ServiceError::Other("Issuer DID not found".to_string()))?;

        let key = issuer
            .keys
            .as_ref()
            .ok_or(ServiceError::Other(
                "No local keys found for issuer DID".to_string(),
            ))?
            .first()
            .ok_or(ServiceError::Other("Issuer DID has empty keys".to_string()))?;

        let assertion_methods = self
            .did_method_provider
            .resolve(&create_request.credential.issuer.to_did_value())
            .await?
            .assertion_method
            .ok_or(ServiceError::MappingError(
                "Missing assertion_method".to_owned(),
            ))?;

        let key_id = assertion_methods.first().ok_or(ServiceError::Other(
            "Could not find key in assertion method".to_string(),
        ))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.key, Some(key_id.to_owned()))?;

        let mut claims: Vec<PublishedClaim> = create_request
            .credential
            .credential_subject
            .subject
            .into_iter()
            .flat_map(|claim| value_to_published_claim(claim, "", false))
            .collect();

        if let Some(credential_subject) = create_request.credential.credential_subject.id {
            claims.push(PublishedClaim {
                key: "id".to_string(),
                value: PublishedClaimValue::String(credential_subject.into()),
                datatype: Some("STRING".to_string()),
                array_item: false,
            });
        }

        let credential_data = CredentialData {
            id: create_request.credential.id.map(|url| url.to_string()),
            issuance_date: create_request
                .credential
                .valid_from
                .unwrap_or(OffsetDateTime::now_utc()), // TODO
            valid_for: Duration::minutes(60), // TODO
            claims,
            issuer_did: create_request.credential.issuer.to_did_value(),
            status: create_request.credential.credential_status,
            schema: CredentialSchemaData {
                id: None,
                r#type: None,
                context: None,
                name: "vc_interop_test_no_schema_data".to_string(),
                metadata: None,
            },
            name: create_request.credential.name,
            description: create_request.credential.description,
            terms_of_use: create_request.credential.terms_of_use,
            evidence: create_request.credential.evidence,
        };

        let formatter = self
            .credential_formatter
            .get_formatter(&credential_format)
            .unwrap();

        let test = formatter
            .format_credentials(
                credential_data,
                &None,
                &signature_algorithm,
                create_request.credential.context.into_iter().collect(),
                create_request.credential.r#type,
                auth_fn,
                None,
                None,
            )
            .await;

        Ok(CredentialIssueResponse {
            verifiable_credential: serde_json::from_str(&test?).unwrap(),
        })
    }

    pub async fn verify_credential(
        &self,
        verify_request: CredentialVerifiyRequest,
    ) -> Result<CredentialVerifyResponse, ServiceError> {
        validate_verifiable_credential(&verify_request.verifiable_credential)?;

        let formatter = self
            .credential_formatter
            .get_formatter("JSON_LD_CLASSIC")
            .unwrap();

        let string_token =
            serde_json::to_string(&verify_request.verifiable_credential).map_err(|e| {
                ServiceError::Other(format!("Failed to serialize verifiable credential: {e}"))
            })?;

        let verification_fn = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let _ = formatter
            .extract_credentials(&string_token, verification_fn)
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
        validate_verifiable_presentation(&verify_request.verifiable_presentation)?;

        let formatter = self
            .credential_formatter
            .get_formatter("JSON_LD_CLASSIC")
            .unwrap();

        let string_token =
            serde_json::to_string(&verify_request.verifiable_presentation).map_err(|e| {
                ServiceError::Other(format!("Failed to serialize verifiable credential: {e}"))
            })?;

        let verification_fn = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let _ = formatter
            .extract_presentation(
                &string_token,
                verification_fn,
                ExtractPresentationCtx::default(),
            )
            .await?;

        Ok(PresentationVerifyResponse {
            checks: vec![],
            warnings: vec![],
            errors: vec![],
        })
    }
}
