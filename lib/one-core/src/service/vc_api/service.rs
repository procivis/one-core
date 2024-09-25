use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::dto::{
    CredentialIssueOptions, CredentialIssueRequest, CredentialIssueResponse,
    CredentialVerifiyRequest, CredentialVerifyResponse, PresentationVerifyRequest,
    PresentationVerifyResponse,
};
use super::mapper::value_to_published_claim;
use super::validation::{validate_verifiable_credential, validate_verifiable_presentation};
use super::VCAPIService;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::did::{DidRelations, KeyRole};
use crate::model::key::KeyRelations;
use crate::model::revocation_list::RevocationListPurpose;
use crate::provider::credential_formatter::json_ld::context::caching_loader::ContextCache;
use crate::provider::credential_formatter::json_ld::model::LdCredential;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchemaData, ExtractPresentationCtx, PublishedClaim,
    PublishedClaimValue,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::bitstring_status_list;
use crate::repository::did_repository::DidRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::service::error::ServiceError;
use crate::util::key_verification::KeyVerification;
use crate::util::revocation_update::get_or_create_revocation_list_id;

impl VCAPIService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_formatter: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        did_repository: Arc<dyn DidRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        json_ld_ctx_cache: ContextCache,
        base_url: Option<String>,
    ) -> Self {
        Self {
            credential_formatter,
            key_provider,
            did_repository,
            did_method_provider,
            key_algorithm_provider,
            revocation_list_repository,
            jsonld_ctx_cache: json_ld_ctx_cache,
            base_url,
        }
    }

    pub async fn issue_credential(
        &self,
        create_request: CredentialIssueRequest,
    ) -> Result<CredentialIssueResponse, ServiceError> {
        let CredentialIssueOptions {
            signature_algorithm,
            credential_format,
            revocation_method,
        } = create_request.options;

        validate_verifiable_credential(&create_request.credential, &self.jsonld_ctx_cache).await?;

        let issuer_did = create_request.credential.issuer.to_did_value();
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

        let credential_subject = create_request.credential.credential_subject[0].clone();

        let mut claims: Vec<PublishedClaim> = credential_subject
            .subject
            .into_iter()
            .flat_map(|claim| value_to_published_claim(claim, "", false))
            .collect();

        if let Some(credential_subject) = credential_subject.id.clone() {
            claims.push(PublishedClaim {
                key: "id".to_string(),
                value: PublishedClaimValue::String(credential_subject.as_str().into()),
                datatype: Some("STRING".to_string()),
                array_item: false,
            });
        }

        let formatter = self
            .credential_formatter
            .get_formatter(&credential_format.unwrap_or("JSON_LD_CLASSIC".to_string()))
            .unwrap();

        let mut credential_status = create_request.credential.credential_status;

        if revocation_method.is_some() {
            let revocation_list_id = get_or_create_revocation_list_id(
                &[Credential {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    issuance_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    deleted_at: None,
                    credential: vec![],
                    exchange: "OPENID4VC".to_owned(),
                    redirect_uri: None,
                    role: CredentialRole::Issuer,
                    state: Some(vec![CredentialState {
                        created_date: OffsetDateTime::now_utc(),
                        state: CredentialStateEnum::Offered,
                        suspend_end_date: None,
                    }]),
                    claims: None,
                    issuer_did: Some(issuer.clone()),
                    holder_did: None,
                    schema: None,
                    key: None,
                    interaction: None,
                    revocation_list: None,
                }],
                &issuer,
                RevocationListPurpose::Revocation,
                &*self.revocation_list_repository,
                &self.key_provider,
                &self.base_url,
                &*formatter,
                Some(key_id.to_owned()),
            )
            .await
            .unwrap();

            let status = bitstring_status_list::create_credential_status(
                &self.base_url,
                &revocation_list_id,
                0,
                "revocation",
            )
            .unwrap();

            credential_status.push(status);
        }

        let credential_data = CredentialData {
            id: create_request.credential.id.map(|url| url.to_string()),
            issuance_date: create_request
                .credential
                .valid_from
                .unwrap_or(OffsetDateTime::now_utc()), // TODO
            valid_for: Duration::minutes(60), // TODO
            claims,
            issuer_did: create_request.credential.issuer,
            status: credential_status,
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
            related_resource: create_request.credential.related_resource,
        };

        let test = formatter
            .format_credentials(
                credential_data,
                &credential_subject.id,
                &signature_algorithm,
                create_request.credential.context.into_iter().collect(),
                create_request.credential.r#type,
                auth_fn,
                None,
                None,
            )
            .await;

        let mut verifiable_credential: LdCredential = serde_json::from_str(&test?).unwrap();
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

        let format = &verify_request
            .options
            .credential_format
            .unwrap_or("JSON_LD_CLASSIC".to_string());

        let formatter =
            self.credential_formatter
                .get_formatter(format)
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
        validate_verifiable_presentation(
            &verify_request.verifiable_presentation,
            &self.jsonld_ctx_cache,
        )
        .await?;

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
