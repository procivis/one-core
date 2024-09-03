use std::{str::FromStr, sync::Arc};
use time::Duration;

use one_providers::{
    common_models::did::KeyRole,
    credential_formatter::{
        model::{
            CredentialData, CredentialSchemaData, ExtractPresentationCtx, PublishedClaim,
            PublishedClaimValue,
        },
        provider::CredentialFormatterProvider,
    },
    did::provider::DidMethodProvider,
    key_algorithm::provider::KeyAlgorithmProvider,
    key_storage::provider::KeyProvider,
    util::key_verification::KeyVerification,
};
use shared_types::DidId;
use time::OffsetDateTime;

use crate::{
    model::{did::DidRelations, key::KeyRelations},
    repository::did_repository::DidRepository,
    service::error::ServiceError,
};

use super::{
    dto::{
        CredentialIssueOptions, CredentialIssueRequest, CredentialIssueResponse,
        CredentialVerifiyRequest, CredentialVerifyResponse, PresentationVerifyRequest,
        PresentationVerifyResponse,
    },
    mapper::value_to_published_claim,
    VCAPIService,
};

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
        let CredentialIssueOptions { issuer_id, r#type } = create_request
            .options
            .ok_or(ServiceError::Other("Options are missing".to_string()))?;

        let issuer = issuer_id.ok_or(ServiceError::Other("Issuer id is missing".to_string()))?;
        let issuer = self
            .did_repository
            .get_did(
                &DidId::from(uuid::Uuid::from_str(&issuer).unwrap()),
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
            .ok_or(ServiceError::Other("Issuer DID has no keys".to_string()))?;

        let key = &key
            .first()
            .ok_or(ServiceError::Other("Issuer DID has no keys".to_string()))?
            .key;

        // TODO
        let key_id = "did:key:z6MkrfxC1rBNcxhAhgnNF4CxTgo2gQVXxvgJEp7enGBtKxBR#z6MkrfxC1rBNcxhAhgnNF4CxTgo2gQVXxvgJEp7enGBtKxBR";

        let auth_fn = self
            .key_provider
            .get_signature_provider(key, Some(key_id.to_string()))?;

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
                datatype: Some("string".to_string()),
                array_item: false,
            });
        }

        let credential_data = CredentialData {
            id: create_request.credential.id,
            issuance_date: create_request
                .credential
                .valid_from
                .unwrap_or(OffsetDateTime::now_utc()), // TODO
            valid_for: Duration::minutes(60), // TODO
            claims,
            issuer_did: issuer.did.into(),
            status: create_request.credential.credential_status,
            schema: CredentialSchemaData {
                id: None,
                r#type: None,
                context: None,
                name: "test".to_string(),
            },
        };

        let formatter = self
            .credential_formatter
            .get_formatter("JSON_LD_CLASSIC")
            .unwrap();

        let test = formatter
            .format_credentials(
                credential_data,
                &None,
                &r#type.ok_or(ServiceError::Other("Type is missing".to_string()))?,
                create_request.credential.context,
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
