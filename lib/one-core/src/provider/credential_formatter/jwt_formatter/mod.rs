//! Implementations for JWT credential format.
//! https://datatracker.ietf.org/doc/html/rfc7519

use std::sync::Arc;

use async_trait::async_trait;
use model::VcClaim;
use serde::Deserialize;
use time::OffsetDateTime;

use super::model::{CredentialData, Features, HolderBindingCtx};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::Identifier;
use crate::model::revocation_list::StatusListType;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialPresentation, DetailCredential, FormatterCapabilities,
    VerificationFn,
};
use crate::provider::credential_formatter::vcdm::vcdm_metadata_claims;
use crate::provider::credential_formatter::{CredentialFormatter, MetadataClaimSchema};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::jwt::Jwt;
use crate::util::jwt::model::{JWTPayload, jwt_metadata_claims};

#[cfg(test)]
mod test;

mod mapper;
pub(crate) mod model;
mod status_list;

pub struct JWTFormatter {
    params: Params,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
    pub embed_layout_properties: bool,
}

impl JWTFormatter {
    pub fn new(params: Params, key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>) -> Self {
        Self {
            params,
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl CredentialFormatter for JWTFormatter {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let mut vcdm = credential_data.vcdm;
        let invalid_before = vcdm.valid_from.or(vcdm.issuance_date);
        let expires_at = vcdm.valid_until.or(vcdm.expiration_date);
        let credential_id = vcdm.id.clone().map(|id| id.to_string());

        let issuer = vcdm.issuer.as_url().to_string();

        if !self.params.embed_layout_properties {
            vcdm.remove_layout_properties();
        }

        let vc = VcClaim { vc: vcdm.into() };

        let holder_did = credential_data
            .holder_identifier
            .as_ref()
            .and_then(|identifier| identifier.did.as_ref())
            .map(|did| did.did.to_string());

        let payload = JWTPayload {
            issued_at: Some(OffsetDateTime::now_utc()),
            expires_at,
            invalid_before,
            issuer: Some(issuer),
            subject: holder_did,
            jwt_id: credential_id,
            custom: vc,
            ..Default::default()
        };

        let key_id = auth_fn.get_key_id();
        let jwt = Jwt::new(
            "JWT".to_owned(),
            auth_fn.jose_alg().ok_or(FormatterError::CouldNotFormat(
                "Invalid key algorithm".to_string(),
            ))?,
            key_id,
            None,
            payload,
        );

        jwt.tokenize(Some(auth_fn)).await
    }

    async fn format_status_list(
        &self,
        revocation_list_url: String,
        issuer_identifier: &Identifier,
        encoded_list: String,
        algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_type(algorithm)
            .ok_or(FormatterError::Failed("Missing key algorithm".to_string()))?;

        let jose_alg = key_algorithm
            .issuance_jose_alg_id()
            .ok_or(FormatterError::Failed("Invalid key algorithm".to_string()))?;

        match status_list_type {
            StatusListType::BitstringStatusList => {
                self.format_bitstring_status_list(
                    revocation_list_url,
                    issuer_identifier,
                    encoded_list,
                    jose_alg,
                    auth_fn,
                    status_purpose,
                )
                .await
            }
            StatusListType::TokenStatusList => {
                self.format_token_status_list(
                    revocation_list_url,
                    issuer_identifier,
                    encoded_list,
                    jose_alg,
                    auth_fn,
                )
                .await
            }
        }
    }

    async fn extract_credentials<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a CredentialSchema>,
        verification: VerificationFn,
        _holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<VcClaim> = Jwt::build_from_token(token, Some(&verification), None).await?;

        DetailCredential::try_from(jwt).map_err(|e| FormatterError::Failed(e.to_string()))
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        let jwt: Jwt<VcClaim> = Jwt::build_from_token(token, None, None).await?;

        DetailCredential::try_from(jwt).map_err(|e| FormatterError::Failed(e.to_string()))
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
        _holder_binding_ctx: Option<HolderBindingCtx>,
        _holder_binding_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError> {
        Ok(credential.token)
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Dilithium,
            ],
            features: vec![Features::SupportsCredentialDesign],
            selective_disclosure: vec![],
            issuance_did_methods: vec![DidType::Key, DidType::Web, DidType::Jwk, DidType::WebVh],
            issuance_exchange_protocols: vec![
                IssuanceProtocolType::OpenId4VciDraft13,
                IssuanceProtocolType::OpenId4VciFinal1_0,
            ],
            proof_exchange_protocols: vec![
                VerificationProtocolType::OpenId4VpDraft20,
                VerificationProtocolType::OpenId4VpDraft25,
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::OpenId4VpProximityDraft00,
            ],
            revocation_methods: vec![
                RevocationType::None,
                RevocationType::BitstringStatusList,
                RevocationType::Lvvc,
            ],
            verification_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Dilithium,
            ],
            verification_key_storages: vec![
                KeyStorageType::Internal,
                KeyStorageType::AzureVault,
                KeyStorageType::SecureElement,
            ],
            allowed_schema_ids: vec![],
            datatypes: vec![
                "STRING".to_string(),
                "BOOLEAN".to_string(),
                "EMAIL".to_string(),
                "DATE".to_string(),
                "STRING".to_string(),
                "COUNT".to_string(),
                "BIRTH_DATE".to_string(),
                "NUMBER".to_string(),
                "PICTURE".to_string(),
                "OBJECT".to_string(),
                "ARRAY".to_string(),
            ],
            forbidden_claim_names: vec!["0".to_string(), "id".to_string()],
            issuance_identifier_types: vec![IdentifierType::Did],
            verification_identifier_types: vec![IdentifierType::Did, IdentifierType::Certificate],
            holder_identifier_types: vec![IdentifierType::Did],
            holder_key_algorithms: vec![
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Dilithium,
            ],
            holder_did_methods: vec![DidType::Web, DidType::Key, DidType::Jwk, DidType::WebVh],
        }
    }

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        [jwt_metadata_claims(), vcdm_metadata_claims(Some("vc"))].concat()
    }

    fn user_claims_path(&self) -> Vec<String> {
        vec!["vc".to_string(), "credentialSubject".to_string()]
    }
}
