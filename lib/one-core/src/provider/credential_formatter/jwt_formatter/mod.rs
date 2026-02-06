//! Implementations for JWT credential format.
//! https://datatracker.ietf.org/doc/html/rfc7519

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use model::VcClaim;
use serde::Deserialize;
use shared_types::DidValue;
use time::OffsetDateTime;
use uuid::Uuid;

use super::error::FormatterError;
use super::json_claims::{parse_claims, prepare_identifier};
use super::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential, Features,
    FormatterCapabilities, HolderBindingCtx, IdentifierDetails, VerificationFn,
};
use super::vcdm::vcdm_metadata_claims;
use super::{CredentialFormatter, MetadataClaimSchema};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::identifier::Identifier;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTPayload, jwt_metadata_claims};
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;

#[cfg(test)]
mod test;

mod mapper;
pub(crate) mod model;
mod status_list;

pub struct JWTFormatter {
    params: Params,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    data_type_provider: Arc<dyn DataTypeProvider>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
    pub embed_layout_properties: bool,
}

impl JWTFormatter {
    pub fn new(
        params: Params,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        data_type_provider: Arc<dyn DataTypeProvider>,
    ) -> Self {
        Self {
            params,
            key_algorithm_provider,
            data_type_provider,
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

        jwt.tokenize(Some(&*auth_fn)).await
    }

    async fn format_status_list(
        &self,
        revocation_list_url: String,
        issuer_identifier: &Identifier,
        encoded_list: String,
        algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: RevocationType,
    ) -> Result<String, FormatterError> {
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_type(algorithm)
            .ok_or(FormatterError::Failed("Missing key algorithm".to_string()))?;

        let jose_alg = key_algorithm
            .issuance_jose_alg_id()
            .ok_or(FormatterError::Failed("Invalid key algorithm".to_string()))?;

        match status_list_type {
            RevocationType::BitstringStatusList => {
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
            RevocationType::TokenStatusList => {
                self.format_token_status_list(
                    revocation_list_url,
                    issuer_identifier,
                    encoded_list,
                    jose_alg,
                    auth_fn,
                    self.key_algorithm_provider.as_ref(),
                )
                .await
            }
            _ => {
                return Err(FormatterError::CouldNotFormat(format!(
                    "Unsupported status list: {status_list_type}"
                )));
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

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
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
                KeyAlgorithmType::MlDsa,
            ],
            features: vec![
                Features::SupportsCredentialDesign,
                Features::SupportsCombinedPresentation,
                Features::SupportsTxCode,
            ],
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
                KeyAlgorithmType::MlDsa,
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
                KeyAlgorithmType::MlDsa,
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

    async fn parse_credential(&self, credential: &str) -> Result<Credential, FormatterError> {
        let now = OffsetDateTime::now_utc();

        let jwt: Jwt<VcClaim> = Jwt::build_from_token(credential, None, None).await?;

        let revocation_method =
            if let Some(status) = jwt.payload.custom.vc.credential_status.first() {
                match status.r#type.as_str() {
                    "LVVC" => Some(RevocationType::Lvvc),
                    "BitstringStatusListEntry" => Some(RevocationType::BitstringStatusList),
                    _ => {
                        return Err(FormatterError::Failed(format!(
                            "Unknown revocation method: {}",
                            status.r#type
                        )));
                    }
                }
            } else {
                None
            };

        let credential_id = Uuid::new_v4().into();
        let vc_types = jwt.payload.custom.vc.r#type.clone();
        let schema_name = vc_types
            .iter()
            .find(|t| t != &"VerifiableCredential")
            .cloned()
            .unwrap_or_else(|| "VerifiableCredential".to_string());

        // Get metadata claims first (includes vc type and standard JWT claims)
        let metadata_claims = jwt.get_metadata_claims()?;

        // Parse claims from credential subject
        let credential_subject = jwt
            .payload
            .custom
            .vc
            .credential_subject
            .first()
            .ok_or_else(|| FormatterError::Failed("Missing credential subject".to_string()))?;

        let (mut claims, mut claim_schemas) = parse_claims(
            HashMap::from_iter(credential_subject.claims.clone()),
            self.data_type_provider.as_ref(),
            credential_id,
        )?;

        // Add parsed metadata claims
        let (metadata_claims, metadata_claim_schemas) = parse_claims(
            metadata_claims,
            self.data_type_provider.as_ref(),
            credential_id,
        )?;
        claims.extend(metadata_claims);
        claim_schemas.extend(metadata_claim_schemas);

        let schema_id = jwt
            .payload
            .custom
            .vc
            .credential_schema
            .as_ref()
            .and_then(|schema| schema.first())
            .map(|s| s.id.clone())
            .unwrap_or_else(|| schema_name.clone());

        let schema = CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: schema_name,
            format: "".into(), // Will be overridden based on config priority
            revocation_method: revocation_method.map(|v| v.to_string().into()),
            key_storage_security: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            requires_wallet_instance_attestation: false,
            claim_schemas: Some(claim_schemas),
            organisation: None,
            transaction_code: None,
        };

        let issuer = jwt
            .payload
            .issuer
            .ok_or(FormatterError::Failed("JWT missing issuer".to_string()))?
            .parse()
            .map_err(|e: anyhow::Error| FormatterError::Failed(e.to_string()))?;

        let issuer_identifier = prepare_identifier(
            &IdentifierDetails::Did(issuer),
            self.key_algorithm_provider.as_ref(),
        )?;
        let holder_identifier = jwt
            .payload
            .subject
            .map(|did| DidValue::from_str(&did))
            .transpose()
            .map_err(|e| FormatterError::Failed(e.to_string()))?
            .map(IdentifierDetails::Did)
            .map(|details| prepare_identifier(&details, self.key_algorithm_provider.as_ref()))
            .transpose()?;

        Ok(Credential {
            id: credential_id,
            created_date: now,
            issuance_date: jwt.payload.issued_at,
            last_modified: now,
            deleted_at: None,
            protocol: "".to_string(),
            redirect_uri: None,
            role: CredentialRole::Holder,
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
            profile: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            claims: Some(claims),
            issuer_certificate: issuer_identifier
                .certificates
                .as_ref()
                .and_then(|certs| certs.first().cloned()),
            issuer_identifier: Some(issuer_identifier),
            holder_identifier,
            schema: Some(schema),
            interaction: None,
            key: None,
        })
    }
}
