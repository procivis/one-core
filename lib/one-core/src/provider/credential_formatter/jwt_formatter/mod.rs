//! Implementations for JWT credential format.
//! https://datatracker.ietf.org/doc/html/rfc7519

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use model::VcClaim;
use proc_macros::Provider;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{CredentialFormat, DidValue, RevocationMethodId, SerializedCredential};
use time::Duration;
use uuid::Uuid;

use super::error::FormatterError;
use super::json_claims::{parse_claims, prepare_identifier};
use super::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential, Features,
    FormatterCapabilities, IdentifierDetails, TokenVerifier, VerificationFn,
};
use super::vcdm::vcdm_metadata_claims;
use super::{CredentialFormatter, MetadataClaimSchema};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::error::ContextWithErrorCode;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::IdentifierData;
use crate::model::organisation::Organisation;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTPayload, jwt_metadata_claims};
use crate::provider::credential_formatter::mapper::{
    default_2_years, first_certificate, to_format_with_mappings,
};
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::key_selection::SelectedKey;

#[cfg(test)]
mod test;

mod mapper;
pub(crate) mod model;
mod status_list;

#[derive(Provider)]
pub struct JWTFormatter {
    config_id: CredentialFormat,
    params: Params,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    data_type_provider: Arc<dyn DataTypeProvider>,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway_seconds: Duration,
    embed_layout_properties: bool,
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "default_2_years")]
    expiration_seconds: Duration,
    revocation_method: Option<RevocationMethodId>,
}

impl JWTFormatter {
    pub fn new(
        config_id: CredentialFormat,
        params: serde_json::Value,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        data_type_provider: Arc<dyn DataTypeProvider>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_id,
            params,
            key_algorithm_provider,
            did_method_provider,
            data_type_provider,
        })
    }
}

#[async_trait]
impl CredentialFormatter for JWTFormatter {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<SerializedCredential, FormatterError> {
        let now = crate::clock::now_utc();

        let mut vcdm = credential_data.credential.into_vcdm()?;
        let invalid_before = vcdm.valid_from.or(vcdm.issuance_date);
        let expires_at = vcdm.valid_until.or(vcdm.expiration_date);
        let credential_id = vcdm.id.clone().map(|id| id.to_string());

        let issuer = vcdm.issuer.as_url().to_string();

        if !self.params.embed_layout_properties {
            vcdm.remove_layout_properties();
        }

        let vc = VcClaim { vc: vcdm.into() };

        let holder_did = match credential_data
            .holder_identifier
            .as_ref()
            .map(|identifier| &identifier.data)
        {
            Some(IdentifierData::Did(did)) => Some(did.as_ref().await?.did.to_string()),
            _ => None,
        };

        let payload = JWTPayload {
            issued_at: Some(now),
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
            auth_fn.jose_alg().error_while("getting JOSE algorithm")?,
            key_id,
            None,
            payload,
        );

        Ok(jwt
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating JWT credential token")?
            .into())
    }

    async fn format_status_list<'a>(
        &self,
        revocation_list_url: String,
        issuer: SelectedKey,
        encoded_list: String,
        algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: RevocationType,
    ) -> Result<Vec<u8>, FormatterError> {
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_type(algorithm)?;

        let jose_alg = key_algorithm.issuance_jose_alg_id();

        let status_list = match status_list_type {
            RevocationType::BitstringStatusList => {
                self.format_bitstring_status_list(
                    revocation_list_url,
                    issuer,
                    encoded_list,
                    jose_alg,
                    auth_fn,
                    status_purpose,
                )
                .await?
            }
            RevocationType::TokenStatusList => {
                let bits = if status_purpose == StatusPurpose::RevocationAndSuspension {
                    2
                } else {
                    1
                };
                self.format_token_status_list(
                    revocation_list_url,
                    issuer,
                    encoded_list,
                    jose_alg,
                    auth_fn,
                    bits,
                )
                .await?
            }
            _ => {
                return Err(FormatterError::CouldNotFormat(format!(
                    "Unsupported status list: {status_list_type}"
                )));
            }
        };

        Ok(status_list.into_bytes())
    }

    async fn extract_credentials<'a>(
        &self,
        token: &SerializedCredential,
        _credential_schema: Option<&'a CredentialSchema>,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<VcClaim> = Jwt::build_from_token(token.as_ref(), Some(&verification), None)
            .await
            .error_while("extracting JWT credential token")?;

        DetailCredential::try_from(jwt)
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &SerializedCredential,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        let jwt: Jwt<VcClaim> = Jwt::build_from_token(token.as_ref(), None, None)
            .await
            .error_while("parsing JWT credential token")?;

        DetailCredential::try_from(jwt)
    }

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        Ok(credential.token.into())
    }

    fn get_leeway(&self) -> Duration {
        self.params.leeway_seconds
    }

    fn get_default_expiration(&self) -> Duration {
        self.params.expiration_seconds
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
            issuance_did_methods: vec![
                DidType::Key,
                DidType::Web,
                DidType::Jwk,
                DidType::Tdw,
                DidType::Webvh,
            ],
            issuance_exchange_protocols: vec![IssuanceProtocolType::OpenId4VciFinal1_0],
            proof_exchange_protocols: vec![
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::OpenId4VpProximityDraft00,
            ],
            revocation_methods: vec![RevocationType::BitstringStatusList],
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
                "EAA_CATEGORY".to_string(),
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
            holder_did_methods: vec![
                DidType::Web,
                DidType::Key,
                DidType::Jwk,
                DidType::Tdw,
                DidType::Webvh,
            ],
        }
    }

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        [jwt_metadata_claims(), vcdm_metadata_claims(Some("vc"))].concat()
    }

    fn user_claims_path(&self) -> Vec<String> {
        vec!["vc".to_string(), "credentialSubject".to_string()]
    }

    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<Credential, FormatterError> {
        let now = crate::clock::now_utc();

        let jwt: Jwt<VcClaim> =
            Jwt::build_from_token(credential.as_ref(), Some(&verification), None)
                .await
                .error_while("parsing JWT credential token")?;

        let revocation_method =
            if let Some(status) = jwt.payload.custom.vc.credential_status.first() {
                match status.r#type.as_str() {
                    "BitstringStatusListEntry" => Some(RevocationType::BitstringStatusList),
                    _ => {
                        return Err(FormatterError::CouldNotExtractCredentials(format!(
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
        let metadata_claims = jwt
            .get_metadata_claims()
            .error_while("getting JWT metadata claims")?;

        // Parse claims from credential subject
        let credential_subject = jwt
            .payload
            .custom
            .vc
            .credential_subject
            .first()
            .ok_or_else(|| {
                FormatterError::CouldNotExtractCredentials("Missing credential subject".to_string())
            })?;

        let (mut claims, mut claim_schemas) = parse_claims(
            HashMap::from_iter(credential_subject.claims.clone()),
            self.data_type_provider.as_ref(),
        )
        .await?;

        // Add parsed metadata claims
        let (metadata_claims, metadata_claim_schemas) =
            parse_claims(metadata_claims, self.data_type_provider.as_ref()).await?;
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

        let credential_schema_id = Uuid::new_v4().into();
        let format = to_format_with_mappings(
            self.config_id.clone(),
            credential_schema_id,
            schema_id,
            &claim_schemas,
            now,
        );

        let schema = CredentialSchema {
            expiration: None,
            ecosystem: None,
            id: credential_schema_id,
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: schema_name,
            wallet_attestation: Default::default(),
            layout_properties: None,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            claim_schemas: claim_schemas.into(),
            organisation: organisation.clone().into(),
            transaction_code: None,
            formats: vec![format.clone()].into(),
            batch_size: None,
            allow_revocation: revocation_method.is_some(),
            translations: Default::default(),
            embedded_disclosure_policy: None,
        };

        let issuer = jwt
            .payload
            .issuer
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "JWT missing issuer".to_string(),
            ))?
            .parse()
            .map_err(DidMethodError::DidValueError)
            .error_while("parsing issuer DID")?;

        let issuer_identifier = prepare_identifier(
            &IdentifierDetails::Did(issuer),
            self.key_algorithm_provider.as_ref(),
            self.did_method_provider.as_ref(),
            organisation.to_owned(),
        )?;
        let holder_identifier = jwt
            .payload
            .subject
            .map(|did| DidValue::from_str(&did))
            .transpose()
            .map_err(DidMethodError::DidValueError)
            .error_while("parsing subject")?
            .map(IdentifierDetails::Did)
            .map(|details| {
                prepare_identifier(
                    &details,
                    self.key_algorithm_provider.as_ref(),
                    self.did_method_provider.as_ref(),
                    organisation,
                )
            })
            .transpose()?;

        Ok(Credential {
            expires_at: jwt.payload.expires_at,
            ecosystem: None,
            id: credential_id,
            created_date: now,
            issuance_date: jwt.payload.issued_at,
            last_modified: now,
            deleted_at: None,
            consumed_at: None,
            protocol: "".to_string(),
            redirect_uri: None,
            role: CredentialRole::Holder,
            r#type: CredentialType::Single,
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
            profile: None,
            credential_blob_id: None,
            wallet_key_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            claims: claims.into(),
            issuer_certificate: first_certificate(&issuer_identifier).await?.map(Into::into),
            issuer_identifier: Some(issuer_identifier.into()),
            holder_identifier: holder_identifier.map(Into::into),
            schema: schema.into(),
            interaction: None,
            key: None,
            webhook_url: None,
            parent: None,
            embedded_disclosure_policy: None,
            subscriber_information: None,
            format: Some(format.into()),
        })
    }

    fn revocation_method_id(&self) -> Option<&RevocationMethodId> {
        self.params.revocation_method.as_ref()
    }

    fn config_name(&self) -> &CredentialFormat {
        &self.config_id
    }
}
