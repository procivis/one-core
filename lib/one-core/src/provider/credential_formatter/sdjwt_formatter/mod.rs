//! SD-JWT implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use serde_json::Value;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::error::FormatterError;
use super::json_claims::{parse_claims, prepare_identifier};
use super::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, CredentialSubject, DetailCredential,
    Features, FormatterCapabilities, HolderBindingCtx, IdentifierDetails, SelectiveDisclosure,
    VerificationFn,
};
use super::sdjwt::disclosures::parse_token;
use super::sdjwt::mapper::vc_from_credential;
use super::sdjwt::model::*;
use super::sdjwt::{SdJwtHolderBindingParams, format_credential, model, prepare_sd_presentation};
use super::vcdm::{VcdmCredential, vcdm_metadata_claims};
use super::{CredentialFormatter, MetadataClaimSchema, StatusListType};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::identifier::Identifier;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTPayload, jwt_metadata_claims};
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;

#[cfg(test)]
mod test;

pub struct SDJWTFormatter {
    crypto: Arc<dyn CryptoProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    data_type_provider: Arc<dyn DataTypeProvider>,
    client: Arc<dyn HttpClient>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
    pub embed_layout_properties: bool,
    #[serde(default = "default_sd_array_elements")]
    pub sd_array_elements: bool,
}

fn default_sd_array_elements() -> bool {
    true
}

#[async_trait]
impl CredentialFormatter for SDJWTFormatter {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        const HASH_ALG: &str = "sha-256";
        let mut vcdm = credential_data.vcdm;

        if !self.params.embed_layout_properties {
            vcdm.remove_layout_properties();
        }

        let inputs = SdJwtFormattingInputs {
            holder_identifier: credential_data.holder_identifier,
            holder_key_id: credential_data.holder_key_id,
            leeway: self.params.leeway,
            token_type: "SD_JWT".to_string(),
            swiyu_proof_of_possession: false,
            issuer_certificate: None,
        };

        let cred = vcdm.clone();
        let payload_from_digests =
            |digests: Vec<String>| vc_from_credential(cred, digests, HASH_ALG);
        let claims = credential_to_claims(&vcdm)?;
        format_credential(
            vcdm,
            claims,
            inputs,
            auth_fn,
            &*self.crypto.get_hasher(HASH_ALG)?,
            &*self.did_method_provider,
            &*self.key_algorithm_provider,
            payload_from_digests,
            self.params.sd_array_elements,
        )
        .await
    }

    async fn format_status_list(
        &self,
        _revocation_list_url: String,
        _issuer_identifier: &Identifier,
        _encoded_list: String,
        _algorithm: KeyAlgorithmType,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        Err(FormatterError::Failed(
            "Cannot format StatusList with SD-JWT formatter".to_string(),
        ))
    }

    async fn extract_credentials<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a CredentialSchema>,
        verification: VerificationFn,
        holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        let (credential, _) = extract_credentials_internal(
            token,
            Some(&(verification)),
            &*self.crypto,
            holder_binding_ctx,
            Duration::seconds(self.get_leeway() as i64),
            &*self.client,
        )
        .await?;

        Ok(credential)
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
        holder_binding_ctx: Option<HolderBindingCtx>,
        holder_binding_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError> {
        let model::DecomposedToken { jwt, .. } = parse_token(&credential.token)?;
        let jwt: Jwt<VcClaim> = Jwt::build_from_token(jwt, None, None).await?;
        let hasher = self
            .crypto
            .get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

        prepare_sd_presentation(
            credential,
            &*hasher,
            holder_binding_ctx,
            holder_binding_fn,
            &self.user_claims_path(),
        )
        .await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        let (credential, _) = extract_credentials_internal(
            token,
            None,
            &*self.crypto,
            None,
            Duration::seconds(self.get_leeway() as i64),
            &*self.client,
        )
        .await?;

        Ok(credential)
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
            features: vec![
                Features::SelectiveDisclosure,
                Features::SupportsCredentialDesign,
                Features::SupportsCombinedPresentation,
            ],
            selective_disclosure: vec![SelectiveDisclosure::AnyLevel],
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

    async fn parse_credential(&self, credential: &str) -> Result<Credential, FormatterError> {
        let now = OffsetDateTime::now_utc();

        let (parsed_credential, _, issuer): (Jwt<VcClaim>, _, _) =
            Jwt::build_from_token_with_disclosures(
                credential,
                &*self.crypto,
                None,
                SdJwtHolderBindingParams {
                    holder_binding_context: None,
                    leeway: Duration::seconds(self.get_leeway() as i64),
                    skip_holder_binding_aud_check: false,
                },
                None,
                &*self.client,
            )
            .await?;

        let revocation_method = if let Some(status) = parsed_credential
            .payload
            .custom
            .vc
            .credential_status
            .first()
        {
            match status.r#type.as_str() {
                "LVVC" => RevocationType::Lvvc,
                "BitstringStatusListEntry" => RevocationType::BitstringStatusList,
                _ => {
                    return Err(FormatterError::Failed(format!(
                        "Unknown revocation method: {}",
                        status.r#type
                    )));
                }
            }
        } else {
            RevocationType::None
        };

        let credential_id = Uuid::new_v4().into();
        let vc_types = parsed_credential.payload.custom.vc.r#type.clone();
        let schema_name = vc_types
            .iter()
            .find(|t| t != &"VerifiableCredential")
            .cloned()
            .unwrap_or_else(|| "VerifiableCredential".to_string());

        // Get metadata claims first (includes vc type and standard JWT claims)
        let metadata_claims = parsed_credential.get_metadata_claims()?;

        // Parse claims from credential subject
        let credential_subject = parsed_credential
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

        let schema_id = parsed_credential
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
            format: "SDJWT".to_string(),
            revocation_method: revocation_method.to_string(),
            wallet_storage_type: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            requires_app_attestation: false,
            claim_schemas: Some(claim_schemas),
            organisation: None,
        };

        let issuer_identifier = prepare_identifier(&issuer, self.key_algorithm_provider.as_ref())?;
        let holder_identifier = parsed_credential
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
            issuance_date: parsed_credential.payload.issued_at,
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
            wallet_app_attestation_blob_id: None,
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

impl SDJWTFormatter {
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        data_type_provider: Arc<dyn DataTypeProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            params,
            crypto,
            did_method_provider,
            key_algorithm_provider,
            data_type_provider,
            client,
        }
    }
}

pub(crate) async fn extract_credentials_internal(
    token: &str,
    verification: Option<&VerificationFn>,
    crypto: &dyn CryptoProvider,
    holder_binding_ctx: Option<HolderBindingCtx>,
    leeway: Duration,
    http_client: &dyn HttpClient,
) -> Result<(DetailCredential, Option<JWTPayload<KeyBindingPayload>>), FormatterError> {
    let params = SdJwtHolderBindingParams {
        holder_binding_context: holder_binding_ctx,
        leeway,
        skip_holder_binding_aud_check: false,
    };
    let (jwt, key_binding_payload, issuer_details): (Jwt<VcClaim>, _, _) =
        Jwt::build_from_token_with_disclosures(
            token,
            crypto,
            verification,
            params,
            None,
            http_client,
        )
        .await?;
    let metadata_claims = jwt.get_metadata_claims()?;
    let credential_subject = jwt
        .payload
        .custom
        .vc
        .credential_subject
        .into_iter()
        .next()
        .ok_or_else(|| FormatterError::Failed("Missing credential subject".to_string()))?;

    let mut claims = CredentialSubject {
        id: credential_subject.id,
        claims: HashMap::from_iter(credential_subject.claims),
    };
    claims.claims.extend(metadata_claims);

    let issuer = match (jwt.payload.issuer, jwt.payload.custom.vc.issuer) {
        (None, None) => {
            return Err(FormatterError::Failed(
                "Missing issuer in SD-JWT".to_string(),
            ));
        }
        (None, Some(iss)) => IdentifierDetails::Did(iss.to_did_value()?),
        (Some(_), None) => issuer_details,
        (Some(i1), Some(i2)) => {
            if i1 != i2.as_url().as_str() {
                return Err(FormatterError::Failed(
                    "Invalid issuer in SD-JWT".to_string(),
                ));
            }
            IdentifierDetails::Did(i2.to_did_value()?)
        }
    };

    Ok((
        DetailCredential {
            id: jwt.payload.jwt_id,
            issuance_date: jwt.payload.issued_at,
            valid_from: jwt.payload.issued_at,
            valid_until: jwt.payload.expires_at,
            update_at: None,
            invalid_before: jwt.payload.invalid_before,
            issuer,
            subject: jwt
                .payload
                .subject
                .map(|did| did.parse().context("did parsing error"))
                .transpose()
                .map_err(|e| FormatterError::Failed(e.to_string()))?
                .map(IdentifierDetails::Did),
            claims,
            status: jwt.payload.custom.vc.credential_status,
            credential_schema: jwt
                .payload
                .custom
                .vc
                .credential_schema
                .and_then(|schema| schema.into_iter().next()),
        },
        key_binding_payload,
    ))
}

fn credential_to_claims(credential: &VcdmCredential) -> Result<Value, FormatterError> {
    credential
        .credential_subject
        .first()
        .map(|cs| {
            let id = cs
                .id
                .as_ref()
                .map(|id| ("id".to_string(), serde_json::json!(id)));
            let claims = cs
                .claims
                .clone()
                .into_iter()
                .map(|(key, val)| (key, val.into()));
            let object = serde_json::Map::from_iter(claims.chain(id));
            serde_json::Value::Object(object)
        })
        .ok_or_else(|| {
            FormatterError::Failed("Credential is missing credential subject".to_string())
        })
}
