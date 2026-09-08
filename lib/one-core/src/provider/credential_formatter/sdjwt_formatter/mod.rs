//! SD-JWT implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use proc_macros::Provider;
use serde::Deserialize;
use serde_json::Value;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{CredentialFormat, DidValue, RevocationMethodId, SerializedCredential};
use time::Duration;
use uuid::Uuid;

use super::error::FormatterError;
use super::json_claims::{parse_claims, prepare_identifier};
use super::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, CredentialSubject, DetailCredential,
    Features, FormatterCapabilities, IdentifierDetails, SelectiveDisclosure, TokenVerifier,
    VerificationFn,
};
use super::sdjwt::disclosures::parse_token;
use super::sdjwt::mapper::vc_from_credential;
use super::sdjwt::model::*;
use super::sdjwt::{format_credential, model, parse_holder_identifier, prepare_sd_presentation};
use super::vcdm::{VcdmCredential, vcdm_metadata_claims};
use super::{CredentialFormatter, MetadataClaimSchema};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::jwt_metadata_claims;
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

#[derive(Provider)]
pub struct SDJWTFormatter {
    base_url: Option<Arc<str>>,
    config_id: CredentialFormat,
    crypto: Arc<dyn CryptoProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    data_type_provider: Arc<dyn DataTypeProvider>,
    client: Arc<dyn HttpClient>,
    params: Params,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway_seconds: Duration,
    embed_layout_properties: bool,
    #[serde(default = "default_sd_array_elements")]
    sd_array_elements: bool,
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "default_2_years")]
    expiration_seconds: Duration,
    revocation_method: Option<RevocationMethodId>,
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
    ) -> Result<SerializedCredential, FormatterError> {
        let Some(base_url) = self.base_url.as_ref() else {
            return Err(
                InitializationError::MissingDependency("base_url".to_string())
                    .error_while("missing base_url")
                    .into(),
            );
        };
        const HASH_ALG: &str = "sha-256";
        let mut vcdm = credential_data.vcdm;

        let now = crate::clock::now_utc();
        if vcdm.valid_from.is_none() {
            vcdm.valid_from = Some(now);
        }

        if !self.params.embed_layout_properties {
            vcdm.remove_layout_properties();
        }

        let inputs = SdJwtFormattingInputs {
            holder_identifier: credential_data.holder_identifier,
            holder_key_id: credential_data.holder_key_id,
            leeway: self.params.leeway_seconds,
            token_type: "SD_JWT".to_string(),
            issuer_certificate: credential_data.issuer_certificate,
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
            base_url,
        )
        .await
    }

    async fn format_status_list<'a>(
        &self,
        _revocation_list_url: String,
        _issuer: SelectedKey,
        _encoded_list: String,
        _algorithm: KeyAlgorithmType,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: RevocationType,
    ) -> Result<Vec<u8>, FormatterError> {
        Err(FormatterError::CouldNotFormat(
            "Cannot format StatusList with SD-JWT formatter".to_string(),
        ))
    }

    async fn extract_credentials<'a>(
        &self,
        token: &SerializedCredential,
        _credential_schema: Option<&'a CredentialSchema>,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(token, Some(&(verification)), &*self.crypto, &*self.client)
            .await
    }

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        let model::DecomposedToken { jwt, .. } = parse_token(&credential.token)?;
        let jwt: Jwt<VcClaim> = Jwt::build_from_token(jwt, None, None)
            .await
            .error_while("creating SD-JWT token")?;
        let hasher = self
            .crypto
            .get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

        prepare_sd_presentation(credential, &*hasher, &self.user_claims_path()).await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &SerializedCredential,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(token, None, &*self.crypto, &*self.client).await
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
            features: vec![
                Features::SelectiveDisclosure,
                Features::SupportsCredentialDesign,
                Features::SupportsCombinedPresentation,
                Features::SupportsTxCode,
            ],
            selective_disclosure: vec![SelectiveDisclosure::AnyLevel],
            issuance_did_methods: vec![DidType::Key, DidType::Web, DidType::Jwk, DidType::WebVh],
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
            forbidden_claim_names: vec!["0".to_string(), "id".to_string()],
            issuance_identifier_types: vec![IdentifierType::Did],
            verification_identifier_types: vec![IdentifierType::Did, IdentifierType::Certificate],
            holder_identifier_types: vec![IdentifierType::Did, IdentifierType::Key],
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

    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<Credential, FormatterError> {
        let now = crate::clock::now_utc();

        let (parsed_credential, issuer, _): (Jwt<VcClaim>, _, _) =
            Jwt::build_from_token_with_disclosures(
                credential,
                &*self.crypto,
                Some(&verification),
                None,
                &*self.client,
            )
            .await?;

        let holder_identifier = parse_holder_identifier(
            &organisation,
            &parsed_credential,
            self.key_algorithm_provider.as_ref(),
            self.did_method_provider.as_ref(),
        )?;

        let revocation_method = if let Some(status) = parsed_credential
            .payload
            .custom
            .vc
            .credential_status
            .first()
        {
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
        let vc_types = parsed_credential.payload.custom.vc.r#type.clone();
        let schema_name = vc_types
            .iter()
            .find(|t| t != &"VerifiableCredential")
            .cloned()
            .unwrap_or_else(|| "VerifiableCredential".to_string());

        // Get metadata claims first (includes vc type and standard JWT claims)
        let metadata_claims = parsed_credential
            .get_metadata_claims()
            .error_while("getting metadata claims")?;

        // Parse claims from credential subject
        let credential_subject = parsed_credential
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
            credential_id,
        )
        .await?;

        // Add parsed metadata claims
        let (metadata_claims, metadata_claim_schemas) = parse_claims(
            metadata_claims,
            self.data_type_provider.as_ref(),
            credential_id,
        )
        .await?;
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
            formats: vec![format.clone()].into(),
            batch_size: None,
            key_storage_security: None,
            layout_properties: None,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            requires_wallet_instance_attestation: false,
            claim_schemas: claim_schemas.into(),
            organisation: organisation.clone().into(),
            transaction_code: None,
            allow_revocation: revocation_method.is_some(),
            translations: Default::default(),
            embedded_disclosure_policy: None,
        };

        let issuer_identifier = prepare_identifier(
            &issuer,
            self.key_algorithm_provider.as_ref(),
            self.did_method_provider.as_ref(),
            organisation.to_owned(),
        )?;

        Ok(Credential {
            expires_at: parsed_credential.payload.expires_at,
            ecosystem: None,
            id: credential_id,
            created_date: now,
            issuance_date: parsed_credential.payload.issued_at,
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
            wallet_unit_attestation_blob_id: None,
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

impl SDJWTFormatter {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        base_url: Option<Arc<str>>,
        config_id: CredentialFormat,
        params: serde_json::Value,
        crypto: Arc<dyn CryptoProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        data_type_provider: Arc<dyn DataTypeProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_id,
            params,
            crypto,
            did_method_provider,
            key_algorithm_provider,
            data_type_provider,
            client,
            base_url,
        })
    }
}

pub(crate) async fn extract_credentials_internal(
    token: &SerializedCredential,
    verification: Option<&VerificationFn>,
    crypto: &dyn CryptoProvider,
    http_client: &dyn HttpClient,
) -> Result<DetailCredential, FormatterError> {
    let (jwt, issuer_details, _): (Jwt<VcClaim>, _, _) =
        Jwt::build_from_token_with_disclosures(token, crypto, verification, None, http_client)
            .await?;
    let metadata_claims = jwt
        .get_metadata_claims()
        .error_while("getting metadata claims")?;
    let credential_subject = jwt
        .payload
        .custom
        .vc
        .credential_subject
        .into_iter()
        .next()
        .ok_or_else(|| {
            FormatterError::CouldNotExtractCredentials("Missing credential subject".to_string())
        })?;

    let mut claims = CredentialSubject {
        id: credential_subject.id,
        claims: HashMap::from_iter(credential_subject.claims),
    };
    claims.claims.extend(metadata_claims);

    let issuer = match (jwt.payload.issuer, jwt.payload.custom.vc.issuer) {
        (None, None) => {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Missing issuer in SD-JWT".to_string(),
            ));
        }
        (None, Some(iss)) => IdentifierDetails::Did(iss.to_did_value()?),
        (Some(_), None) => issuer_details,
        (Some(i1), Some(i2)) => {
            if i1 != i2.as_url().as_str() {
                return Err(FormatterError::CouldNotExtractCredentials(
                    "Invalid issuer in SD-JWT".to_string(),
                ));
            }
            IdentifierDetails::Did(i2.to_did_value()?)
        }
    };

    let subject = match (
        jwt.payload.subject.as_ref(),
        jwt.payload.proof_of_possession_key.as_ref(),
    ) {
        (Some(sub), None) if sub.starts_with("did:") => {
            let did = DidValue::from_str(sub)
                .map_err(DidMethodError::DidValueError)
                .error_while("parsing subject DID")?;
            Some(IdentifierDetails::Did(did))
        }
        (_, Some(holder_key)) => Some(IdentifierDetails::Key(holder_key.jwk.jwk().clone())),
        (None, None) => None,
        (Some(sub), None) => {
            return Err(FormatterError::CouldNotExtractCredentials(format!(
                "Could not determine public key for subject: `{sub}`"
            )));
        }
    };

    Ok(DetailCredential {
        id: jwt.payload.jwt_id,
        issuance_date: jwt.payload.issued_at,
        valid_from: jwt.payload.issued_at,
        valid_until: jwt.payload.expires_at,
        update_at: None,
        invalid_before: jwt.payload.invalid_before,
        issuer,
        subject,
        claims,
        status: jwt.payload.custom.vc.credential_status,
        credential_schema: jwt
            .payload
            .custom
            .vc
            .credential_schema
            .and_then(|schema| schema.into_iter().next()),
    })
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
            FormatterError::CouldNotFormat("Credential is missing credential subject".to_string())
        })
}
