//! SD-JWT VC implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

pub(crate) mod model;

#[cfg(test)]
mod test;

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use model::SdJwtVcStatus;
use one_crypto::CryptoProvider;
use sdjwt::format_credential;
use serde::Deserialize;
use serde_json::Value;
use shared_types::{CredentialSchemaId, DidValue};
use time::Duration;
use url::Url;

use super::model::{CredentialData, HolderBindingCtx};
use super::sdjwt;
use super::vcdm::VcdmCredential;
use crate::config::core_config::{
    DidType, ExchangeType, KeyAlgorithmType, KeyStorageType, RevocationType,
};
use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialPresentation, CredentialSubject, DetailCredential,
    ExtractPresentationCtx, Features, FormatPresentationCtx, FormatterCapabilities, Presentation,
    SelectiveDisclosure, VerificationFn,
};
use crate::provider::credential_formatter::sdjwt::disclosures::parse_token;
use crate::provider::credential_formatter::sdjwt::model::{
    DecomposedToken, SdJwtFormattingInputs, Sdvp,
};
use crate::provider::credential_formatter::sdjwt::prepare_sd_presentation;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVc;
use crate::provider::credential_formatter::{CredentialFormatter, StatusListType};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::token_status_list::credential_status_from_sdjwt_status;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;

pub struct SDJWTVCFormatter {
    crypto: Arc<dyn CryptoProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
    pub embed_layout_properties: bool,
}

#[async_trait]
impl CredentialFormatter for SDJWTVCFormatter {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        const HASH_ALG: &str = "sha-256";
        // todo: here we need sdjwt-vc specific data model instead of using vcdm
        let vcdm = credential_data.vcdm;

        let schema_id = vcdm
            .credential_schema
            .as_ref()
            .and_then(|schemas| schemas.iter().next())
            .map(|schema| schema.id.to_owned())
            .ok_or_else(|| FormatterError::Failed("Missing credential schema id".to_string()))?;
        let inputs = SdJwtFormattingInputs {
            holder_did: credential_data.holder_did,
            holder_key_id: credential_data.holder_key_id,
            leeway: self.params.leeway,
            token_type: "vc+sd-jwt".to_string(),
            vc_type: Some(schema_id),
        };
        let payload_from_cred_and_digests = |cred: VcdmCredential, digests: Vec<String>| {
            sdjwt_vc_from_credential(cred, digests, HASH_ALG)
        };

        format_credential(
            vcdm,
            inputs,
            auth_fn,
            &*self.crypto.get_hasher(HASH_ALG)?,
            &*self.did_method_provider,
            credential_to_claims,
            payload_from_cred_and_digests,
        )
        .await
    }

    async fn format_status_list(
        &self,
        _revocation_list_url: String,
        _issuer_did: &Did,
        _encoded_list: String,
        _algorithm: String,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        Err(FormatterError::Failed(
            "Cannot format StatusList with SD-JWT VC formatter".to_string(),
        ))
    }

    async fn extract_credentials(
        &self,
        token: &str,
        verification: VerificationFn,
        holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(
            token,
            Some(verification),
            &*self.crypto,
            holder_binding_ctx,
            Duration::seconds(self.get_leeway() as i64),
        )
        .await
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
        holder_binding_ctx: Option<HolderBindingCtx>,
        holder_binding_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError> {
        let DecomposedToken { jwt, .. } = parse_token(&credential.token)?;
        let jwt: Jwt<SdJwtVc> = Jwt::build_from_token(jwt, None).await?;
        let hasher = self
            .crypto
            .get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

        prepare_sd_presentation(credential, &*hasher, holder_binding_ctx, holder_binding_fn).await
    }

    async fn extract_credentials_unverified(
        &self,
        token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(
            token,
            None,
            &*self.crypto,
            None,
            Duration::seconds(self.get_leeway() as i64),
        )
        .await
    }

    async fn format_presentation(
        &self,
        _credentials: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _context: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        // for presentation the JWT formatter is used
        unreachable!()
    }

    async fn extract_presentation(
        &self,
        token: &str,
        verification: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<Sdvp> = Jwt::build_from_token(token, Some(verification)).await?;

        jwt.try_into()
            .context("SDVP mapping failed")
            .map_err(|_| FormatterError::Failed("Jwt mapping error".to_string()))
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let jwt: Jwt<Sdvp> = Jwt::build_from_token(token, None).await?;

        jwt.try_into()
            .context("SDVP mapping failed")
            .map_err(|_| FormatterError::Failed("Jwt mapping error".to_string()))
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Es256,
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
                Features::RequiresSchemaId,
                Features::SupportsCredentialDesign,
            ],
            selective_disclosure: vec![SelectiveDisclosure::AnyLevel],
            issuance_did_methods: vec![DidType::Key, DidType::Web, DidType::Jwk, DidType::X509],
            issuance_exchange_protocols: vec![ExchangeType::OpenId4Vc],
            proof_exchange_protocols: vec![ExchangeType::OpenId4Vc],
            revocation_methods: vec![RevocationType::None, RevocationType::TokenStatusList],
            verification_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Es256,
                KeyAlgorithmType::Dilithium,
            ],
            verification_key_storages: vec![
                KeyStorageType::Internal,
                KeyStorageType::AzureVault,
                KeyStorageType::SecureElement,
            ],
            forbidden_claim_names: vec!["0".to_string()],
        }
    }

    fn credential_schema_id(
        &self,
        _id: CredentialSchemaId,
        request: &CreateCredentialSchemaRequestDTO,
        core_base_url: &str,
    ) -> Result<String, FormatterError> {
        let Some(schema_id) = request.schema_id.as_ref() else {
            return Err(FormatterError::Failed("Missing schema_id".to_string()));
        };

        if request.external_schema {
            return Ok(schema_id.to_string());
        }

        let mut url = Url::parse(core_base_url)
            .map_err(|error| FormatterError::Failed(format!("Invalid base URL: {error}")))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| FormatterError::Failed("Invalid base URL".to_string()))?;
            let organisation_id = request.organisation_id.to_string();
            // /ssi/vct/v1/:organisation_id/:schema_id
            segments.extend(["ssi", "vct", "v1", &organisation_id, schema_id]);
        }

        Ok(url.to_string())
    }
}

impl SDJWTVCFormatter {
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
    ) -> Self {
        Self {
            params,
            crypto,
            did_method_provider,
        }
    }
}

pub(super) async fn extract_credentials_internal(
    token: &str,
    verification: Option<VerificationFn>,
    crypto: &dyn CryptoProvider,
    holder_binding_ctx: Option<HolderBindingCtx>,
    leeway: Duration,
) -> Result<DetailCredential, FormatterError> {
    let jwt: Jwt<SdJwtVc> = Jwt::build_from_token_with_disclosures(
        token,
        crypto,
        verification,
        holder_binding_ctx,
        leeway,
    )
    .await?;

    let subject = jwt
        .payload
        .subject
        .map(|did| DidValue::from_str(&did))
        .transpose()
        .map_err(|e| FormatterError::Failed(e.to_string()))?;

    Ok(DetailCredential {
        id: jwt.payload.jwt_id,
        valid_from: jwt.payload.issued_at,
        valid_until: jwt.payload.expires_at,
        update_at: None,
        invalid_before: jwt.payload.invalid_before,
        issuer_did: jwt
            .payload
            .issuer
            .map(|did| DidValue::from_str(&did))
            .transpose()
            .map_err(|e| FormatterError::Failed(e.to_string()))?,
        subject,
        claims: CredentialSubject {
            claims: jwt.payload.custom.public_claims,
            id: None,
        },
        status: credential_status_from_sdjwt_status(&jwt.payload.custom.status),
        credential_schema: None,
    })
}

fn credential_to_claims(credential: &VcdmCredential) -> Result<Value, FormatterError> {
    credential
        .credential_subject
        .first()
        .map(|cs| {
            let object = serde_json::Map::from_iter(cs.claims.clone());
            serde_json::Value::Object(object)
        })
        .ok_or_else(|| {
            FormatterError::Failed("Credential is missing credential subject".to_string())
        })
}

fn sdjwt_vc_from_credential(
    credential: VcdmCredential,
    mut hashed_claims: Vec<String>,
    algorithm: &str,
) -> Result<SdJwtVc, FormatterError> {
    hashed_claims.sort_unstable();

    let status = credential.credential_status.first().and_then(|status| {
        let obj: serde_json::Value = status
            .additional_fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        serde_json::from_value(obj).ok()
    });
    Ok(SdJwtVc {
        digests: hashed_claims,
        hash_alg: Some(algorithm.to_owned()),
        status: status.map(|status| SdJwtVcStatus {
            status_list: status,
            custom_claims: Default::default(),
        }),
        public_claims: Default::default(),
    })
}
