//! SD-JWT implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use serde_json::Value;
use shared_types::DidValue;
use time::Duration;

use crate::config::core_config::{
    DidType, ExchangeType, KeyAlgorithmType, KeyStorageType, RevocationType,
};
use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialPresentation, CredentialSubject, DetailCredential,
    ExtractPresentationCtx, Features, FormatPresentationCtx, FormatterCapabilities,
    HolderBindingCtx, Presentation, SelectiveDisclosure, VerificationFn,
};
use crate::provider::credential_formatter::{CredentialFormatter, StatusListType};
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;

#[cfg(test)]
mod test;

use super::jwt::model::JWTPayload;
use super::model::CredentialData;
use super::vcdm::VcdmCredential;
use crate::provider::credential_formatter::sdjwt::disclosures::parse_token;
use crate::provider::credential_formatter::sdjwt::mapper::vc_from_credential;
use crate::provider::credential_formatter::sdjwt::model::*;
use crate::provider::credential_formatter::sdjwt::{
    format_credential, model, prepare_sd_presentation,
};
use crate::provider::did_method::provider::DidMethodProvider;

pub struct SDJWTFormatter {
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
            holder_did: credential_data.holder_did,
            holder_key_id: credential_data.holder_key_id,
            leeway: self.params.leeway,
            token_type: "SD_JWT".to_string(),
            vc_type: None,
        };
        let payload_from_cred_and_digests = |cred: VcdmCredential, digests: Vec<String>| {
            vc_from_credential(cred, digests, HASH_ALG)
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
            "Cannot format StatusList with SD-JWT formatter".to_string(),
        ))
    }

    async fn extract_credentials(
        &self,
        token: &str,
        verification: VerificationFn,
        holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        let (credential, _) = extract_credentials_internal(
            token,
            Some(&(verification)),
            &*self.crypto,
            holder_binding_ctx,
            Duration::seconds(self.get_leeway() as i64),
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

        prepare_sd_presentation(credential, &*hasher, holder_binding_ctx, holder_binding_fn).await
    }

    async fn extract_credentials_unverified(
        &self,
        token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        let (credential, _) = extract_credentials_internal(
            token,
            None,
            &*self.crypto,
            None,
            Duration::seconds(self.get_leeway() as i64),
        )
        .await?;

        Ok(credential)
    }

    async fn format_presentation(
        &self,
        credentials: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _context: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        if credentials.len() != 1 {
            return Err(FormatterError::Failed(
                "SD-JWT formatter only supports single credential presentations".to_string(),
            ));
        }

        let credential = credentials.first().ok_or(FormatterError::Failed(
            "Empty credential list passed to format_presentation".to_string(),
        ))?;

        Ok(credential.to_string())
    }

    async fn extract_presentation(
        &self,
        token: &str,
        verification: VerificationFn,
        context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(token, Some(&verification), context)
            .await
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(token, None, context)
            .await
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
            ],
            selective_disclosure: vec![SelectiveDisclosure::AnyLevel],
            issuance_did_methods: vec![DidType::Key, DidType::Web, DidType::Jwk, DidType::X509],
            issuance_exchange_protocols: vec![ExchangeType::OpenId4Vc],
            proof_exchange_protocols: vec![ExchangeType::OpenId4Vc],
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
            forbidden_claim_names: vec!["0".to_string()],
        }
    }
}

impl SDJWTFormatter {
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
    verification: Option<&VerificationFn>,
    crypto: &dyn CryptoProvider,
    holder_binding_ctx: Option<HolderBindingCtx>,
    leeway: Duration,
) -> Result<(DetailCredential, Option<JWTPayload<KeyBindingPayload>>), FormatterError> {
    let (jwt, key_binding_payload): (Jwt<VcClaim>, Option<JWTPayload<KeyBindingPayload>>) =
        Jwt::build_from_token_with_disclosures(
            token,
            crypto,
            verification,
            holder_binding_ctx,
            leeway,
        )
        .await?;
    let credential_subject = jwt
        .payload
        .custom
        .vc
        .credential_subject
        .into_iter()
        .next()
        .ok_or_else(|| FormatterError::Failed("Missing credential subject".to_string()))?;

    let claims = CredentialSubject {
        id: credential_subject.id,
        claims: HashMap::from_iter(credential_subject.claims),
    };

    let issuer_did = match (jwt.payload.issuer, jwt.payload.custom.vc.issuer) {
        (None, None) => {
            return Err(FormatterError::Failed(
                "Missing issuer in SD-JWT".to_string(),
            ))
        }
        (None, Some(iss)) => iss.to_did_value()?,
        (Some(iss), None) => iss
            .parse()
            .map_err(|err| FormatterError::Failed(format!("Invalid issuer did: {err}")))?,
        (Some(i1), Some(i2)) => {
            if i1 != i2.as_url().as_str() {
                return Err(FormatterError::Failed(
                    "Invalid issuer in SD-JWT".to_string(),
                ));
            }

            i2.to_did_value()?
        }
    };

    Ok((
        DetailCredential {
            id: jwt.payload.jwt_id,
            valid_from: jwt.payload.issued_at,
            valid_until: jwt.payload.expires_at,
            update_at: None,
            invalid_before: jwt.payload.invalid_before,
            issuer_did: Some(issuer_did),
            subject: jwt
                .payload
                .subject
                .map(|did| did.parse().context("did parsing error"))
                .transpose()
                .map_err(|e| FormatterError::Failed(e.to_string()))?,
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

impl SDJWTFormatter {
    async fn extract_presentation_internal(
        &self,
        token: &str,
        verification: Option<&VerificationFn>,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        // W3C VP SD-JWT tokens and SD-JWT tokens.
        let as_jwt_vp: Result<Jwt<Sdvp>, FormatterError> =
            Jwt::build_from_token(token, verification, None)
                .await
                .map_err(|e| FormatterError::Failed(format!("Failed to build Jwt<Sdvp>: {e}")));

        if let Ok(jwt_vp) = as_jwt_vp {
            return jwt_vp.try_into().map_err(|e| {
                FormatterError::Failed(format!("Failed to convert Jwt<Sdvp> to Presentation: {e}"))
            });
        }

        let (credential, proof_of_key_possesion) = extract_credentials_internal(
            token,
            verification,
            &*self.crypto,
            None,
            Duration::seconds(self.get_leeway() as i64),
        )
        .await?;

        let proof_of_key_possesion = proof_of_key_possesion.ok_or(FormatterError::Failed(
            "Missing proof of key possesion".to_string(),
        ))?;

        let presentation = Presentation {
            id: proof_of_key_possesion.jwt_id,
            issued_at: proof_of_key_possesion.issued_at,
            expires_at: proof_of_key_possesion.expires_at,
            issuer_did: credential.subject,
            nonce: Some(proof_of_key_possesion.custom.nonce),
            credentials: vec![token.to_string()],
        };

        Ok(presentation)
    }
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
            let claims = cs.claims.clone().into_iter();
            let object = serde_json::Map::from_iter(claims.chain(id));
            serde_json::Value::Object(object)
        })
        .ok_or_else(|| {
            FormatterError::Failed("Credential is missing credential subject".to_string())
        })
}
