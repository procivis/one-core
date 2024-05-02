// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::sync::Arc;

use async_trait::async_trait;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use serde::Deserialize;
use shared_types::DidValue;
use time::Duration;

use crate::crypto::CryptoProvider;
use crate::provider::credential_formatter::common::nest_claims;
use crate::provider::credential_formatter::sdjwt_formatter::model::{
    DecomposedToken, Disclosure, Sdvc,
};

#[cfg(test)]
mod test;

mod mapper;
use self::mapper::*;

mod model;
use self::model::*;

mod verifier;
use self::verifier::*;

use super::jwt::model::JWTPayload;
use super::jwt::Jwt;
use super::model::{CredentialPresentation, CredentialSubject};
use super::{
    AuthenticationFn, CredentialData, CredentialFormatter, DetailCredential, ExtractCredentialsCtx,
    ExtractPresentationCtx, FormatPresentationCtx, FormatterCapabilities, FormatterError,
    Presentation, VerificationFn,
};

pub struct SDJWTFormatter {
    pub crypto: Arc<dyn CryptoProvider>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    leeway: u64,
}

#[async_trait]
impl CredentialFormatter for SDJWTFormatter {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        _json_ld_context_url: Option<String>,
        _custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        let issuer = credential.issuer_did.to_string();
        let id = credential.id.clone();

        let issued_at = credential.issuance_date;
        let expires_at = issued_at.checked_add(credential.valid_for);

        let (vc, disclosures) = self.format_hashed_credential(
            credential,
            "sha-256",
            additional_context,
            additional_types,
        )?;

        let payload = JWTPayload {
            issued_at: Some(issued_at),
            expires_at,
            invalid_before: issued_at.checked_sub(Duration::seconds(self.get_leeway() as i64)),
            subject: Some(holder_did.to_string()),
            issuer: Some(issuer),
            jwt_id: Some(id),
            custom: vc,
            nonce: None,
        };

        let jwt = Jwt::new("SDJWT".to_owned(), algorithm.to_owned(), None, payload);

        let mut token = jwt.tokenize(auth_fn).await?;

        let disclosures_token = tokenize_claims(disclosures)?;

        token.push_str(&disclosures_token);

        Ok(token)
    }

    async fn extract_credentials(
        &self,
        token: &str,
        verification: VerificationFn,
        _ctx: ExtractCredentialsCtx,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(token, Some(verification))
            .await
    }

    async fn extract_credentials_unverified(
        &self,
        token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(token, None).await
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

        Ok(Presentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer_did: jwt.payload.issuer.map(|v| match v.parse() {
                Ok(v) => v,
                Err(err) => match err {},
            }),
            nonce: jwt.payload.nonce,
            credentials: jwt.payload.custom.vp.verifiable_credential,
        })
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        prepare_sd_presentation(credential)
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                "EDDSA".to_owned(),
                "ES256".to_owned(),
                "DILITHIUM".to_owned(),
            ],
            features: vec!["SELECTIVE_DISCLOSURE".to_string()],
            issuance_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            proof_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            revocation_methods: vec![
                "NONE".to_string(),
                "BITSTRINGSTATUSLIST".to_string(),
                "LVVC".to_string(),
            ],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let jwt: Jwt<Sdvp> = Jwt::build_from_token(token, None).await?;

        Ok(Presentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer_did: jwt.payload.issuer.map(|v| match v.parse() {
                Ok(v) => v,
                Err(err) => match err {},
            }),
            nonce: jwt.payload.nonce,
            credentials: jwt.payload.custom.vp.verifiable_credential,
        })
    }
}

impl SDJWTFormatter {
    pub fn new(params: Params, crypto: Arc<dyn CryptoProvider>) -> Self {
        Self { params, crypto }
    }

    async fn extract_credentials_internal(
        &self,
        token: &str,
        verification: Option<VerificationFn>,
    ) -> Result<DetailCredential, FormatterError> {
        let DecomposedToken {
            deserialized_disclosures,
            jwt,
        } = extract_disclosures(token)?;

        let jwt: Jwt<Sdvc> = Jwt::build_from_token(jwt, verification).await?;

        let hasher = self
            .crypto
            .get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

        verify_claims(
            &jwt.payload.custom.vc.credential_subject.claims,
            &deserialized_disclosures,
            &hasher,
        )?;

        Ok(DetailCredential {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            invalid_before: jwt.payload.invalid_before,
            issuer_did: jwt.payload.issuer.map(|v| match v.parse() {
                Ok(v) => v,
                Err(err) => match err {},
            }),
            subject: jwt.payload.subject.map(|v| match v.parse() {
                Ok(v) => v,
                Err(err) => match err {},
            }),
            claims: CredentialSubject {
                values: nest_claims(
                    deserialized_disclosures
                        .into_iter()
                        .map(|(dis, _, _)| (dis.key, dis.value))
                        .collect::<Vec<(String, String)>>(),
                )?,
            },
            status: jwt.payload.custom.vc.credential_status,
            credential_schema: jwt.payload.custom.vc.credential_schema,
        })
    }

    fn format_hashed_credential(
        &self,
        credential: CredentialData,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
    ) -> Result<(Sdvc, Vec<String>), FormatterError> {
        let claims: Vec<String> = claims_to_formatted_disclosure(&credential.claims, &self.crypto);
        let hasher = self.crypto.get_hasher(algorithm)?;

        let vc = vc_from_credential(
            credential,
            &hasher,
            &claims,
            additional_context,
            additional_types,
            algorithm,
        );

        Ok((vc, claims))
    }
}

fn prepare_sd_presentation(presentation: CredentialPresentation) -> Result<String, FormatterError> {
    let DecomposedToken {
        jwt,
        deserialized_disclosures,
    } = extract_disclosures(&presentation.token)?;

    let mut token = jwt.to_owned();
    for (disclosure, _, disclosure_encoded) in deserialized_disclosures {
        if presentation.disclosed_keys.contains(&disclosure.key) {
            token.push('~');
            token.push_str(&disclosure_encoded);
        }
    }

    Ok(token)
}

fn extract_disclosures(token: &str) -> Result<DecomposedToken, FormatterError> {
    let mut token_parts = token.split('~');
    let jwt = token_parts.next().ok_or(FormatterError::MissingPart)?;

    let disclosures_decoded_encoded: Vec<(String, String)> = token_parts
        .filter_map(|encoded| {
            let bytes = Base64UrlSafeNoPadding::decode_to_vec(encoded, None).ok()?;
            let decoded = String::from_utf8(bytes).ok()?;
            Some((decoded, encoded.to_owned()))
        })
        .collect();

    let deserialized_claims: Vec<(Disclosure, String, String)> = disclosures_decoded_encoded
        .into_iter()
        .filter_map(|(decoded, encoded)| {
            serde_json::from_str(&decoded)
                .ok()
                .map(|disclosure| (disclosure, decoded, encoded))
        })
        .collect();

    Ok(DecomposedToken {
        jwt,
        deserialized_disclosures: deserialized_claims,
    })
}
