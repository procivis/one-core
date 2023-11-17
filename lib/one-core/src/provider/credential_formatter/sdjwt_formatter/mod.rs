// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::data_structure::FormatJwtParams;
use crate::crypto::CryptoProvider;
use crate::provider::credential_formatter::sdjwt_formatter::model::{
    DecomposedToken, Disclosure, Sdvc,
};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use async_trait::async_trait;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};

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
    AuthenticationFn, CredentialFormatter, CredentialStatus, DetailCredential, FormatterError,
    Presentation, VerificationFn,
};

pub struct SDJWTFormatter {
    pub crypto: Arc<dyn CryptoProvider + Send + Sync>,
    pub params: FormatJwtParams,
}

#[async_trait]
impl CredentialFormatter for SDJWTFormatter {
    fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let (vc, disclosures) = self.format_hashed_credential(
            credential,
            credential_status,
            "sha-256",
            additional_context,
            additional_types,
        )?;

        let now = OffsetDateTime::now_utc();
        let valid_for = time::Duration::days(365 * 2);

        let payload = JWTPayload {
            issued_at: Some(now),
            expires_at: now.checked_add(valid_for),
            invalid_before: now.checked_sub(Duration::seconds(self.get_leeway() as i64)),
            subject: Some(holder_did.to_string()),
            issuer: credential.issuer_did.clone().map(|x| x.to_string()),
            jwt_id: Some(credential.id.to_string()),
            custom: vc,
            nonce: None,
        };

        let jwt = Jwt::new("SDJWT".to_owned(), algorithm.to_owned(), None, payload);

        let mut token = jwt.tokenize(auth_fn)?;

        let disclosures_token = tokenize_claims(disclosures)?;

        token.push_str(&disclosures_token);

        Ok(token)
    }

    async fn extract_credentials(
        &self,
        token: &str,
        verification: VerificationFn,
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
            subject: jwt.payload.subject,
            claims: CredentialSubject {
                values: HashMap::from_iter(
                    deserialized_disclosures
                        .into_iter()
                        .map(|(dis, _, _)| (dis.key, dis.value)),
                ),
            },
            status: jwt.payload.custom.vc.credential_status,
        })
    }

    fn format_presentation(
        &self,
        _credentials: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _nonce: Option<String>,
    ) -> Result<String, FormatterError> {
        // for presentation the JWT formatter is used
        unreachable!()
    }

    async fn extract_presentation(
        &self,
        token: &str,
        verification: VerificationFn,
    ) -> Result<Presentation, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<Sdvp> = Jwt::build_from_token(token, verification).await?;

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

    fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        prepare_sd_presentation(credential)
    }

    fn get_leeway(&self) -> u64 {
        match &self.params.leeway {
            None => 0,
            Some(leeway) => leeway.value,
        }
    }
}

impl SDJWTFormatter {
    fn format_hashed_credential(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
    ) -> Result<(Sdvc, Vec<String>), FormatterError> {
        let claims: Vec<String> = claims_to_formatted_disclosure(&credential.claims, &self.crypto);
        let hasher = self.crypto.get_hasher(algorithm)?;

        let vc = vc_from_credential(
            &hasher,
            &claims,
            credential_status,
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
