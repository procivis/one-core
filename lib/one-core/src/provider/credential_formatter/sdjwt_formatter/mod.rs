// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::collections::HashMap;

use crate::crypto::Crypto;
use crate::provider::credential_formatter::sdjwt_formatter::models::{
    DecomposedToken, Disclosure, Sdvc,
};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

mod mapper;
use self::mapper::*;

mod models;
use self::models::*;

mod verifier;
use self::verifier::*;

use super::jwt::model::JWTPayload;
use super::jwt::{AuthenticationFn, Jwt, VerificationFn};
use super::model::CredentialSubject;
use super::{
    CredentialFormatter, CredentialPresentation, CredentialStatus, DetailCredential,
    FormatterError, PresentationCredential,
};

pub struct SDJWTFormatter {
    pub crypto: Crypto,
}

impl CredentialFormatter for SDJWTFormatter {
    fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        holder_did: &str,
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
            invalid_before: now.checked_sub(Duration::seconds(30)),
            subject: Some(holder_did.to_owned()),
            issuer: credential.issuer_did.clone(),
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

    fn extract_credentials(
        &self,
        token: &str,
        verify_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        let DecomposedToken {
            deserialized_disclosures,
            jwt,
        } = decompose_sd_token(token)?;

        let jwt: Jwt<Sdvc> = Jwt::build_from_token(jwt, verify_fn)?;

        let hasher = self
            .crypto
            .hashers
            .get(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))
            .ok_or(FormatterError::MissingHasher)?;

        verify_claims(
            &jwt.payload.custom.vc.credential_subject.claims,
            &deserialized_disclosures,
            hasher,
        )?;

        Ok(DetailCredential {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            invalid_before: jwt.payload.invalid_before,
            issuer_did: jwt.payload.issuer,
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
        credentials: &[PresentationCredential],
        holder_did: &str,
        algorithm: &str,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let vp: Sdvp = format_payload(credentials);

        let now = OffsetDateTime::now_utc();
        let valid_for = time::Duration::minutes(5);

        let payload = JWTPayload {
            issued_at: Some(now),
            expires_at: now.checked_add(valid_for),
            invalid_before: now.checked_sub(Duration::seconds(30)),
            issuer: Some(holder_did.to_owned()),
            subject: Some(holder_did.to_owned()),
            jwt_id: Some(Uuid::new_v4().to_string()),
            custom: vp,
            nonce: None,
        };

        let jwt = Jwt::new("SDJWT".to_owned(), algorithm.to_owned(), None, payload);

        jwt.tokenize(auth_fn)
    }

    fn extract_presentation(
        &self,
        token: &str,
        verify_fn: VerificationFn,
    ) -> Result<CredentialPresentation, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<Sdvp> = Jwt::build_from_token(token, verify_fn)?;

        Ok(CredentialPresentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer_did: jwt.payload.issuer,
            credentials: jwt.payload.custom.vp.verifiable_credential,
        })
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
        let claims: Vec<String> = claims_to_formatted_disclosure(&credential.claims);
        let hasher = self
            .crypto
            .hashers
            .get(algorithm)
            .ok_or(FormatterError::MissingHasher)?;

        let vc = vc_from_credential(
            hasher,
            &claims,
            credential_status,
            additional_context,
            additional_types,
            algorithm,
        );

        Ok((vc, claims))
    }
}

fn prepare_sd_presentation(
    presentation: &PresentationCredential,
) -> Result<String, FormatterError> {
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

fn format_payload(credentials: &[PresentationCredential]) -> Sdvp {
    Sdvp {
        vp: VPContent {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
            r#type: vec!["VerifiablePresentation".to_owned()],
            verifiable_credential: credentials
                .iter()
                .filter_map(|credential| prepare_sd_presentation(credential).ok())
                .collect(),
        },
    }
}

fn decompose_sd_token(token: &str) -> Result<DecomposedToken, FormatterError> {
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
