// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::collections::HashMap;

use crate::credential_formatter::sdjwt::mapper::json_from_decoded;
use crate::credential_formatter::sdjwt::models::{
    DecomposedToken, Disclosure, JWTHeader, JWTPayload, VC,
};
use crate::credential_formatter::CredentialSubject;
use crate::crypto::Crypto;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder};
use serde::de::DeserializeOwned;
use serde::Serialize;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

mod mapper;
use self::mapper::*;

mod models;
use self::models::*;

mod verifier;
use self::verifier::*;

use super::{
    CredentialFormatter, CredentialPresentation, CredentialStatus, DetailCredential,
    FormatterError, PresentationCredential,
};

pub struct SDJWTFormatter {
    pub crypto: Crypto,
}

// Temporary key provider
fn get_temp_keys() -> (Vec<u8>, Vec<u8>) {
    let private =
        Base64::decode_to_vec("cHl197m5y0cTmdvl8M1jZhWEw+S8btcEQ+pI8grCadw=", None).unwrap();
    let public =
        Base64::decode_to_vec("rTa2X5z9tCT9eVFG0yKDR5w4k89fwHohWxcd1I2LDsQ=", None).unwrap();

    (private, public)
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
    ) -> Result<String, FormatterError> {
        let (vc, disclosures) = self.format_hashed_credential(
            credential,
            credential_status,
            "sha-256",
            additional_context,
            additional_types,
        )?;

        let (header, payload) = prepare_jwt(
            algorithm,
            OffsetDateTime::now_utc(),
            credential
                .issuer_did
                .as_ref()
                .unwrap_or(&"NOT PROVIDED".to_owned()),
            holder_did,
            credential.id.to_string(),
            time::Duration::days(365 * 2),
            vc,
        );

        let signer = self
            .crypto
            .signers
            .get(algorithm)
            .ok_or(FormatterError::MissingSigner)?;

        let mut token = tokenize_jwt(signer, header, payload)?;

        let disclosures_token = tokenize_claims(disclosures)?;

        token.push_str(&disclosures_token);

        Ok(token)
    }

    fn extract_credentials(&self, token: &str) -> Result<DetailCredential, FormatterError> {
        let DecomposedToken {
            header,
            header_json,
            payload,
            payload_json,
            signature,
            disclosures,
        } = decompose_token::<VC>(token)?;

        verify_signature(
            &self.crypto,
            &header_json,
            &payload_json,
            &signature,
            &header.algorithm,
        )?;

        let hasher = self
            .crypto
            .hashers
            .get(&payload.hash_alg.unwrap_or("sha-256".to_string()))
            .ok_or(FormatterError::MissingHasher)?;

        verify_claims(
            &payload.custom.vc.credential_subject.claims,
            &disclosures,
            hasher,
        )?;

        Ok(DetailCredential {
            id: payload.jwt_id,
            issued_at: payload.issued_at,
            expires_at: payload.expires_at,
            invalid_before: payload.invalid_before,
            issuer_did: payload.issuer,
            subject: payload.subject,
            claims: CredentialSubject {
                values: HashMap::from_iter(
                    disclosures
                        .into_iter()
                        .map(|(dis, _, _)| (dis.key, dis.value)),
                ),
                one_credential_schema: payload.custom.vc.credential_subject.one_credential_schema,
            },
            status: payload.custom.vc.credential_status,
        })
    }

    fn format_presentation(
        &self,
        credentials: &[PresentationCredential],
        holder_did: &str,
        algorithm: &str,
    ) -> Result<String, FormatterError> {
        let payload: VP = format_payload(credentials);

        let (header, payload) = prepare_jwt(
            algorithm,
            OffsetDateTime::now_utc(),
            holder_did,
            holder_did,
            Uuid::new_v4().to_string(),
            time::Duration::minutes(5),
            payload,
        );

        let signer = self
            .crypto
            .signers
            .get(algorithm)
            .ok_or(FormatterError::MissingSigner)?;

        let token = tokenize_jwt(signer, header, payload)?;

        Ok(token)
    }

    fn extract_presentation(
        &self,
        presentation: &str,
    ) -> Result<CredentialPresentation, FormatterError> {
        let DecomposedToken {
            header,
            header_json,
            payload,
            payload_json,
            signature,
            ..
        } = decompose_token::<VP>(presentation)?;

        verify_signature(
            &self.crypto,
            &header_json,
            &payload_json,
            &signature,
            &header.algorithm,
        )?;

        Ok(CredentialPresentation {
            id: payload.jwt_id,
            issued_at: payload.issued_at,
            expires_at: payload.expires_at,
            issuer_did: payload.issuer,
            credentials: payload.custom.vp.verifiable_credential,
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
    ) -> Result<(VC, Vec<String>), FormatterError> {
        let hasher = self
            .crypto
            .hashers
            .get(algorithm)
            .ok_or(FormatterError::MissingHasher)?;

        let claims: Vec<String> = claims_to_formatted_disclosure(&credential.claims);

        let vc = vc_from_credential(
            &claims,
            credential,
            credential_status,
            hasher,
            additional_context,
            additional_types,
        );

        Ok((vc, claims))
    }
}

fn prepare_sd_presentation(
    presentation: &PresentationCredential,
) -> Result<String, FormatterError> {
    let ExtractedDisclosures {
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

fn format_payload(credentials: &[PresentationCredential]) -> VP {
    VP {
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

fn extract_disclosures(token: &str) -> Result<ExtractedDisclosures, FormatterError> {
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

    Ok(ExtractedDisclosures {
        jwt,
        deserialized_disclosures: deserialized_claims,
    })
}

fn decompose_token<Claims: Serialize + DeserializeOwned>(
    token: &str,
) -> Result<DecomposedToken<Claims>, FormatterError> {
    let ExtractedDisclosures {
        jwt,
        deserialized_disclosures,
    } = extract_disclosures(token)?;

    let jwt_parts: Vec<&str> = jwt.split('.').collect();

    let header_decoded = Base64UrlSafeNoPadding::decode_to_vec(
        jwt_parts
            .first()
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "Missing token part".to_owned(),
            ))?,
        None,
    )
    .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

    let header: JWTHeader = serde_json::from_slice(&header_decoded)
        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

    let payload_decoded = Base64UrlSafeNoPadding::decode_to_vec(
        jwt_parts
            .get(1)
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "Missing token part".to_owned(),
            ))?,
        None,
    )
    .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

    let payload: JWTPayload<Claims> = serde_json::from_slice(&payload_decoded)
        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

    let signature = Base64UrlSafeNoPadding::decode_to_vec(
        jwt_parts
            .get(2)
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "Missing token part".to_owned(),
            ))?,
        None,
    )
    .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

    Ok(DecomposedToken {
        header,
        header_json: json_from_decoded(header_decoded)?,
        payload,
        payload_json: json_from_decoded(payload_decoded)?,
        signature,
        disclosures: deserialized_disclosures,
    })
}

fn prepare_jwt<Claims>(
    algorithm: &str,
    now: OffsetDateTime,
    issuer_did: &str,
    holder_did: &str,
    jwt_id: String,
    valid_for: Duration,
    payload: Claims,
) -> (JWTHeader, JWTPayload<Claims>) {
    let header = JWTHeader {
        algorithm: algorithm.to_owned(),
        signature_type: Some("SDJWT".to_owned()),
        ..Default::default()
    };

    let payload = JWTPayload {
        issued_at: Some(now),
        expires_at: Some(now + valid_for),
        invalid_before: Some(now - Duration::seconds(30)),
        issuer: Some(issuer_did.to_owned()),
        subject: Some(holder_did.to_owned()),
        jwt_id: Some(jwt_id),
        hash_alg: Some("sha-256".to_owned()),
        custom: payload,
        nonce: None,
    };
    (header, payload)
}
