// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::collections::HashMap;

use crate::credential_formatter::sdjwt::mapper::json_from_decoded;
use crate::credential_formatter::sdjwt::models::{
    DecomposedToken, Disclosure, JWTHeader, JWTPayload, VC,
};
use crate::credential_formatter::CredentialSubject;
use crate::crypto::Crypto;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::de::DeserializeOwned;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

mod mapper;
mod models;

use self::models::{SDCredentialSubject, VCContent};

use super::{
    CredentialFormatter, CredentialPresentation, DetailCredential, FormatterError,
    VCCredentialClaimSchemaResponse, VCCredentialSchemaResponse,
};

pub struct SDJWTFormatter {
    pub crypto: Crypto,
}

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
        holder_did: &str,
        algorithm: &str,
    ) -> Result<String, FormatterError> {
        let (vc, disclosures) = self.format_hashed_credentials(credential, "sha-256")?;

        let now = OffsetDateTime::now_utc();

        let header = JWTHeader {
            algorithm: algorithm.to_owned(),
            signature_type: Some("SDJWT".to_owned()),
            ..Default::default()
        };

        let payload = JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + time::Duration::days(365 * 2)),
            invalid_before: Some(now - Duration::seconds(30)),
            issuer: Some(
                credential
                    .issuer_did
                    .as_ref()
                    .unwrap_or(&"NOT PROVIDED".to_owned())
                    .to_owned(),
            ),
            subject: Some(holder_did.to_owned()),
            jwt_id: Some(credential.id.to_string()),
            hash_alg: Some("sha-256".to_owned()),
            custom: vc,
            nonce: None,
        };

        let mut token = self.tokenize_jwt(header, payload, algorithm)?;

        let disclosures_token = self.tokenize_claims(disclosures)?;

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
            disclosures_decoded,
        } = self.decompose_token::<VC>(token)?;

        self.verify_signature(&header_json, &payload_json, &signature, &header.algorithm)?;

        let disclosures_len = disclosures_decoded.len();

        let hasher = self
            .crypto
            .hashers
            .get(&payload.hash_alg.unwrap_or("sha-256".to_string()))
            .ok_or(FormatterError::MissingHasher)?;

        //Verify if all claims are correct
        if !disclosures_decoded.iter().all(|disclosure| {
            payload.custom.vc.credential_subject.claims.contains(
                &hasher
                    .hash_base64(disclosure.as_bytes())
                    .unwrap_or_default(),
            )
        }) {
            return Err(FormatterError::MissingDisclosure);
        }

        let deserialized_claims: Vec<(Disclosure, String)> = disclosures_decoded
            .into_iter()
            .filter_map(|disclosure_str| {
                serde_json::from_str(&disclosure_str)
                    .ok()
                    .map(|disclosure| (disclosure, disclosure_str))
            })
            .collect();

        if deserialized_claims.len() != disclosures_len {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Missing disclosure".to_owned(),
            ));
        }

        Ok(DetailCredential {
            id: payload.jwt_id,
            issued_at: payload.issued_at,
            expires_at: payload.expires_at,
            invalid_before: payload.invalid_before,
            issuer_did: payload.issuer,
            subject: payload.subject,
            claims: CredentialSubject {
                values: HashMap::from_iter(
                    deserialized_claims
                        .into_iter()
                        .map(|(dis, _)| (dis.attribute, dis.value)),
                ),
                one_credential_schema: payload.custom.vc.credential_subject.one_credential_schema,
            },
        })
    }

    fn format_presentation(
        &self,
        _credentials: &[String],
        _holder_did: &str,
    ) -> Result<String, FormatterError> {
        unimplemented!()
    }

    fn extract_presentation(
        &self,
        _presentation: &str,
    ) -> Result<CredentialPresentation, FormatterError> {
        unimplemented!()
    }
}

impl SDJWTFormatter {
    // Format credentials
    fn format_hashed_credentials(
        &self,
        credentials: &CredentialDetailResponseDTO,
        algorithm: &str,
    ) -> Result<(VC, Vec<String>), FormatterError> {
        let hasher = self
            .crypto
            .hashers
            .get(algorithm)
            .ok_or(FormatterError::MissingHasher)?;

        let claims: Vec<String> = credentials
            .claims
            .iter()
            .filter_map(|c| {
                serde_json::to_string(&Disclosure {
                    salt: Crypto::generate_salt_base64(),
                    attribute: c.schema.key.clone(),
                    value: c.value.clone(),
                })
                .ok()
            })
            .collect();

        let mut hashed_claims: Vec<String> = claims
            .iter()
            .filter_map(|claim_string| hasher.hash_base64(claim_string.as_bytes()).ok())
            .collect();

        hashed_claims.sort_unstable();

        let vc = VC {
            vc: VCContent {
                context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
                r#type: vec!["VerifiableCredential".to_owned()],
                credential_subject: SDCredentialSubject {
                    claims: hashed_claims,
                    one_credential_schema: VCCredentialSchemaResponse {
                        name: credentials.schema.name.clone(),
                        id: credentials.schema.id.to_string(),
                        claims: credentials
                            .claims
                            .iter()
                            .map(|claim| VCCredentialClaimSchemaResponse {
                                key: claim.schema.key.clone(),
                                id: claim.schema.id.to_string(),
                                datatype: claim.schema.datatype.to_owned(),
                                required: claim.schema.required,
                            })
                            .collect(),
                    },
                },
            },
        };

        Ok((vc, claims))
    }

    fn tokenize_jwt<CustomClaims: Serialize>(
        &self,
        header: JWTHeader,
        payload: JWTPayload<CustomClaims>,
        signature_algorithm: &str,
    ) -> Result<String, FormatterError> {
        let signer = self
            .crypto
            .signers
            .get(signature_algorithm)
            .ok_or(FormatterError::MissingSigner)?;

        let jwt_header_json = serde_json::to_string(&header)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;
        let claims_json = serde_json::to_string(&payload)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;
        let mut token = format!(
            "{}.{}",
            Base64UrlSafeNoPadding::encode_to_string(jwt_header_json)
                .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?,
            Base64UrlSafeNoPadding::encode_to_string(claims_json)
                .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?,
        );

        let (private, public) = get_temp_keys();

        let signature = signer.sign(
            &token,
            &private
                .into_iter()
                .chain(public.into_iter())
                .collect::<Vec<u8>>(),
        )?;

        let signature = Base64UrlSafeNoPadding::encode_to_string(signature)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        token.push('.');
        token.push_str(&signature);

        Ok(token)
    }

    fn tokenize_claims(&self, disclosures: Vec<String>) -> Result<String, FormatterError> {
        let mut token = String::new();

        for disclosure in disclosures {
            token.push('~');
            token.push_str(
                &Base64UrlSafeNoPadding::encode_to_string(disclosure)
                    .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?,
            );
        }

        Ok(token)
    }

    fn verify_signature(
        &self,
        header_json: &str,
        payload_json: &str,
        signature: &[u8],
        signature_algorithm: &str,
    ) -> Result<(), FormatterError> {
        let signer = self
            .crypto
            .signers
            .get(signature_algorithm)
            .ok_or(FormatterError::MissingSigner)?;

        let (_, public) = get_temp_keys();

        let jwt = format!(
            "{}.{}",
            Base64UrlSafeNoPadding::encode_to_string(header_json)
                .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?,
            Base64UrlSafeNoPadding::encode_to_string(payload_json)
                .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?,
        );

        signer.verify(&jwt, signature, &public)?;
        Ok(())
    }

    fn decompose_token<Claims: Serialize + DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<DecomposedToken<Claims>, FormatterError> {
        let mut token_parts = token.split('~');
        let jwt = token_parts.next().ok_or(FormatterError::MissingPart)?;

        let disclosures_decoded = token_parts
            .filter_map(|disclosure_encoded| {
                let bytes = Base64UrlSafeNoPadding::decode_to_vec(disclosure_encoded, None).ok()?;

                String::from_utf8(bytes).ok()
            })
            .collect();

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
            disclosures_decoded,
        })
    }
}
