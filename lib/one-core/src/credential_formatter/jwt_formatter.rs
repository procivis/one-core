use std::collections::HashMap;

use crate::repository::data_provider::DetailCredentialResponse;

use base64::{engine::general_purpose, Engine};
use jwt_simple::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    CredentialFormatter, CredentialPresentation, CredentialSubject, DetailCredential,
    FormatterError, VCCredentialClaimSchemaResponse, VCCredentialSchemaResponse,
};

pub struct JWTFormatter {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub r#type: Vec<String>,
    pub credential_subject: CredentialSubject,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VPContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub verifiable_credential: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VC {
    pub vc: VCContent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VP {
    pub vp: VPContent,
}

#[derive(Debug, Serialize, Deserialize)]
struct PresentationMeta {
    iss: String,
}

fn get_temp_keys() -> Ed25519KeyPair {
    // Until we have a proper key handling we use static keys.
    let private = general_purpose::STANDARD
        .decode("cHl197m5y0cTmdvl8M1jZhWEw+S8btcEQ+pI8grCadw=")
        .unwrap();
    let public = general_purpose::STANDARD
        .decode("rTa2X5z9tCT9eVFG0yKDR5w4k89fwHohWxcd1I2LDsQ=")
        .unwrap();

    Ed25519KeyPair::from_bytes(
        &private
            .into_iter()
            .chain(public.into_iter())
            .collect::<Vec<u8>>(),
    )
    .unwrap()
}

impl CredentialFormatter for JWTFormatter {
    fn format_credentials(
        &self,
        credentials: &DetailCredentialResponse, // Todo define input/output format
        holder_did: &str,
    ) -> Result<String, FormatterError> {
        let key = get_temp_keys();
        let custom_claims: VC = credentials.into();

        let claims = Claims::with_custom_claims(custom_claims, Duration::from_days(365 * 2))
            // FIXME Issuer did should probably not be optional.
            .with_issuer(
                credentials
                    .issuer_did
                    .as_ref()
                    .unwrap_or(&"NOT PROVIDED".to_owned()),
            )
            .with_jwt_id(credentials.id.to_owned())
            .with_subject(holder_did);

        // This should be put to a signer
        // although in this case this is also responsible for building and formatting.
        let token = key
            .sign(claims)
            .map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

        Ok(token)
    }

    fn extract_credentials(&self, credentials: &str) -> Result<DetailCredential, FormatterError> {
        let pair = get_temp_keys();
        let pubkey = pair.public_key();

        let claims = pubkey
            .verify_token::<VC>(credentials, None)
            .map_err(|e| FormatterError::Failed(e.to_string()))?;

        Ok(claims.into())
    }

    fn format_presentation(
        &self,
        credentials: &[String],
        holder_did: &str,
    ) -> Result<String, FormatterError> {
        let key = get_temp_keys();
        let custom_claims: VP = format_presentation(credentials);

        let claims = Claims::with_custom_claims(custom_claims, Duration::from_mins(5))
            .with_issuer(holder_did)
            .with_jwt_id(Uuid::new_v4().to_string());

        // This should be put to a signer
        // although in this case this is also responsible for building and formatting.
        let token = key
            .sign(claims)
            .map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

        Ok(token)
    }

    fn extract_presentation(
        &self,
        presentation: &str,
    ) -> Result<CredentialPresentation, FormatterError> {
        let keys = get_temp_keys();
        let pubkey = keys.public_key();

        let claims = pubkey
            .verify_token::<VP>(presentation, None)
            .map_err(|e| FormatterError::Failed(e.to_string()))?;

        Ok(claims.into())
    }
}

// Format credentials
impl From<&DetailCredentialResponse> for VC {
    fn from(value: &DetailCredentialResponse) -> Self {
        let claims: HashMap<String, String> = value
            .claims
            .iter()
            .map(|c| (c.schema.key.clone(), c.value.clone()))
            .collect();

        Self {
            vc: VCContent {
                context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
                r#type: vec!["VerifiableCredential".to_owned()],
                credential_subject: CredentialSubject {
                    values: claims,
                    one_credential_schema: VCCredentialSchemaResponse {
                        name: value.schema.name.clone(),
                        id: value.schema.id.clone(),
                        claims: value
                            .claims
                            .iter()
                            .map(|claim| VCCredentialClaimSchemaResponse {
                                key: claim.schema.key.clone(),
                                id: claim.schema.id.clone(),
                                datatype: claim.schema.datatype.to_owned(),
                            })
                            .collect(),
                    },
                },
            },
        }
    }
}

fn format_presentation(credentials: &[String]) -> VP {
    VP {
        vp: VPContent {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
            r#type: vec!["VerifiablePresentation".to_owned()],
            verifiable_credential: credentials.to_owned(),
        },
    }
}

impl From<JWTClaims<VC>> for DetailCredential {
    fn from(value: JWTClaims<VC>) -> Self {
        Self {
            id: value.jwt_id,
            issued_at: value.issued_at.and_then(|timestamp| {
                OffsetDateTime::from_unix_timestamp_nanos(timestamp.as_nanos() as i128).ok()
            }),
            expires_at: value.expires_at.and_then(|timestamp| {
                OffsetDateTime::from_unix_timestamp_nanos(timestamp.as_nanos() as i128).ok()
            }),
            invalid_before: value.invalid_before.and_then(|timestamp| {
                OffsetDateTime::from_unix_timestamp_nanos(timestamp.as_nanos() as i128).ok()
            }),
            issuer_did: value.issuer,
            subject: value.subject,
            claims: value.custom.vc.credential_subject,
        }
    }
}

impl From<JWTClaims<VP>> for CredentialPresentation {
    fn from(value: JWTClaims<VP>) -> Self {
        Self {
            id: value.jwt_id,
            issued_at: value.issued_at.and_then(|timestamp| {
                OffsetDateTime::from_unix_timestamp_nanos(timestamp.as_nanos() as i128).ok()
            }),
            expires_at: value.expires_at.and_then(|timestamp| {
                OffsetDateTime::from_unix_timestamp_nanos(timestamp.as_nanos() as i128).ok()
            }),
            issuer_did: value.issuer,
            credentials: value.custom.vp.verifiable_credential,
        }
    }
}
