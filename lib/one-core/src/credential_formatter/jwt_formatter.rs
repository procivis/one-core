use std::collections::HashMap;

use crate::service::credential::dto::CredentialDetailResponseDTO;
use jwt_simple::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    CredentialFormatter, CredentialPresentation, CredentialSubject, DetailCredential,
    FormatterError, PresentationCredential, VCCredentialClaimSchemaResponse,
    VCCredentialSchemaResponse,
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
    let private =
        Base64::decode_to_vec("cHl197m5y0cTmdvl8M1jZhWEw+S8btcEQ+pI8grCadw=", None).unwrap();
    let public =
        Base64::decode_to_vec("rTa2X5z9tCT9eVFG0yKDR5w4k89fwHohWxcd1I2LDsQ=", None).unwrap();

    Ed25519KeyPair::from_bytes(&private.into_iter().chain(public).collect::<Vec<u8>>()).unwrap()
}

impl CredentialFormatter for JWTFormatter {
    fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO, // Todo define input/output format
        holder_did: &str,
        _algorithm: &str,
    ) -> Result<String, FormatterError> {
        let key = get_temp_keys();
        let custom_claims: VC = credential.into();

        let claims = Claims::with_custom_claims(custom_claims, Duration::from_days(365 * 2))
            // FIXME Issuer did should probably not be optional.
            .with_issuer(
                credential
                    .issuer_did
                    .as_ref()
                    .unwrap_or(&"NOT PROVIDED".to_owned()),
            )
            .with_jwt_id(credential.id.to_owned())
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
        credentials: &[PresentationCredential],
        holder_did: &str,
        _algorithm: &str,
    ) -> Result<String, FormatterError> {
        let key = get_temp_keys();

        // We should explicitly confirm that claims are identical that the claims provided in the token as JWT
        // does not allow to limit number of disclosures.
        let custom_claims: VP = format_payload(credentials);

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
impl From<&CredentialDetailResponseDTO> for VC {
    fn from(value: &CredentialDetailResponseDTO) -> Self {
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
                        id: value.schema.id.to_string(),
                        claims: value
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
        }
    }
}

fn format_payload(credentials: &[PresentationCredential]) -> VP {
    VP {
        vp: VPContent {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
            r#type: vec!["VerifiablePresentation".to_owned()],
            verifiable_credential: credentials.iter().map(|fc| fc.token.clone()).collect(),
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
