use std::collections::HashMap;

use crate::data_layer::data_model::{Datatype, DetailCredentialResponse};

use base64::{engine::general_purpose, Engine};
use jwt_simple::prelude::*;

use super::{CredentialFormatter, FormatterError};

pub struct JWTFormatter {}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialClaimSchemaResponse {
    key: String,
    id: String,
    datatype: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialSchemaResponse {
    name: String,
    id: String,
    claims: Vec<VCCredentialClaimSchemaResponse>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(flatten)]
    values: HashMap<String, String>,
    one_credential_schema: VCCredentialSchemaResponse,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VCContent {
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "type")]
    _type: Vec<String>,
    credential_subject: CredentialSubject,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VC {
    vc: VCContent,
}

impl CredentialFormatter for JWTFormatter {
    fn format(
        &self,
        credentials: &DetailCredentialResponse,
        holder_did: &str,
    ) -> Result<String, FormatterError> {
        // Until we have a proper key handling we use static keys.
        let private = general_purpose::STANDARD
            .decode("cHl197m5y0cTmdvl8M1jZhWEw+S8btcEQ+pI8grCadw=")
            .unwrap();
        let public = general_purpose::STANDARD
            .decode("rTa2X5z9tCT9eVFG0yKDR5w4k89fwHohWxcd1I2LDsQ=")
            .unwrap();

        let key = Ed25519KeyPair::from_bytes(
            &private
                .into_iter()
                .chain(public.clone().into_iter())
                .collect::<Vec<u8>>(),
        )
        .unwrap();

        let custom_claims: VC = credentials.into();

        let claims = Claims::with_custom_claims(custom_claims, Duration::from_days(365 * 2))
            .with_issuer(credentials.issuer_did.clone().unwrap())
            // Issuer did should probably not be optional.
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

        let pubkey = Ed25519PublicKey::from_bytes(&public).unwrap();
        pubkey.verify_token::<VC>(&token, None).unwrap();

        Ok(token)
    }
}

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
                _type: vec!["VerifiableCredential".to_owned()],
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
                                datatype: match claim.schema.datatype {
                                    Datatype::String => "STRING".to_owned(),
                                    Datatype::Date => "DATE".to_owned(),
                                    Datatype::Number => "NUMBER".to_owned(),
                                },
                            })
                            .collect(),
                    },
                },
            },
        }
    }
}
