use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde::Serialize;

use crate::{
    credential_formatter::{
        FormatterError, VCCredentialClaimSchemaResponse, VCCredentialSchemaResponse,
    },
    crypto::{hasher::Hasher, signer::Signer, Crypto},
    service::credential::dto::{CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO},
};

use super::{
    get_temp_keys,
    models::{JWTHeader, JWTPayload, SDCredentialSubject, VCContent, VC},
};

pub(super) fn json_from_decoded(decoded: Vec<u8>) -> Result<String, FormatterError> {
    let result = String::from_utf8(decoded)
        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;
    Ok(result)
}

pub(super) fn claims_to_formatted_disclosure(
    claims: &[DetailCredentialClaimResponseDTO],
) -> Vec<String> {
    claims
        .iter()
        .filter_map(|c| {
            serde_json::to_string(&vec![
                Crypto::generate_salt_base64(),
                c.schema.key.clone(),
                c.value.clone(),
            ])
            .ok()
        })
        .collect()
}

pub(super) fn vc_from_credential(
    claims: &[String],
    credential: &CredentialDetailResponseDTO,
    hasher: &Arc<dyn Hasher + Send + Sync>,
) -> VC {
    let mut hashed_claims: Vec<String> = claims
        .iter()
        .filter_map(|claim_string| hasher.hash_base64(claim_string.as_bytes()).ok())
        .collect();

    hashed_claims.sort_unstable();

    VC {
        vc: VCContent {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
            r#type: vec!["VerifiableCredential".to_owned()],
            credential_subject: SDCredentialSubject {
                claims: hashed_claims,
                one_credential_schema: VCCredentialSchemaResponse {
                    name: credential.schema.name.clone(),
                    id: credential.schema.id.to_string(),
                    claims: credential
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

pub(super) fn bin_to_b64url_string(bin: &[u8]) -> Result<String, FormatterError> {
    Base64UrlSafeNoPadding::encode_to_string(bin)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))
}

pub(super) fn string_to_b64url_string(string: &str) -> Result<String, FormatterError> {
    Base64UrlSafeNoPadding::encode_to_string(string)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))
}

pub(super) fn tokenize_claims(disclosures: Vec<String>) -> Result<String, FormatterError> {
    let mut token = String::new();

    for disclosure in disclosures {
        token.push('~');
        let b64 = string_to_b64url_string(&disclosure)?;
        token.push_str(&b64);
    }

    Ok(token)
}

pub(super) fn tokenize_jwt<CustomClaims: Serialize>(
    signer: &Arc<dyn Signer + Send + Sync>,
    header: JWTHeader,
    payload: JWTPayload<CustomClaims>,
) -> Result<String, FormatterError> {
    let jwt_header_json = serde_json::to_string(&header)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;
    let mut token = format!(
        "{}.{}",
        string_to_b64url_string(&jwt_header_json)?,
        string_to_b64url_string(&payload_json)?,
    );

    let (private, public) = get_temp_keys();

    let signature = signer.sign(
        &token,
        &private
            .into_iter()
            .chain(public.into_iter())
            .collect::<Vec<u8>>(),
    )?;

    let signature = bin_to_b64url_string(&signature)?;

    token.push('.');
    token.push_str(&signature);

    Ok(token)
}
