use std::sync::Arc;

use crate::{
    crypto::{hasher::Hasher, Crypto},
    provider::credential_formatter::{
        jwt::mapper::string_to_b64url_string, CredentialStatus, FormatterError,
    },
    service::credential::dto::DetailCredentialClaimResponseDTO,
};

use super::models::{SDCredentialSubject, Sdvc, VCContent};

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
    hasher: &Arc<dyn Hasher + Send + Sync>,
    claims: &[String],
    credential_status: Option<CredentialStatus>,
    additional_context: Vec<String>,
    additional_types: Vec<String>,
    algorithm: &str,
) -> Sdvc {
    let mut hashed_claims: Vec<String> = claims
        .iter()
        .filter_map(|claim_string| hasher.hash_base64(claim_string.as_bytes()).ok())
        .collect();

    hashed_claims.sort_unstable();

    let context = vec!["https://www.w3.org/2018/credentials/v1".to_owned()]
        .into_iter()
        .chain(additional_context)
        .collect();

    let types = vec!["VerifiableCredential".to_owned()]
        .into_iter()
        .chain(additional_types)
        .collect();

    Sdvc {
        vc: VCContent {
            context,
            r#type: types,
            credential_subject: SDCredentialSubject {
                claims: hashed_claims,
            },
            credential_status,
        },
        hash_alg: Some(algorithm.to_owned()),
    }
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