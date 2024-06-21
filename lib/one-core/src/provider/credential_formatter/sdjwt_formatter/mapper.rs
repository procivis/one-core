use std::sync::Arc;

use crate::{
    crypto::{hasher::Hasher, CryptoProvider},
    provider::credential_formatter::{
        jwt::mapper::string_to_b64url_string, Context, CredentialData, FormatterError,
        PublishedClaim,
    },
};

use super::model::{SDCredentialSubject, Sdvc, VCContent};

pub(super) fn claims_to_formatted_disclosure(
    claims: &[PublishedClaim],
    crypto: &Arc<dyn CryptoProvider>,
) -> Vec<String> {
    claims
        .iter()
        .filter_map(|claim| {
            let salt = crypto.generate_salt_base64();
            serde_json::to_string(&[&salt, &claim.key, &claim.value]).ok()
        })
        .collect()
}

pub(super) fn vc_from_credential(
    credential: CredentialData,
    hasher: &Arc<dyn Hasher>,
    claims: &[String],
    additional_context: Vec<String>,
    additional_types: Vec<String>,
    algorithm: &str,
) -> Sdvc {
    let mut hashed_claims: Vec<String> = claims
        .iter()
        .filter_map(|claim_string| hasher.hash_base64(claim_string.as_bytes()).ok())
        .collect();

    hashed_claims.sort_unstable();

    let context = vec![Context::CredentialsV1.to_string()]
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
            id: Some(credential.id),
            credential_subject: SDCredentialSubject {
                claims: hashed_claims,
            },
            credential_status: credential.status,
            credential_schema: credential.schema.into(),
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
