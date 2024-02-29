use std::{collections::HashMap, sync::Arc};

use convert_case::{Case, Casing};
use serde::Serialize;
use shared_types::DidValue;
use sophia_api::{quad::Spog, source::QuadSource, term::SimpleTerm};
use sophia_c14n::rdfc10;
use sophia_jsonld::{
    loader::HttpLoader, loader_factory::DefaultLoaderFactory, JsonLdOptions, JsonLdParser,
};
use time::OffsetDateTime;

use crate::{
    crypto::CryptoProvider, provider::did_method::dto::DidDocumentDTO,
    service::credential::dto::CredentialDetailResponseDTO,
};

use self::model::{Claims, LdCredential, LdCredentialSubject, LdPresentation, LdProof};

use super::{
    error::FormatterError, model::CredentialStatus, AuthenticationFn, Context, VerificationFn,
};

pub mod model;

#[cfg(test)]
mod test;

type LdDataset = std::collections::HashSet<Spog<SimpleTerm<'static>>>;

pub(super) fn prepare_credential(
    base_url: &Option<String>,
    credential: &CredentialDetailResponseDTO,
    credential_status: Option<CredentialStatus>,
    holder_did: &DidValue,
    issuer_did: &DidValue,
    additional_context: Vec<String>,
    additional_types: Vec<String>,
) -> LdCredential {
    let issuance_date = OffsetDateTime::now_utc();

    let mut context = prepare_context(additional_context);

    if let Some(url) = &base_url {
        context.push(format!("{}/ssi/context/v1/{}", url, credential.schema.id));
    }

    let ld_type = prepare_credential_type(credential, additional_types);

    let id = format!("urn:uuid:{}", credential.id);

    let credential_subject = prepare_credential_subject(credential, holder_did);

    LdCredential {
        context,
        id,
        r#type: ld_type,
        issuer: issuer_did.clone(),
        issuance_date,
        credential_subject,
        credential_status,
        proof: None,
    }
}

pub fn get_crypto_suite(json_ld_str: &str) -> Option<String> {
    match serde_json::from_str::<LdCredential>(json_ld_str) {
        Ok(json_ld) => json_ld.proof.map(|proof| proof.cryptosuite),
        Err(_) => None,
    }
}

pub(super) async fn prepare_proof_config(
    proof_purpose: &str,
    cryptosuite: &str,
    context: Vec<String>,
    did_document: &DidDocumentDTO,
) -> Result<LdProof, FormatterError> {
    let r#type = "DataIntegrityProof".to_owned();

    // We take first key as we don't have a way to select other one.
    let key_id = did_document
        .assertion_method
        .as_ref()
        .ok_or(FormatterError::CouldNotFormat(
            "Missing assertion method id".to_owned(),
        ))?
        .first()
        .ok_or(FormatterError::CouldNotFormat(
            "Missing assertion method".to_owned(),
        ))?
        .clone();

    Ok(LdProof {
        context,
        r#type,
        created: OffsetDateTime::now_utc(),
        cryptosuite: cryptosuite.to_owned(),
        verification_method: key_id,
        proof_purpose: proof_purpose.to_owned(),
        proof_value: None,
        nonce: None,
        challenge: None,
        domain: None,
    })
}

pub(super) fn prepare_context(additional_context: Vec<String>) -> Vec<String> {
    let mut context = vec![
        Context::CredentialsV1.to_string(),
        Context::DataIntegrityV2.to_string(),
    ];

    context.extend(additional_context);
    context
}

pub(super) fn prepare_credential_type(
    credential: &CredentialDetailResponseDTO,
    additional_types: Vec<String>,
) -> Vec<String> {
    let pascal_schema_name = credential.schema.name.to_case(Case::Pascal);

    let mut types = vec![
        "VerifiableCredential".to_string(),
        format!("{}Subject", pascal_schema_name),
    ];

    types.extend(additional_types);

    types
}

pub(super) fn prepare_credential_subject(
    credential: &CredentialDetailResponseDTO,
    holder_did: &DidValue,
) -> LdCredentialSubject {
    let pascal_schema_name = credential.schema.name.to_case(Case::Pascal);
    let claims: Claims = credential
        .claims
        .iter()
        .map(|claim| (claim.schema.key.clone(), claim.value.clone()))
        .collect();

    let mut subject = HashMap::new();
    subject.insert(format!("{}Subject", pascal_schema_name), claims);

    LdCredentialSubject {
        id: holder_did.clone(),
        subject,
    }
}

pub(super) async fn prepare_proof_hash<T>(
    object: &T,
    crypto: &Arc<dyn CryptoProvider>,
    proof: &LdProof,
) -> Result<Vec<u8>, FormatterError>
where
    T: Serialize,
{
    let transformed_document = canonize_any(object).await?;

    let transformed_proof_config = canonize_any(proof).await?;

    let hashing_function = "sha-256";
    let hasher = crypto.get_hasher(hashing_function).map_err(|_| {
        FormatterError::CouldNotFormat(format!("Hasher {} unavailable", hashing_function))
    })?;

    let transformed_document_hash = hasher
        .hash(transformed_document.as_bytes())
        .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

    let mut transformed_proof_config_hash = hasher
        .hash(transformed_proof_config.as_bytes())
        .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

    transformed_proof_config_hash.extend(transformed_document_hash);
    Ok(transformed_proof_config_hash)
}

pub(super) async fn sign_proof_hash(
    proof_hash: &[u8],
    auth_fn: AuthenticationFn,
) -> Result<String, FormatterError> {
    let signature = auth_fn
        .sign(proof_hash)
        .await
        .map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

    Ok(bs58::encode(signature).into_string())
}

pub(super) async fn verify_proof_signature(
    proof_hash: &[u8],
    proof_value_bs58: &str,
    issuer_did: &DidValue,
    key_id: &str,
    cryptosuite: &str,
    verification_fn: VerificationFn,
) -> Result<(), FormatterError> {
    let signature = bs58::decode(proof_value_bs58)
        .into_vec()
        .map_err(|_| FormatterError::CouldNotVerify("Hash decoding error".to_owned()))?;

    let algorithm = match cryptosuite {
        "eddsa-rdfc-2022" => "EDDSA",
        "ecdsa-rdfc-2019" => "ES256",
        _ => {
            return Err(FormatterError::CouldNotVerify(format!(
                "Unsupported cryptosuite: {cryptosuite}"
            )))
        }
    };

    verification_fn
        .verify(
            Some(issuer_did.clone()),
            Some(key_id),
            algorithm,
            proof_hash,
            &signature,
        )
        .await
        .map_err(|_| FormatterError::CouldNotVerify("Verification error".to_string()))?;

    Ok(())
}

pub(super) async fn canonize_any<T>(json_ld: &T) -> Result<String, FormatterError>
where
    T: Serialize,
{
    let content_str = serde_json::to_string(&json_ld)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

    let options: JsonLdOptions<DefaultLoaderFactory<HttpLoader>> = JsonLdOptions::default();

    let parser = JsonLdParser::new_with_options(options);

    // This will actually fetch context
    let parsed = parser.async_parse_str(&content_str).await;

    let dataset: LdDataset = parsed
        .collect_quads()
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

    canonize_dataset(dataset).await
}

pub(super) async fn canonize_dataset(dataset: LdDataset) -> Result<String, FormatterError> {
    let mut buf = Vec::<u8>::new();
    rdfc10::normalize(&dataset, &mut buf)
        .map_err(|e| FormatterError::CouldNotFormat(format!("Normalization error: `{}`", e)))?;

    let str = String::from_utf8_lossy(buf.as_slice());

    Ok(str.into_owned())
}

pub(super) async fn verify_credential_signature(
    mut ld_credential: LdCredential,
    verification_fn: VerificationFn,
    crypto: &Arc<dyn CryptoProvider>,
) -> Result<(), FormatterError> {
    let mut proof = ld_credential
        .proof
        .as_ref()
        .ok_or(FormatterError::CouldNotVerify("Missing proof".to_owned()))?
        .clone();
    let proof_value = proof.proof_value.ok_or(FormatterError::CouldNotVerify(
        "Missing proof_value".to_owned(),
    ))?;
    let key_id = proof.verification_method.as_str();
    let issuer_did = &ld_credential.issuer;

    // Remove proof value and proof for canonicalization
    proof.proof_value = None;
    ld_credential.proof = None;

    let proof_hash = prepare_proof_hash(&ld_credential, crypto, &proof).await?;
    verify_proof_signature(
        &proof_hash,
        &proof_value,
        issuer_did,
        key_id,
        &proof.cryptosuite,
        verification_fn,
    )
    .await?;

    Ok(())
}

pub(super) async fn verify_presentation_signature(
    mut presentation: LdPresentation,
    verification_fn: VerificationFn,
    crypto: &Arc<dyn CryptoProvider>,
) -> Result<(), FormatterError> {
    let mut proof = presentation
        .proof
        .as_ref()
        .ok_or(FormatterError::CouldNotVerify("Missing proof".to_owned()))?
        .clone();
    let proof_value = proof.proof_value.ok_or(FormatterError::CouldNotVerify(
        "Missing proof_value".to_owned(),
    ))?;
    let key_id = proof.verification_method.as_str();
    let issuer_did = &presentation.holder;

    // Remove proof value and proof for canonicalization
    proof.proof_value = None;
    presentation.proof = None;

    let proof_hash = prepare_proof_hash(&presentation, crypto, &proof).await?;
    verify_proof_signature(
        &proof_hash,
        &proof_value,
        issuer_did,
        key_id,
        &proof.cryptosuite,
        verification_fn,
    )
    .await?;

    Ok(())
}
