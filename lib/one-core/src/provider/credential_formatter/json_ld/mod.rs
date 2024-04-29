use std::collections::HashMap;
use std::sync::Arc;

use convert_case::{Case, Casing};
use serde::Serialize;
use shared_types::DidValue;
use sophia_api::{quad::Spog, source::QuadSource, term::SimpleTerm};
use sophia_c14n::rdfc10;
use sophia_jsonld::loader::NoLoader;
use sophia_jsonld::loader_factory::DefaultLoaderFactory;
use sophia_jsonld::{JsonLdOptions, JsonLdParser};
use time::OffsetDateTime;

use crate::provider::credential_formatter::common::nest_claims;
use crate::provider::credential_formatter::json_ld::caching_loader::CachingLoader;
use crate::{crypto::CryptoProvider, provider::did_method::dto::DidDocumentDTO};

use super::{error::FormatterError, AuthenticationFn, Context, CredentialData, VerificationFn};

use self::model::{LdCredential, LdCredentialSubject, LdPresentation, LdProof};

pub mod caching_loader;
pub mod model;

#[cfg(test)]
mod test;

type LdDataset = std::collections::HashSet<Spog<SimpleTerm<'static>>>;

pub(super) fn prepare_credential(
    credential: CredentialData,
    holder_did: &DidValue,
    additional_context: Vec<String>,
    additional_types: Vec<String>,
    json_ld_context_url: Option<String>,
    custom_subject_name: Option<String>,
) -> Result<LdCredential, FormatterError> {
    let credential_schema = &credential.schema;

    let issuance_date = OffsetDateTime::now_utc();

    let mut context = prepare_context(additional_context);
    if let Some(json_ld_context_url) = json_ld_context_url {
        context.push(json_ld_context_url);
    }

    if let Some(credential_schema_context) = &credential_schema.context {
        context.push(credential_schema_context.to_owned());
    }

    let ld_type = prepare_credential_type(&credential_schema.name, additional_types);

    let credential_subject = prepare_credential_subject(
        &credential_schema.name,
        credential.claims,
        holder_did,
        custom_subject_name,
    )?;

    Ok(LdCredential {
        context,
        id: credential.id,
        r#type: ld_type,
        issuer: credential.issuer_did,
        issuance_date,
        credential_subject,
        credential_status: credential.status,
        proof: None,
        credential_schema: credential.schema.into(),
    })
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
    credential_schema_name: &str,
    additional_types: Vec<String>,
) -> Vec<String> {
    let credential_schema_name = credential_schema_name.to_case(Case::Pascal);

    let mut types = vec![
        "VerifiableCredential".to_string(),
        format!("{}Subject", credential_schema_name),
    ];

    types.extend(additional_types);

    types
}

pub(super) fn prepare_credential_subject(
    credential_schema_name: &str,
    claims: Vec<(String, String)>,
    holder_did: &DidValue,
    custom_subject_name: Option<String>,
) -> Result<LdCredentialSubject, FormatterError> {
    let credential_schema_name = credential_schema_name.to_case(Case::Pascal);

    let subject_name_base = custom_subject_name.unwrap_or(credential_schema_name);

    Ok(LdCredentialSubject {
        id: holder_did.clone(),
        subject: HashMap::from([(
            format!("{subject_name_base}Subject"),
            serde_json::to_value(nest_claims(claims)?)
                .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?,
        )]),
    })
}

pub(super) async fn prepare_proof_hash<T>(
    object: &T,
    crypto: &Arc<dyn CryptoProvider>,
    proof: &LdProof,
    caching_loader: CachingLoader,
) -> Result<Vec<u8>, FormatterError>
where
    T: Serialize,
{
    let transformed_document = canonize_any(object, caching_loader.clone()).await?;

    let transformed_proof_config = canonize_any(proof, caching_loader).await?;

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

pub(super) async fn canonize_any<T>(
    json_ld: &T,
    caching_loader: CachingLoader,
) -> Result<String, FormatterError>
where
    T: Serialize,
{
    let content_str = serde_json::to_string(&json_ld)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

    let options = JsonLdOptions::<DefaultLoaderFactory<NoLoader>>::default()
        .with_document_loader(caching_loader);

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
    caching_loader: CachingLoader,
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

    let proof_hash = prepare_proof_hash(&ld_credential, crypto, &proof, caching_loader).await?;
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
    caching_loader: CachingLoader,
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

    let proof_hash = prepare_proof_hash(&presentation, crypto, &proof, caching_loader).await?;
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
