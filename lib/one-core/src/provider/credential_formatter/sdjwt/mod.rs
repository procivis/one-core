use itertools::Itertools;
use one_crypto::CryptoProvider;
use shared_types::DidValue;
use time::Duration;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::jwt::model::{DecomposedToken, JWTPayload};
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, CredentialSubject, DetailCredential,
    VerificationFn,
};
use crate::provider::credential_formatter::sdjwt::disclosures::{
    extract_claims_from_disclosures, extract_disclosures, gather_disclosures,
    get_disclosures_by_claim_name, sort_published_claims_by_indices, to_hashmap,
};
use crate::provider::credential_formatter::sdjwt::mapper::{
    nest_claims_to_json, tokenize_claims, unpack_arrays, vc_from_credential,
};
use crate::provider::credential_formatter::sdjwt::model::{Disclosure, Sdvc};
use crate::provider::credential_formatter::sdjwt::verifier::verify_claims;

pub mod disclosures;
pub mod mapper;
pub mod model;
pub mod verifier;

#[cfg(test)]
pub mod test;

pub(crate) enum SdJwtType {
    SdJwt,
    SdJwtVc,
}

pub(crate) fn detect_sdjwt_type_from_token(token: &str) -> Result<SdJwtType, FormatterError> {
    let without_claims = match token.split_once('~') {
        None => token,
        Some((without_claims, _)) => without_claims,
    };
    let jwt: DecomposedToken<Sdvc> = Jwt::decompose_token(without_claims)?;

    if jwt.payload.vc_type.is_some() {
        Ok(SdJwtType::SdJwtVc)
    } else {
        Ok(SdJwtType::SdJwt)
    }
}

pub(crate) fn prepare_sd_presentation(
    presentation: CredentialPresentation,
    crypto: &dyn CryptoProvider,
) -> Result<String, FormatterError> {
    let model::DecomposedToken {
        jwt,
        deserialized_disclosures,
    } = extract_disclosures(&presentation.token)?;

    let decomposed_jwt: DecomposedToken<Sdvc> = Jwt::decompose_token(jwt)?;
    let algorithm = decomposed_jwt
        .payload
        .custom
        .hash_alg
        .unwrap_or("sha-256".to_string());
    let hasher = crypto
        .get_hasher(&algorithm)
        .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;

    let disclosures = presentation
        .disclosed_keys
        .iter()
        .map(|key| get_disclosures_by_claim_name(key, &deserialized_disclosures, &*hasher))
        .collect::<Result<Vec<Vec<Disclosure>>, FormatterError>>()?
        .into_iter()
        .flatten()
        .map(|disclosure| disclosure.base64_encoded_disclosure)
        .unique()
        .collect::<Vec<String>>();

    let mut token = jwt.to_owned();
    for disclosure in disclosures {
        token.push('~');
        token.push_str(&disclosure);
    }

    Ok(token)
}

pub(super) async fn extract_credentials_internal(
    token: &str,
    verification: Option<VerificationFn>,
    crypto: &dyn CryptoProvider,
) -> Result<DetailCredential, FormatterError> {
    let model::DecomposedToken {
        deserialized_disclosures,
        jwt,
    } = extract_disclosures(token)?;

    let jwt: Jwt<Sdvc> = Jwt::build_from_token(jwt, verification).await?;

    let hasher =
        crypto.get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

    verify_claims(
        &jwt.payload.custom.vc.credential_subject.claims,
        &deserialized_disclosures,
        &*hasher,
    )?;

    let claims = extract_claims_from_disclosures(&deserialized_disclosures, &*hasher)?;

    Ok(DetailCredential {
        id: jwt.payload.jwt_id,
        valid_from: jwt.payload.issued_at,
        valid_until: jwt.payload.expires_at,
        update_at: None,
        invalid_before: jwt.payload.invalid_before,
        issuer_did: jwt.payload.issuer.map(DidValue::from),
        subject: jwt.payload.subject.map(DidValue::from),
        claims: CredentialSubject {
            values: to_hashmap(unpack_arrays(&claims)?)?,
        },
        status: jwt.payload.custom.vc.credential_status,
        credential_schema: jwt.payload.custom.vc.credential_schema,
    })
}

pub(super) fn format_hashed_credential(
    credential: CredentialData,
    algorithm: &str,
    additional_context: Vec<ContextType>,
    additional_types: Vec<String>,
    crypto: &dyn CryptoProvider,
    embed_layout_properties: bool,
) -> Result<(Sdvc, Vec<String>), FormatterError> {
    let nested = nest_claims_to_json(&sort_published_claims_by_indices(&credential.claims))?;
    let (disclosures, sd_section) = gather_disclosures(&nested, algorithm, crypto)?;

    let vc = vc_from_credential(
        credential,
        &sd_section,
        additional_context,
        additional_types,
        algorithm,
        embed_layout_properties,
    )?;

    Ok((vc, disclosures))
}

#[allow(clippy::too_many_arguments)]
pub async fn format_sdjwt_credentials(
    credential: CredentialData,
    holder_did: &Option<DidValue>,
    algorithm: &str,
    additional_context: Vec<ContextType>,
    additional_types: Vec<String>,
    auth_fn: AuthenticationFn,
    crypto: &dyn CryptoProvider,
    embed_layout_properties: bool,
    leeway: u64,
    token_type: String,
    vc_type: Option<String>,
) -> Result<String, FormatterError> {
    let issuer = credential.issuer_did.to_did_value().to_string();
    let id = credential.id.clone();
    let issued_at = credential.issuance_date;
    let expires_at = issued_at.checked_add(credential.valid_for);

    let (vc, disclosures) = format_hashed_credential(
        credential,
        "sha-256",
        additional_context,
        additional_types,
        crypto,
        embed_layout_properties,
    )?;

    let payload = JWTPayload {
        issued_at: Some(issued_at),
        expires_at,
        invalid_before: issued_at.checked_sub(Duration::seconds(leeway as i64)),
        subject: holder_did.as_ref().map(|did| did.to_string()),
        issuer: Some(issuer),
        jwt_id: id,
        custom: vc,
        nonce: None,
        vc_type,
    };

    let key_id = auth_fn.get_key_id();
    let jwt = Jwt::new(token_type, algorithm.to_owned(), key_id, None, payload);

    let mut token = jwt.tokenize(auth_fn).await?;

    let disclosures_token = tokenize_claims(disclosures)?;

    token.push_str(&disclosures_token);

    Ok(token)
}
