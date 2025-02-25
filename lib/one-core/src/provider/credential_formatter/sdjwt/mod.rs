use anyhow::Context;
use disclosures::recursively_expand_disclosures;
use model::{DecomposedToken as DecomposedTokenWithDisclosures, Disclosure};
use one_crypto::{CryptoProvider, Hasher};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use time::Duration;

use super::jwt::model::JWTPayload;
use super::model::{AuthenticationFn, TokenVerifier};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::DecomposedToken;
use crate::provider::credential_formatter::jwt::{AnyPayload, Jwt};
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::credential_formatter::sdjwt::disclosures::{
    compute_object_disclosures, parse_token, select_disclosures,
};
use crate::provider::credential_formatter::sdjwt::model::SdJwtFormattingInputs;
use crate::provider::credential_formatter::vcdm::VcdmCredential;

pub mod disclosures;
pub mod mapper;
pub mod model;

#[cfg(test)]
pub mod test;

pub(crate) enum SdJwtType {
    SdJwt,
    SdJwtVc,
}

pub async fn format_credential<T: Serialize>(
    credential: VcdmCredential,
    additional_inputs: SdJwtFormattingInputs,
    auth_fn: AuthenticationFn,
    hasher: &dyn Hasher,
    credential_to_claims: fn(credential: &VcdmCredential) -> Result<Value, FormatterError>,
    cred_and_digests_to_payload: fn(VcdmCredential, Vec<String>) -> Result<T, FormatterError>,
) -> Result<String, FormatterError> {
    let issuer = credential.issuer.to_did_value()?.to_string();
    let id = credential.id.clone();
    let issued_at = credential.valid_from.or(credential.issuance_date);
    let expires_at = credential.valid_until.or(credential.expiration_date);
    let (payload, disclosures) = format_hashed_credential(
        credential,
        hasher,
        credential_to_claims,
        cred_and_digests_to_payload,
    )?;

    let payload = JWTPayload {
        issued_at,
        expires_at,
        invalid_before: issued_at
            .and_then(|iat| iat.checked_sub(Duration::seconds(additional_inputs.leeway as i64))),
        subject: additional_inputs.holder_did.map(|did| did.to_string()),
        issuer: Some(issuer),
        jwt_id: id.map(|id| id.to_string()),
        custom: payload,
        vc_type: additional_inputs.vc_type,
        proof_of_possession_key: None,
    };

    let key_id = auth_fn.get_key_id();
    let jwt = Jwt::new(
        additional_inputs.token_type,
        auth_fn.jose_alg().ok_or(FormatterError::CouldNotFormat(
            "Invalid key algorithm".to_string(),
        ))?,
        key_id,
        None,
        payload,
    );

    let jwt_token = jwt.tokenize(Some(auth_fn)).await?;
    let sdjwt = serialize(jwt_token, disclosures);
    Ok(sdjwt)
}

fn format_hashed_credential<T>(
    credential: VcdmCredential,
    hasher: &dyn Hasher,
    credential_to_claims: fn(credential: &VcdmCredential) -> Result<Value, FormatterError>,
    cred_and_digests_to_payload: fn(VcdmCredential, Vec<String>) -> Result<T, FormatterError>,
) -> Result<(T, Vec<String>), FormatterError> {
    let claims = credential_to_claims(&credential)?;
    let (disclosures, digests) = compute_object_disclosures(&claims, hasher)?;
    let payload = cred_and_digests_to_payload(credential, digests)?;
    Ok((payload, disclosures))
}

pub(crate) fn detect_sdjwt_type_from_token(token: &str) -> Result<SdJwtType, FormatterError> {
    let without_claims = match token.split_once('~') {
        None => token,
        Some((without_claims, _)) => without_claims,
    };
    let jwt: DecomposedToken<AnyPayload> = Jwt::decompose_token(without_claims)?;

    if jwt.payload.vc_type.is_some() {
        Ok(SdJwtType::SdJwtVc)
    } else {
        Ok(SdJwtType::SdJwt)
    }
}

pub(crate) fn prepare_sd_presentation(
    presentation: CredentialPresentation,
    hasher: &dyn Hasher,
) -> Result<String, FormatterError> {
    let model::DecomposedToken { jwt, disclosures } = parse_token(&presentation.token)?;
    let disclosures = select_disclosures(presentation.disclosed_keys, disclosures, hasher)?;
    Ok(serialize(jwt.to_owned(), disclosures))
}

pub(crate) fn serialize(jwt: String, disclosures: Vec<String>) -> String {
    let mut token = jwt;
    token.push('~');

    let disclosures = disclosures.join("~");
    if !disclosures.is_empty() {
        token.push_str(&disclosures);
        token.push('~');
    }

    token
}

impl<Payload: DeserializeOwned> Jwt<Payload> {
    pub async fn build_from_token_with_disclosures(
        token: &str,
        crypto: &dyn CryptoProvider,
        verification: Option<Box<dyn TokenVerifier>>,
    ) -> Result<Jwt<Payload>, FormatterError> {
        let DecomposedTokenWithDisclosures { jwt, disclosures } = parse_token(token)?;
        let decomposed_token = Jwt::<serde_json::Map<String, Value>>::decompose_token(jwt)?;

        let issuer = decomposed_token.payload.issuer.as_ref().map(|issuer| {
            if issuer.starts_with("did:") {
                issuer.to_owned()
            } else {
                format!(
                    "did:sd_jwt_vc_issuer_metadata:{}",
                    urlencoding::encode(issuer)
                )
            }
        });

        if let (Some(verification), Some(issuer)) = (verification, &issuer) {
            Self::verify_token_signature(&decomposed_token, issuer, verification).await?;
        };

        let hash_alg = decomposed_token
            .payload
            .custom
            .get("_sd_alg")
            .and_then(|alg| alg.as_str())
            .unwrap_or("sha-256");

        let hasher = crypto.get_hasher(hash_alg).map_err(|_| {
            FormatterError::CouldNotExtractCredentials(
                "Missing or invalid hash algorithm".to_string(),
            )
        })?;

        let disclosures_with_hashes = disclosures
            .iter()
            .map(|disclosure| {
                Ok((
                    disclosure,
                    (
                        disclosure.hash_disclosure(&*hasher)?,
                        disclosure.hash_disclosure_array(&*hasher)?,
                    ),
                ))
            })
            .collect::<Result<Vec<(&Disclosure, (String, String))>, FormatterError>>()?;

        let expanded_payload: Payload = {
            let mut payload_before_expanding = Value::from(decomposed_token.payload.custom);

            recursively_expand_disclosures(&disclosures_with_hashes, &mut payload_before_expanding);
            serde_json::from_value(payload_before_expanding).map_err(|_| {
                FormatterError::CouldNotExtractCredentials(
                    "Failed to deserialize JWT payload".to_string(),
                )
            })?
        };

        let new_payload = JWTPayload {
            custom: expanded_payload,
            invalid_before: decomposed_token.payload.invalid_before,
            issued_at: decomposed_token.payload.issued_at,
            expires_at: decomposed_token.payload.expires_at,
            issuer,
            subject: decomposed_token.payload.subject,
            jwt_id: decomposed_token.payload.jwt_id,
            vc_type: decomposed_token.payload.vc_type,
            proof_of_possession_key: decomposed_token.payload.proof_of_possession_key,
        };

        Ok(Jwt {
            header: decomposed_token.header.clone(),
            payload: new_payload,
        })
    }

    async fn verify_token_signature<AnyPayload>(
        token: &DecomposedToken<AnyPayload>,
        issuer: &str,
        verification_fn: Box<dyn TokenVerifier>,
    ) -> Result<(), FormatterError> {
        let (_, algorithm) = verification_fn
            .key_algorithm_provider()
            .key_algorithm_from_jose_alg(&token.header.algorithm)
            .ok_or(FormatterError::CouldNotVerify(format!(
                "Missing key algorithm for {}",
                token.header.algorithm
            )))?;

        verification_fn
            .verify(
                Some(
                    issuer
                        .parse()
                        .context("issuer did parsing error")
                        .map_err(|e| FormatterError::Failed(e.to_string()))?,
                ),
                token.header.key_id.as_deref(),
                &algorithm.algorithm_id(),
                token.unverified_jwt.as_bytes(),
                &token.signature,
            )
            .await
            .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))
    }
}
