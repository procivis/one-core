use anyhow::Context;
use disclosures::recursively_expand_disclosures;
use model::{DecomposedToken as DecomposedTokenWithDisclosures, Disclosure};
use one_crypto::{CryptoProvider, Hasher};
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::jwt::model::JWTPayload;
use super::model::TokenVerifier;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::DecomposedToken;
use crate::provider::credential_formatter::jwt::{AnyPayload, Jwt};
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::credential_formatter::sdjwt::disclosures::{parse_token, select_disclosures};

pub mod disclosures;
pub mod mapper;
pub mod model;

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
            .get_key_algorithm_from_jose_alg(&token.header.algorithm)
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
                &algorithm,
                token.unverified_jwt.as_bytes(),
                &token.signature,
            )
            .await
            .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))
    }
}
