use anyhow::Context;
use disclosures::recursively_expand_disclosures;
use model::{DecomposedToken as DecomposedTokenWithDisclosures, Disclosure};
use one_crypto::{CryptoProvider, Hasher};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use super::jwt::model::{JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey};
use super::model::{AuthenticationFn, HolderBindingCtx, TokenVerifier, VerificationFn};
use crate::model::did::KeyRole;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::DecomposedToken;
use crate::provider::credential_formatter::jwt::{AnyPayload, Jwt};
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::credential_formatter::sdjwt::disclosures::{
    compute_object_disclosures, parse_token, select_disclosures,
};
use crate::provider::credential_formatter::sdjwt::model::{
    KeyBindingPayload, SdJwtFormattingInputs,
};
use crate::provider::credential_formatter::vcdm::VcdmCredential;
use crate::provider::did_method::jwk::jwk_helpers::encode_to_did;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::service::key::dto::PublicKeyJwkDTO;

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
    did_method_provider: &dyn DidMethodProvider,
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

    let proof_of_possession_key = if let Some(ref holder_did) = additional_inputs.holder_did {
        let did_document = did_method_provider
            .resolve(holder_did)
            .await
            .map_err(|err| FormatterError::CouldNotFormat(format!("{}", err)))?;
        did_document
            .find_verification_method(
                additional_inputs.holder_key_id.as_deref(),
                Some(KeyRole::AssertionMethod),
            )
            .map(|verification_method| verification_method.public_key_jwk.clone())
            .map(PublicKeyJwkDTO::from)
            .map(|jwk| ProofOfPossessionKey {
                key_id: None,
                jwk: ProofOfPossessionJwk::Jwk { jwk },
            })
    } else {
        None
    };

    let payload = JWTPayload {
        issued_at,
        expires_at,
        invalid_before: issued_at
            .and_then(|iat| iat.checked_sub(Duration::seconds(additional_inputs.leeway as i64))),
        subject: additional_inputs.holder_did.map(|did| did.to_string()),
        audience: None,
        issuer: Some(issuer),
        jwt_id: id.map(|id| id.to_string()),
        custom: payload,
        vc_type: additional_inputs.vc_type,
        proof_of_possession_key,
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

    let mut token = jwt.tokenize(Some(auth_fn)).await?;
    append_disclosures(&mut token, disclosures);
    Ok(token)
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

pub(crate) async fn prepare_sd_presentation(
    presentation: CredentialPresentation,
    hasher: &dyn Hasher,
    holder_binding_ctx: Option<HolderBindingCtx>,
    holder_binding_fn: Option<AuthenticationFn>,
) -> Result<String, FormatterError> {
    let model::DecomposedToken {
        jwt, disclosures, ..
    } = parse_token(&presentation.token)?;
    let disclosures = select_disclosures(presentation.disclosed_keys, disclosures, hasher)?;
    let mut token = jwt.to_owned();
    append_disclosures(&mut token, disclosures);

    let jwt_payload = Jwt::<()>::decompose_token(jwt)?.payload;
    if jwt_payload.proof_of_possession_key.is_some() {
        let holder_binding_ctx = holder_binding_ctx.ok_or(FormatterError::Failed(
            "holder binding required, but no context provided".to_string(),
        ))?;
        let holder_binding_fn = holder_binding_fn.ok_or(FormatterError::Failed(
            "holder binding required, but no signature provider provided".to_string(),
        ))?;
        append_key_binding_token(hasher, holder_binding_ctx, holder_binding_fn, &mut token).await?;
    }
    Ok(token)
}

fn append_disclosures(token: &mut String, disclosures: Vec<String>) {
    token.push('~');

    let disclosures = disclosures.join("~");
    if !disclosures.is_empty() {
        token.push_str(&disclosures);
        token.push('~');
    }
}

async fn append_key_binding_token(
    hasher: &dyn Hasher,
    holder_binding_ctx: HolderBindingCtx,
    holder_binding_fn: AuthenticationFn,
    token: &mut String,
) -> Result<(), FormatterError> {
    const KEY_BINDING_TYPE: &str = "kb+jwt";
    let alg = holder_binding_fn
        .jose_alg()
        .ok_or(FormatterError::CouldNotFormat(
            "Invalid key algorithm".to_string(),
        ))?;
    let sd_hash = hasher
        .hash_base64(token.as_bytes())
        .map_err(|err| FormatterError::CouldNotFormat(format!("failed to hash token: {err}")))?;
    let payload = JWTPayload {
        issued_at: Some(OffsetDateTime::now_utc()),
        audience: Some(vec![holder_binding_ctx.audience]),
        custom: KeyBindingPayload {
            nonce: holder_binding_ctx.nonce,
            sd_hash,
        },
        ..Default::default()
    };
    let kb_token = Jwt::new(
        KEY_BINDING_TYPE.to_string(),
        alg,
        holder_binding_fn.get_key_id(),
        None,
        payload,
    )
    .tokenize(Some(holder_binding_fn))
    .await
    .map_err(|err| {
        FormatterError::CouldNotFormat(format!("failed to tokenize key binding token: {err}"))
    })?;
    token.push_str(&kb_token);
    Ok(())
}

impl<Payload: DeserializeOwned> Jwt<Payload> {
    pub async fn build_from_token_with_disclosures(
        token: &str,
        crypto: &dyn CryptoProvider,
        verification: Option<&VerificationFn>,
        key_binding_context: Option<HolderBindingCtx>,
        leeway: Duration,
    ) -> Result<(Jwt<Payload>, Option<JWTPayload<KeyBindingPayload>>), FormatterError> {
        let DecomposedTokenWithDisclosures {
            jwt,
            disclosures,
            key_binding_token,
        } = parse_token(token)?;
        let decomposed_token = Jwt::<serde_json::Map<String, Value>>::decompose_token(jwt)?;

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

        let key_binding_payload =
            if let Some(ref cnf) = decomposed_token.payload.proof_of_possession_key {
                Self::verify_holder_binding(
                    cnf,
                    token,
                    key_binding_token,
                    &*hasher,
                    verification,
                    key_binding_context,
                    leeway,
                )
                .await?
            } else {
                None
            };
        let issuer = decomposed_token
            .payload
            .issuer
            .as_ref()
            .ok_or(FormatterError::Failed(
                "Missing issuer in sd-jwt".to_string(),
            ))?;

        let issuer_did = if issuer.starts_with("did:") {
            issuer.clone()
        } else {
            let url = match decomposed_token.header.x5c.as_ref() {
                None => issuer.clone(),
                Some(x5c) => {
                    let mut url = url::Url::parse(issuer)
                        .map_err(|e| FormatterError::Failed(e.to_string()))?;

                    for cert in x5c {
                        let mut query_pairs = url.query_pairs_mut();
                        query_pairs.append_pair("x5c", cert);
                    }

                    url.into()
                }
            };

            format!(
                "did:sd_jwt_vc_issuer_metadata:{}",
                urlencoding::encode(&url)
            )
        };

        let subject = match (
            decomposed_token.payload.subject.as_ref(),
            decomposed_token.payload.proof_of_possession_key.as_ref(),
        ) {
            (Some(subject), _) => Some(subject.to_string()),
            (None, Some(cnf)) => Some(
                encode_to_did(cnf.jwk.jwk())
                    .map(|did| did.to_string())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?,
            ),
            (None, None) => None,
        };

        if let Some(verification) = verification {
            Self::verify_token_signature(&decomposed_token, &issuer_did, verification).await?;
        };

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
            issuer: Some(issuer_did),
            subject,
            audience: None,
            jwt_id: decomposed_token.payload.jwt_id,
            vc_type: decomposed_token.payload.vc_type,
            proof_of_possession_key: decomposed_token.payload.proof_of_possession_key,
        };

        Ok((
            Jwt {
                header: decomposed_token.header.clone(),
                payload: new_payload,
            },
            key_binding_payload,
        ))
    }

    async fn verify_holder_binding(
        cnf: &ProofOfPossessionKey,
        token: &str,
        key_binding_token: Option<&str>,
        hasher: &dyn Hasher,
        verification: Option<&VerificationFn>,
        holder_binding_context: Option<HolderBindingCtx>,
        leeway: Duration,
    ) -> Result<Option<JWTPayload<KeyBindingPayload>>, FormatterError> {
        let decomposed_kb_token = key_binding_token.map(Jwt::<KeyBindingPayload>::decompose_token);

        let Some(holder_binding_context) = holder_binding_context else {
            if let Some(decomposed_kb_token) = decomposed_kb_token {
                let token = decomposed_kb_token?;
                return Ok(Some(token.payload));
            } else {
                return Ok(None);
            }
        };

        let decomposed_kb_token =
            decomposed_kb_token
                .transpose()?
                .ok_or(FormatterError::CouldNotExtractCredentials(
                    "Missing key binding token".to_string(),
                ))?;

        if let Some(verification) = verification {
            let kb_issuer = encode_to_did(cnf.jwk.jwk()).map_err(|err| {
                FormatterError::CouldNotExtractCredentials(format!(
                    "Failed to encode cnf JWK to did: {err}"
                ))
            })?;
            Self::verify_token_signature(&decomposed_kb_token, kb_issuer.as_str(), verification)
                .await?;
        }

        let DecomposedToken {
            payload: kb_payload,
            ..
        } = decomposed_kb_token;

        // use `rmatch` instead of `rsplit` because the separator must not be discarded.
        let (payload_end, _) =
            token
                .rmatch_indices('~')
                .next()
                .ok_or(FormatterError::CouldNotExtractCredentials(
                    "Invalid credential format".to_string(),
                ))?;
        let expected_hash = hasher
            .hash_base64(token[..=payload_end].as_bytes())
            .map_err(|err| {
                FormatterError::CouldNotFormat(format!("failed to hash token: {err}"))
            })?;
        if kb_payload.custom.sd_hash != expected_hash {
            return Err(FormatterError::CouldNotExtractCredentials(format!(
                "Invalid key binding token sd_hash: expected '{}', got '{}'",
                expected_hash, kb_payload.custom.sd_hash
            )));
        }

        let Some(iat) = kb_payload.issued_at else {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Missing iat claim in key binding token".to_string(),
            ));
        };
        if (iat - leeway) > OffsetDateTime::now_utc() {
            // kb token is supposedly issued in the future
            return Err(FormatterError::CouldNotExtractCredentials(
                "Invalid iat claim in key binding token, token is issued in the future".to_string(),
            ));
        }

        let Some(ref audience) = kb_payload.audience else {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Missing aud claim in key binding token".to_string(),
            ));
        };

        if !audience
            .iter()
            .any(|aud| *aud == holder_binding_context.audience)
        {
            return Err(FormatterError::CouldNotExtractCredentials(format!(
                "Invalid key binding token aud: expected '{}' to be listed, got '{:?}'",
                holder_binding_context.audience, kb_payload.audience
            )));
        }

        if kb_payload.custom.nonce != holder_binding_context.nonce {
            return Err(FormatterError::CouldNotExtractCredentials(format!(
                "Invalid key binding token nonce: expected '{}', got '{}'",
                holder_binding_context.nonce, kb_payload.custom.nonce
            )));
        }
        Ok(Some(kb_payload))
    }

    async fn verify_token_signature<AnyPayload>(
        token: &DecomposedToken<AnyPayload>,
        issuer: &str,
        verification_fn: &dyn TokenVerifier,
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
