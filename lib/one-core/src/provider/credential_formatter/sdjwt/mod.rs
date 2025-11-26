use std::borrow::Cow;

use anyhow::Context;
use disclosures::recursively_expand_disclosures;
use model::{DecomposedToken as DecomposedTokenWithDisclosures, Disclosure};
use one_crypto::{CryptoProvider, Hasher};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};

use super::model::{
    AuthenticationFn, CertificateDetails, CredentialClaim, HolderBindingCtx, IdentifierDetails,
    PublicKeySource, SettableClaims, VerificationFn,
};
use crate::mapper::x509::{pem_chain_into_x5c, x5c_into_pem_chain};
use crate::model::did::KeyRole;
use crate::model::identifier::IdentifierType;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::model::{
    DecomposedToken, JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey,
};
use crate::proto::jwt::{AnyPayload, Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::credential_formatter::sdjwt::disclosures::{
    compute_object_disclosures, parse_token, select_disclosures,
};
use crate::provider::credential_formatter::sdjwt::model::{
    KeyBindingPayload, SdJwtFormattingInputs,
};
use crate::provider::credential_formatter::sdjwt::x5c::resolve_jwks_url;
use crate::provider::credential_formatter::vcdm::VcdmCredential;
use crate::provider::did_method::jwk::jwk_helpers::encode_to_did;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::key::dto::PublicKeyJwkDTO;

pub mod disclosures;
pub mod mapper;
pub mod model;
pub mod x5c;

#[cfg(test)]
pub mod test;

pub(crate) enum SdJwtType {
    SdJwt,
    SdJwtVc,
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn format_credential<T: Serialize>(
    credential: VcdmCredential,
    claims: Value,
    additional_inputs: SdJwtFormattingInputs,
    auth_fn: AuthenticationFn,
    hasher: &dyn Hasher,
    did_method_provider: &dyn DidMethodProvider,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    digests_to_payload: impl FnOnce(Vec<String>) -> Result<T, FormatterError>,
    sd_array_elements: bool,
) -> Result<String, FormatterError> {
    let issuer = credential.issuer.as_url().to_string();
    let id = credential.id.clone();
    let invalid_before = credential.valid_from.or(credential.issuance_date);
    let expires_at = credential.valid_until.or(credential.expiration_date);
    let (payload, disclosures) =
        format_hashed_credential(&claims, hasher, digests_to_payload, sd_array_elements)?;

    let proof_of_possession_key = match &additional_inputs.holder_identifier {
        Some(identifier) => match &identifier.r#type {
            IdentifierType::Did => {
                if let Some(did) = &identifier.did {
                    let did_document = did_method_provider
                        .resolve(&did.did)
                        .await
                        .map_err(|err| FormatterError::CouldNotFormat(format!("{err}")))?;
                    did_document
                        .find_verification_method(
                            additional_inputs.holder_key_id.as_deref(),
                            Some(KeyRole::AssertionMethod),
                        )
                        .map(|verification_method| verification_method.public_key_jwk.clone())
                        .map(PublicKeyJwkDTO::from)
                        .map(|jwk| {
                            let jwk = match additional_inputs.swiyu_proof_of_possession {
                                false => ProofOfPossessionJwk::Jwk { jwk },
                                true => ProofOfPossessionJwk::Swiyu(jwk),
                            };
                            ProofOfPossessionKey { key_id: None, jwk }
                        })
                } else {
                    None
                }
            }
            IdentifierType::Key => {
                if let Some(key) = &identifier.key {
                    let key_type =
                        key.key_algorithm_type()
                            .ok_or(FormatterError::CouldNotFormat(
                                "Invalid key algorithm".to_string(),
                            ))?;

                    let key_algorithm = key_algorithm_provider
                        .key_algorithm_from_type(key_type)
                        .ok_or(FormatterError::CouldNotFormat(
                            "Invalid key algorithm".to_string(),
                        ))?;

                    let jwk = key_algorithm
                        .reconstruct_key(key.public_key.as_slice(), None, None)
                        .map_err(|e| {
                            FormatterError::CouldNotFormat(format!("failed to parse key: {e}"))
                        })?;

                    let jwk = jwk
                        .public_key_as_jwk()
                        .map_err(|e| {
                            FormatterError::CouldNotFormat(format!("failed to parse key: {e}"))
                        })?
                        .into();

                    let jwk = match additional_inputs.swiyu_proof_of_possession {
                        false => ProofOfPossessionJwk::Jwk { jwk },
                        true => ProofOfPossessionJwk::Swiyu(jwk),
                    };

                    Some(ProofOfPossessionKey { key_id: None, jwk })
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    };

    let subject = additional_inputs
        .holder_identifier
        .as_ref()
        .and_then(|identifier| identifier.did.as_ref())
        .map(|did| did.did.clone())
        .map(|did| did.to_string());

    let payload = JWTPayload {
        issued_at: Some(OffsetDateTime::now_utc()),
        expires_at,
        invalid_before,
        subject,
        audience: None,
        issuer: Some(issuer),
        jwt_id: id.map(|id| id.to_string()),
        custom: payload,
        proof_of_possession_key,
    };

    let key_id = auth_fn.get_key_id();
    let jwt = Jwt::new(
        additional_inputs.token_type,
        auth_fn.jose_alg().ok_or(FormatterError::CouldNotFormat(
            "Invalid key algorithm".to_string(),
        ))?,
        key_id,
        additional_inputs
            .issuer_certificate
            .map(|issuer_certificate| pem_chain_into_x5c(&issuer_certificate.chain))
            .transpose()
            .map_err(|err| {
                FormatterError::Failed(format!("failed to create x5c header parameter: {err}"))
            })?
            .map(JwtPublicKeyInfo::X5c),
        payload,
    );

    let mut token = jwt.tokenize(Some(&*auth_fn)).await?;
    append_disclosures(&mut token, disclosures);
    Ok(token)
}

fn format_hashed_credential<T>(
    claims: &Value,
    hasher: &dyn Hasher,
    digests_to_payload: impl FnOnce(Vec<String>) -> Result<T, FormatterError>,
    sd_array_elements: bool,
) -> Result<(T, Vec<String>), FormatterError> {
    let (disclosures, digests) = compute_object_disclosures(claims, hasher, sd_array_elements)?;
    let payload = digests_to_payload(digests)?;
    Ok((payload, disclosures))
}

pub(crate) fn detect_sdjwt_type_from_token(token: &str) -> Result<SdJwtType, FormatterError> {
    let without_claims = match token.split_once('~') {
        None => token,
        Some((without_claims, _)) => without_claims,
    };
    let jwt: DecomposedToken<AnyPayload> = Jwt::decompose_token(without_claims)?;

    if jwt.payload.custom.contains_key("vct") {
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
    user_claim_path: &[String],
) -> Result<String, FormatterError> {
    let model::DecomposedToken {
        jwt, disclosures, ..
    } = parse_token(&presentation.token)?;
    let jwt_payload = Jwt::<Value>::decompose_token(jwt)?.payload;
    let disclosed_keys = if !user_claim_path.is_empty() {
        let prefix = user_claim_path.join("/");
        presentation
            .disclosed_keys
            .iter()
            .map(|disclosed_key| format!("{prefix}/{disclosed_key}",))
            .collect()
    } else {
        presentation.disclosed_keys.clone()
    };
    let disclosures = select_disclosures(disclosed_keys, &jwt_payload.custom, disclosures, hasher)?;
    let mut token = jwt.to_owned();
    append_disclosures(&mut token, disclosures);

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
        .hash_base64_url(token.as_bytes())
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
    .tokenize(Some(&*holder_binding_fn))
    .await
    .map_err(|err| {
        FormatterError::CouldNotFormat(format!("failed to tokenize key binding token: {err}"))
    })?;
    token.push_str(&kb_token);
    Ok(())
}

pub(crate) struct SdJwtHolderBindingParams {
    pub holder_binding_context: Option<HolderBindingCtx>,
    pub leeway: Duration,
    pub skip_holder_binding_aud_check: bool,
}

impl<Payload: DeserializeOwned + SettableClaims> Jwt<Payload> {
    pub(crate) async fn build_from_token_with_disclosures(
        token: &str,
        crypto: &dyn CryptoProvider,
        verification: Option<&VerificationFn>,
        params: SdJwtHolderBindingParams,
        certificate_validator: Option<&dyn CertificateValidator>,
        http_client: &dyn HttpClient,
    ) -> Result<
        (
            Jwt<Payload>,
            Option<JWTPayload<KeyBindingPayload>>,
            IdentifierDetails,
        ),
        FormatterError,
    > {
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
                    params,
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

        let (params, isuer_details) = if issuer.starts_with("did:") {
            let did: DidValue = issuer
                .parse()
                .context("issuer did parsing error")
                .map_err(|e| FormatterError::Failed(e.to_string()))?;
            let params = PublicKeySource::Did {
                did: Cow::Owned(did.clone()),
                key_id: decomposed_token.header.key_id.as_deref(),
            };
            (params, IdentifierDetails::Did(did))
        } else {
            match decomposed_token.header.x5c.as_ref() {
                None => {
                    let jwks = resolve_jwks_url(
                        issuer.parse().map_err(|e| {
                            FormatterError::CouldNotExtractCredentials(format!(
                                "failed parsing did url: {e}"
                            ))
                        })?,
                        http_client,
                    )
                    .await?;
                    let header_key_id = decomposed_token.header.key_id.as_deref();

                    let jwk = jwks
                        .iter()
                        .find(|dto| dto.get_kid().as_deref() == header_key_id)
                        .or(jwks.first())
                        .ok_or(FormatterError::CouldNotExtractCredentials(
                            "empty JWK list".to_string(),
                        ))?;

                    let did = encode_to_did(jwk)
                        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;
                    let params = PublicKeySource::Did {
                        did: Cow::Owned(did.clone()),
                        key_id: decomposed_token.header.key_id.as_deref(),
                    };
                    (params, IdentifierDetails::Did(did))
                }
                Some(x5c) => {
                    let certificate_validator = certificate_validator.ok_or(
                        FormatterError::Failed("x5c header param not supported".to_string()),
                    )?;
                    let params = PublicKeySource::X5c { x5c };
                    let chain = x5c_into_pem_chain(x5c).map_err(|err| {
                        FormatterError::Failed(format!("failed to parse x5c header param: {err}"))
                    })?;
                    let validation_options =
                        CertificateValidationOptions::signature_and_revocation(None);
                    let ParsedCertificate {
                        attributes,
                        subject_common_name,
                        ..
                    } = certificate_validator
                        .parse_pem_chain(&chain, validation_options)
                        .await
                        .map_err(|err| {
                            FormatterError::Failed(format!(
                                "failed to parse x5c header param: {err}"
                            ))
                        })?;
                    (
                        params,
                        IdentifierDetails::Certificate(CertificateDetails {
                            chain,
                            fingerprint: attributes.fingerprint,
                            expiry: attributes.not_after,
                            subject_common_name,
                        }),
                    )
                }
            }
        };

        if let Some(verification) = verification {
            decomposed_token
                .verify_signature(params, verification)
                .await?;
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
            let mut payload_before_expanding =
                CredentialClaim::try_from(Value::from(decomposed_token.payload.custom.clone()))?;

            recursively_expand_disclosures(
                &disclosures_with_hashes,
                &mut payload_before_expanding,
            )?;

            let mut extended_payload: Payload = serde_json::from_value(Value::from(
                decomposed_token.payload.custom,
            ))
            .map_err(|_| {
                FormatterError::CouldNotExtractCredentials(
                    "Failed to deserialize JWT payload".to_string(),
                )
            })?;
            extended_payload.set_claims(payload_before_expanding)?;
            extended_payload
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
        let new_payload = JWTPayload {
            custom: expanded_payload,
            invalid_before: decomposed_token.payload.invalid_before,
            issued_at: decomposed_token.payload.issued_at,
            expires_at: decomposed_token.payload.expires_at,
            issuer: Some(issuer.clone()),
            subject,
            audience: None,
            jwt_id: decomposed_token.payload.jwt_id,
            proof_of_possession_key: decomposed_token.payload.proof_of_possession_key,
        };

        Ok((
            Jwt {
                header: decomposed_token.header.clone(),
                payload: new_payload,
            },
            key_binding_payload,
            isuer_details,
        ))
    }

    async fn verify_holder_binding(
        cnf: &ProofOfPossessionKey,
        token: &str,
        key_binding_token: Option<&str>,
        hasher: &dyn Hasher,
        verification: Option<&VerificationFn>,
        params: SdJwtHolderBindingParams,
    ) -> Result<Option<JWTPayload<KeyBindingPayload>>, FormatterError> {
        let decomposed_kb_token = key_binding_token.map(Jwt::<KeyBindingPayload>::decompose_token);

        let Some(holder_binding_context) = params.holder_binding_context else {
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
            let params = PublicKeySource::Did {
                did: Cow::Borrowed(&kb_issuer),
                key_id: decomposed_kb_token.header.key_id.as_deref(),
            };
            decomposed_kb_token
                .verify_signature(params, verification)
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
            .hash_base64_url(&token.as_bytes()[..=payload_end])
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
        if (iat - params.leeway) > OffsetDateTime::now_utc() {
            // kb token is supposedly issued in the future
            return Err(FormatterError::CouldNotExtractCredentials(
                "Invalid iat claim in key binding token, token is issued in the future".to_string(),
            ));
        }

        if !params.skip_holder_binding_aud_check {
            let Some(ref audience) = kb_payload.audience else {
                return Err(FormatterError::CouldNotExtractCredentials(
                    "Missing aud claim in key binding token".to_string(),
                ));
            };

            if !audience.contains(&holder_binding_context.audience) {
                return Err(FormatterError::CouldNotExtractCredentials(format!(
                    "Invalid key binding token aud: expected '{}' to be listed, got '{:?}'",
                    holder_binding_context.audience, kb_payload.audience
                )));
            }
        }

        if kb_payload.custom.nonce != holder_binding_context.nonce {
            return Err(FormatterError::CouldNotExtractCredentials(format!(
                "Invalid key binding token nonce: expected '{}', got '{}'",
                holder_binding_context.nonce, kb_payload.custom.nonce
            )));
        }
        Ok(Some(kb_payload))
    }
}
