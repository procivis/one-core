use std::borrow::Cow;
use std::str::FromStr;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use disclosures::recursively_expand_disclosures;
use model::{DecomposedToken as DecomposedTokenWithDisclosures, Disclosure};
use one_crypto::{Hasher, get_hasher};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use shared_types::{DidValue, SerializedCredential};
use time::Duration;

use super::model::{
    AuthenticationFn, CertificateDetails, CredentialClaim, HolderBindingCtx, IdentifierDetails,
    PublicKeySource, SettableClaims, SignatureProvider, VerificationFn, X5References,
};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::{CertificateParsingError, pem_chain_into_x5c, x5c_into_pem_chain};
use crate::model::certificate::Certificate;
use crate::model::did::KeyRole;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::organisation::Organisation;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::model::{
    DecomposedJwt, JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey,
};
use crate::proto::jwt::{AnyPayload, Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::common::resolve_x5u;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_claims::prepare_identifier;
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::credential_formatter::sdjwt::disclosures::{
    compute_object_disclosures, parse_token, select_disclosures,
};
use crate::provider::credential_formatter::sdjwt::model::{
    KeyBindingPayload, SdJwtFormattingInputs,
};
use crate::provider::credential_formatter::sdjwt::x5c::resolve_jwks_url;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
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
    claims: Value,
    inputs: SdJwtFormattingInputs,
    auth_fn: AuthenticationFn,
    hasher: &dyn Hasher,
    did_method_provider: &dyn DidMethodProvider,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    digests_to_payload: impl FnOnce(Vec<String>) -> Result<T, FormatterError>,
    sd_array_elements: bool,
    base_url: &str,
) -> Result<SerializedCredential, FormatterError> {
    let (payload, disclosures) =
        format_hashed_credential(&claims, hasher, digests_to_payload, sd_array_elements)?;

    let proof_of_possession_key = match &inputs.holder_identifier {
        Some(identifier) => match &identifier.data {
            IdentifierData::Did(did) => {
                let did = did.as_ref().await?;
                let did_document = did_method_provider
                    .resolve(&did.did)
                    .await
                    .error_while("resolving DID")?;
                did_document
                    .find_verification_method(
                        inputs.holder_key_id.as_deref(),
                        Some(KeyRole::AssertionMethod),
                    )
                    .map(|verification_method| verification_method.public_key_jwk.clone())
                    .map(|jwk| ProofOfPossessionKey {
                        key_id: None,
                        jwk: ProofOfPossessionJwk::Jwk { jwk },
                    })
            }
            IdentifierData::Key(key) => {
                let key = key.as_ref().await?;

                let key_algorithm = key_algorithm_provider
                    .key_algorithm_from_key(&key)
                    .error_while("getting key algorithm")?;

                let jwk = key_algorithm
                    .reconstruct_key(key.public_key.as_slice(), None, None)
                    .error_while("reconstructing key")?;

                let jwk = jwk.public_key_as_jwk().error_while("getting JWK")?;
                Some(ProofOfPossessionKey {
                    key_id: None,
                    jwk: ProofOfPossessionJwk::Jwk { jwk },
                })
            }
            other => {
                return Err(FormatterError::UnsupportedIdentifierType(other.r#type()));
            }
        },
        None => None,
    };

    let subject =
        match inputs
            .holder_identifier
            .as_ref()
            .and_then(|identifier| match &identifier.data {
                IdentifierData::Did(did) => Some(did),
                _ => None,
            }) {
            Some(did) => Some(did.as_ref().await?.did.to_string()),
            None => None,
        };

    let payload = JWTPayload {
        issued_at: Some(crate::clock::now_utc()),
        expires_at: inputs.valid_until,
        invalid_before: Some(inputs.valid_from),
        subject,
        audience: None,
        issuer: Some(inputs.issuer.to_string()),
        jwt_id: inputs.id.map(|id| id.to_string()),
        custom: payload,
        proof_of_possession_key,
    };

    let key_id = auth_fn.get_key_id();
    let jwt = Jwt::new(
        inputs.token_type,
        auth_fn.jose_alg().error_while("preparing JWT")?,
        key_id,
        inputs
            .issuer_certificate
            .map(|issuer_certificate| certificate_into_x5c_and_x5u(base_url, &issuer_certificate))
            .transpose()
            .error_while("parsing PEM chain")?,
        payload,
    );

    let mut token = jwt
        .tokenize(Some(&*auth_fn))
        .await
        .error_while("creating SD-JWT token")?;
    append_disclosures(&mut token, disclosures);
    Ok(token.into())
}

/// Verifies that the `x5t#S256` header parameter (base64url-encoded SHA-256 of the
/// signing certificate DER, RFC 7515 clause 4.1.8) matches the resolved leaf.
fn verify_x5t_s256(header_thumbprint: &str, leaf_fingerprint: &str) -> Result<(), FormatterError> {
    let der_fingerprint = hex::decode(leaf_fingerprint).map_err(|e| {
        FormatterError::CouldNotExtractCredentials(format!("invalid certificate fingerprint: {e}"))
    })?;
    let expected = Base64UrlSafeNoPadding::encode_to_string(&der_fingerprint)
        .map_err(CertificateParsingError::from)
        .error_while("encoding thumbprint as base64url")?;

    if expected != header_thumbprint {
        return Err(FormatterError::CouldNotExtractCredentials(
            "x5t#S256 does not match the referenced certificate".to_string(),
        ));
    }
    Ok(())
}

fn certificate_into_x5c_and_x5u(
    base_url: &str,
    certificate: &Certificate,
) -> Result<JwtPublicKeyInfo, FormatterError> {
    let chain = pem_chain_into_x5c(&certificate.chain).error_while("parsing PEM chain")?;
    let url = format!("{base_url}/ssi/certificate/{}", certificate.id);
    let der_fingerprint = hex::decode(&certificate.fingerprint)?;
    let fingerprint = Base64UrlSafeNoPadding::encode_to_string(&der_fingerprint)
        .map_err(CertificateParsingError::from)
        .error_while("encoding chain as base64url")?;
    Ok(JwtPublicKeyInfo::X5cAndU {
        chain,
        url,
        fingerprint,
    })
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

pub(crate) fn detect_sdjwt_type_from_token(
    token: &SerializedCredential,
) -> Result<SdJwtType, FormatterError> {
    let without_claims = match token.as_ref().split_once('~') {
        None => token.as_ref(),
        Some((without_claims, _)) => without_claims,
    };
    let jwt: DecomposedJwt<AnyPayload> =
        Jwt::decompose_token(without_claims).error_while("parsing SD-JWT token")?;

    if jwt.payload.custom.contains_key("vct") {
        Ok(SdJwtType::SdJwtVc)
    } else {
        Ok(SdJwtType::SdJwt)
    }
}

pub(crate) async fn prepare_sd_presentation(
    presentation: CredentialPresentation,
    hasher: &dyn Hasher,
    user_claim_path: &[String],
) -> Result<String, FormatterError> {
    let model::DecomposedToken {
        jwt, disclosures, ..
    } = parse_token(&presentation.token)?;
    let jwt_payload = Jwt::<Value>::decompose_token(jwt)
        .error_while("parsing SD-JWT token")?
        .payload;
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

pub(crate) async fn append_key_binding_token(
    hasher: &dyn Hasher,
    holder_binding_ctx: HolderBindingCtx,
    holder_binding_fn: &dyn SignatureProvider,
    token: &mut String,
) -> Result<(), FormatterError> {
    const KEY_BINDING_TYPE: &str = "kb+jwt";
    let alg = holder_binding_fn
        .jose_alg()
        .error_while("getting JOSE alg")?;
    let sd_hash = hasher.hash_base64_url(token.as_bytes())?;

    let payload = JWTPayload {
        issued_at: Some(crate::clock::now_utc()),
        audience: Some(vec![holder_binding_ctx.audience]),
        custom: KeyBindingPayload {
            nonce: holder_binding_ctx.nonce,
            sd_hash,
            transaction_data: holder_binding_ctx.transaction_data,
        },
        ..Default::default()
    };
    let kb_token = Jwt::new(KEY_BINDING_TYPE.to_string(), alg, None, None, payload)
        .tokenize(Some(holder_binding_fn))
        .await
        .error_while("creating KB token")?;
    token.push_str(&kb_token);
    Ok(())
}

pub(crate) struct SdJwtHolderBindingParams {
    pub holder_binding_context: Option<HolderBindingCtx>,
    pub leeway: Duration,
}

impl<Payload: DeserializeOwned + SettableClaims> Jwt<Payload> {
    pub(crate) async fn build_from_token_with_disclosures(
        token: &SerializedCredential,
        verification: Option<&VerificationFn>,
        certificate_validator: Option<&dyn CertificateValidator>,
        http_client: &dyn HttpClient,
    ) -> Result<(Jwt<Payload>, IdentifierDetails, Option<String>), FormatterError> {
        let DecomposedTokenWithDisclosures {
            jwt,
            disclosures,
            key_binding_token,
        } = parse_token(token)?;
        let decomposed_token = Jwt::<serde_json::Map<String, Value>>::decompose_token(jwt)
            .error_while("parsing SD-JWT token")?;

        let hash_alg = decomposed_token
            .payload
            .custom
            .get("_sd_alg")
            .and_then(|alg| alg.as_str())
            .unwrap_or("sha-256");
        let hasher = get_hasher(hash_alg.try_into()?)?;

        let issuer = decomposed_token.payload.issuer.as_deref();
        let header = &decomposed_token.header;

        // The signing certificate may be carried inline via `x5c` or referenced via
        // `x5u`. ETSI TS 119 472-1 (QEAA-5.6.2-02) allows QEAA/PuB-EAA to reference it
        // by `x5u` + `x5t#S256` only, so fetch the chain from `x5u` when `x5c` is absent.
        let certificate_chain = match (header.x5c.as_deref(), header.x5u.as_deref()) {
            (Some(x5c), _) => Some(Cow::Borrowed(x5c)),
            (None, Some(x5u)) => {
                let pem_chain = resolve_x5u(x5u, http_client).await?;
                let x5c = pem_chain_into_x5c(&pem_chain).error_while("parsing x5u chain")?;
                Some(Cow::Owned(x5c))
            }
            (None, None) => None,
        };

        let (params, issuer_details) = match (issuer, certificate_chain.as_deref()) {
            // DID issuer
            (Some(iss), _) if iss.starts_with("did:") => {
                let did: DidValue = iss
                    .parse()
                    .map_err(DidMethodError::DidValueError)
                    .error_while("parsing issuer DID")?;
                let params = PublicKeySource::Did {
                    did: Cow::Owned(did.clone()),
                    key_id: header.key_id.as_deref(),
                };
                (params, IdentifierDetails::Did(did))
            }
            // Certificate issuer (x5c and/or x5u)
            (_, Some(x5c)) => {
                let certificate_validator =
                    certificate_validator.ok_or(FormatterError::CouldNotExtractCredentials(
                        "x5c/x5u header param not supported".to_string(),
                    ))?;

                let chain = x5c_into_pem_chain(x5c).error_while("parsing x5c")?;
                let validation_options =
                    CertificateValidationOptions::signature_and_revocation(None);
                let ParsedCertificate {
                    attributes,
                    subject_common_name,
                    ..
                } = certificate_validator
                    .parse_pem_chain(&chain, validation_options)
                    .await
                    .error_while("parsing PEM chain")?;

                // `x5t#S256` (RFC 7515 clause 4.1.8) binds the referenced certificate to
                // the signature; when present it must match the resolved leaf, whether the
                // certificate was inlined via `x5c` or fetched via `x5u`.
                if let Some(thumbprint) = header.x5t_s256.as_deref() {
                    verify_x5t_s256(thumbprint, &attributes.fingerprint)?;
                }

                (
                    PublicKeySource::X5c { x5c },
                    IdentifierDetails::Certificate(CertificateDetails {
                        chain,
                        fingerprint: attributes.fingerprint,
                        expiry: attributes.not_after,
                        subject_common_name,
                        x5_references: X5References {
                            x5c: header.x5c.is_some(),
                            x5u: header.x5u.is_some(),
                            x5t_s256: header.x5t_s256.is_some(),
                        },
                    }),
                )
            }
            // URL issuer, resolve JWKS
            (Some(iss), None) => {
                let jwks = resolve_jwks_url(
                    iss.parse().map_err(|e| {
                        FormatterError::CouldNotExtractCredentials(format!(
                            "failed parsing jwks url: {e}"
                        ))
                    })?,
                    http_client,
                )
                .await?;
                let header_key_id = header.key_id.as_deref();

                let jwk = jwks
                    .iter()
                    .find(|dto| dto.kid() == header_key_id)
                    .or(jwks.first())
                    .ok_or(FormatterError::CouldNotExtractCredentials(
                        "empty JWK list".to_string(),
                    ))?;

                let params = PublicKeySource::Jwk {
                    jwk: Cow::Owned(jwk.clone()),
                };
                (params, IdentifierDetails::Key(jwk.clone()))
            }
            // Neither iss nor x5c/x5u
            (None, None) => {
                return Err(FormatterError::CouldNotExtractCredentials(
                    "Missing issuer: no iss claim and no x5c/x5u in header".to_string(),
                ));
            }
        };

        if let Some(verification) = verification {
            decomposed_token
                .verify_signature(params, verification)
                .await
                .error_while("verifying SD-JWT token")?;
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

            let mut extended_payload: Payload =
                serde_json::from_value(Value::from(decomposed_token.payload.custom))?;
            extended_payload.set_claims(payload_before_expanding)?;
            extended_payload
        };
        let new_payload = JWTPayload {
            custom: expanded_payload,
            invalid_before: decomposed_token.payload.invalid_before,
            issued_at: decomposed_token.payload.issued_at,
            expires_at: decomposed_token.payload.expires_at,
            issuer: issuer.map(String::from),
            subject: decomposed_token.payload.subject,
            audience: None,
            jwt_id: decomposed_token.payload.jwt_id,
            proof_of_possession_key: decomposed_token.payload.proof_of_possession_key,
        };

        Ok((
            Jwt {
                header: decomposed_token.header.clone(),
                payload: new_payload,
            },
            issuer_details,
            key_binding_token.map(String::from),
        ))
    }

    pub(crate) async fn verify_holder_binding(
        cnf: &ProofOfPossessionKey,
        token: &str,
        key_binding_token: Option<&str>,
        hasher: &dyn Hasher,
        verification: Option<&VerificationFn>,
        params: SdJwtHolderBindingParams,
    ) -> Result<JWTPayload<KeyBindingPayload>, FormatterError> {
        let decomposed_kb_token = key_binding_token.map(Jwt::<KeyBindingPayload>::decompose_token);

        let Some(holder_binding_context) = params.holder_binding_context else {
            if let Some(decomposed_kb_token) = decomposed_kb_token {
                let token = decomposed_kb_token.error_while("parsing SD-JWT key binding token")?;
                return Ok(token.payload);
            } else {
                return Err(FormatterError::CouldNotExtractCredentials(
                    "Missing key binding token".to_string(),
                ));
            }
        };

        let decomposed_kb_token = decomposed_kb_token
            .transpose()
            .error_while("parsing SD-JWT key binding token")?
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "Missing key binding token".to_string(),
            ))?;

        if let Some(verification) = verification {
            let params = PublicKeySource::Jwk {
                jwk: Cow::Borrowed(cnf.jwk.jwk()),
            };
            decomposed_kb_token
                .verify_signature(params, verification)
                .await
                .error_while("verifying SD-JWT key binding token")?;
        }

        let DecomposedJwt {
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
        let expected_hash = hasher.hash_base64_url(token.as_bytes().get(..=payload_end).ok_or(
            FormatterError::CouldNotExtractCredentials(
                "Could not extract payload for hash".to_string(),
            ),
        )?)?;
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
        if (iat - params.leeway) > crate::clock::now_utc() {
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

        if !audience.contains(&holder_binding_context.audience) {
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
        Ok(kb_payload)
    }
}

pub(crate) fn parse_holder_identifier<T>(
    organisation: &Organisation,
    parsed_credential: &Jwt<T>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<Option<Identifier>, FormatterError> {
    Ok(
        if let Some(proof_of_possession_key) = &parsed_credential.payload.proof_of_possession_key {
            Some(prepare_identifier(
                &IdentifierDetails::Key(proof_of_possession_key.jwk.jwk().to_owned()),
                key_algorithm_provider,
                did_method_provider,
                organisation.clone(),
            )?)
        } else {
            parsed_credential
                .payload
                .subject
                .as_ref()
                .map(|did| DidValue::from_str(did))
                .transpose()
                .map_err(DidMethodError::DidValueError)
                .error_while("parsing subject DID")?
                .map(IdentifierDetails::Did)
                .map(|details| {
                    prepare_identifier(
                        &details,
                        key_algorithm_provider,
                        did_method_provider,
                        organisation.clone(),
                    )
                })
                .transpose()?
        },
    )
}
