use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use indexmap::indexset;
use model::CredentialEnvelope;
use one_crypto::CryptoProvider;
use one_providers::common_models::did::DidValue;
use one_providers::credential_formatter::error::FormatterError;
use one_providers::credential_formatter::imp::json_ld;
use one_providers::credential_formatter::imp::json_ld::context::caching_loader::{
    ContextCache, JsonLdCachingLoader,
};
use one_providers::credential_formatter::imp::json_ld::model::{
    ContextType, LdCredential, LdPresentation, LdProof, ManyOrOne,
};
use one_providers::credential_formatter::model::{
    AuthenticationFn, Context, CredentialData, CredentialPresentation, CredentialSubject,
    DetailCredential, ExtractPresentationCtx, FormatPresentationCtx, FormatterCapabilities, Issuer,
    Presentation, VerificationFn,
};
use one_providers::credential_formatter::CredentialFormatter;
use one_providers::did::provider::DidMethodProvider;
use one_providers::http_client::HttpClient;
use serde::ser::Error;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use time::{Duration, OffsetDateTime};

#[cfg(test)]
mod test;

mod model;

pub struct JsonLdClassic {
    pub base_url: Option<String>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub caching_loader: ContextCache,
    params: Params,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway: Duration,
    embed_layout_properties: Option<bool>,
}

#[async_trait]
impl CredentialFormatter for JsonLdClassic {
    async fn extract_credentials_unverified(
        &self,
        credential: &str,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(credential, None).await
    }

    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &Option<DidValue>,
        algorithm: &str,
        additional_context: Vec<ContextType>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        json_ld_context_url: Option<String>,
        custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        let mut credential = json_ld::prepare_credential(
            credential,
            holder_did.as_ref(),
            additional_context,
            additional_types,
            json_ld_context_url.map(|u| u.parse().unwrap()),
            custom_subject_name,
            self.params.embed_layout_properties.unwrap_or_default(),
        )?;

        let cryptosuite = match algorithm {
            "EDDSA" => "eddsa-rdfc-2022",
            "ES256" => "ecdsa-rdfc-2019",
            _ => {
                return Err(FormatterError::CouldNotFormat(format!(
                    "Unsupported algorithm: {algorithm}"
                )))
            }
        };

        let key_id = auth_fn.get_key_id().ok_or(FormatterError::CouldNotFormat(
            "Missing jwk key id".to_string(),
        ))?;

        let mut proof = json_ld::prepare_proof_config(
            "assertionMethod",
            cryptosuite,
            key_id,
            indexset![ContextType::Url(
                Context::CredentialsV2.to_string().parse().unwrap()
            )],
        )
        .await?;

        let proof_hash = prepare_proof_hash(
            &credential,
            &*self.crypto,
            &proof,
            self.caching_loader.to_owned(),
            None,
        )
        .await?;

        let signed_proof = sign_proof_hash(&proof_hash, auth_fn).await?;

        proof.proof_value = Some(signed_proof);
        // we remove the context proof since the same context is already present in the VC
        proof.context = None;
        credential.proof = Some(proof);

        let resp = serde_json::to_string(&credential)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        Ok(resp)
    }

    async fn extract_credentials(
        &self,
        credential: &str,
        verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(credential, Some(verification_fn))
            .await
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        Ok(credential.token)
    }

    async fn format_presentation(
        &self,
        tokens: &[String],
        holder_did: &DidValue,
        algorithm: &str,
        auth_fn: AuthenticationFn,
        ctx: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        let context = json_ld::prepare_context(vec![]);

        let formats = ctx.token_formats.map(|formats| {
            formats
                .into_iter()
                .filter_map(|format| {
                    ctx.vc_format_map
                        .get(&format)
                        .map(|format: &String| format.to_owned())
                })
                .collect::<Vec<String>>()
        });

        let verifiable_credential: VerifiableCredential = match formats {
            // Envelope if we know we should
            Some(formats) => tokens
                .iter()
                .zip(formats)
                .map(|(token, format)| match format.as_str() {
                    "ldp_vc" => serde_json::from_str(token),
                    _ => {
                        let enveloped = CredentialEnvelope::new(&format, token);
                        let json_value = serde_json::to_value(enveloped)?;
                        let map = json_value
                            .as_object()
                            .ok_or(serde_json::Error::custom("Credential must be an object"))?
                            .to_owned();
                        Ok(map)
                    }
                })
                .collect::<Result<_, _>>()
                .map_err(|err| FormatterError::CouldNotFormat(err.to_string()))?,
            // Assume json inside
            None => tokens
                .iter()
                .map(|token| serde_json::from_str(token))
                .collect::<Result<_, _>>()
                .map_err(|err| FormatterError::CouldNotFormat(err.to_string()))?,
        };

        let mut presentation = LdPresentation {
            context: context.clone(),
            r#type: ManyOrOne::One("VerifiablePresentation".to_string()),
            verifiable_credential,
            holder: Issuer::Url(holder_did.as_str().parse().unwrap()),
            nonce,
            proof: None,
            issuance_date: OffsetDateTime::now_utc(),
        };

        let cryptosuite = match algorithm {
            "EDDSA" => "eddsa-rdfc-2022",
            "ES256" => "ecdsa-rdfc-2019",
            _ => {
                return Err(FormatterError::CouldNotFormat(format!(
                    "Unsupported algorithm: {algorithm}"
                )))
            }
        };

        let key_id = auth_fn.get_key_id().ok_or(FormatterError::CouldNotFormat(
            "Missing jwk key id".to_string(),
        ))?;

        let mut proof =
            json_ld::prepare_proof_config("authentication", cryptosuite, key_id, context).await?;

        let proof_hash = prepare_proof_hash(
            &presentation,
            &*self.crypto,
            &proof,
            self.caching_loader.to_owned(),
            None,
        )
        .await?;

        let signed_proof = sign_proof_hash(&proof_hash, auth_fn).await?;

        proof.proof_value = Some(signed_proof);
        proof.context = None;
        presentation.proof = Some(proof);

        let resp = serde_json::to_string(&presentation)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        Ok(resp)
    }

    async fn extract_presentation(
        &self,
        json_ld: &str,
        verification_fn: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(json_ld, Some(verification_fn))
            .await
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway.whole_seconds() as u64
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_owned(), "ES256".to_owned()],
            features: vec!["SUPPORTS_CREDENTIAL_DESIGN".to_string()],
            selective_disclosure: vec![],
            issuance_did_methods: vec![
                "KEY".to_string(),
                "WEB".to_string(),
                "JWK".to_string(),
                "X509".to_string(),
            ],
            issuance_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            proof_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            revocation_methods: vec![
                "NONE".to_string(),
                "BITSTRINGSTATUSLIST".to_string(),
                "LVVC".to_string(),
            ],
            allowed_schema_ids: vec![],
            datatypes: vec![
                "STRING".to_string(),
                "BOOLEAN".to_string(),
                "EMAIL".to_string(),
                "DATE".to_string(),
                "STRING".to_string(),
                "COUNT".to_string(),
                "BIRTH_DATE".to_string(),
                "NUMBER".to_string(),
                "PICTURE".to_string(),
                "OBJECT".to_string(),
                "ARRAY".to_string(),
            ],
            verification_key_algorithms: vec!["EDDSA".to_string(), "ES256".to_string()],
            verification_key_storages: vec![
                "INTERNAL".to_string(),
                "AZURE_HSM".to_string(),
                "SECURE_ELEMENT".to_string(),
            ],
            forbidden_claim_names: [
                json_ld::jsonld_forbidden_claim_names(),
                vec!["0".to_string()],
            ]
            .concat(),
        }
    }

    async fn extract_presentation_unverified(
        &self,
        json_ld: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(json_ld, None).await
    }
}

impl JsonLdClassic {
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        base_url: Option<String>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        caching_loader: JsonLdCachingLoader,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            params,
            crypto,
            base_url,
            did_method_provider,
            caching_loader: ContextCache::new(caching_loader, client),
        }
    }

    async fn extract_credentials_internal(
        &self,
        credential: &str,
        verification_fn: Option<VerificationFn>,
    ) -> Result<DetailCredential, FormatterError> {
        let credential: LdCredential = serde_json::from_str(credential)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        if let Some(verification_fn) = verification_fn {
            verify_credential_signature(
                credential.clone(),
                verification_fn,
                &*self.crypto,
                self.caching_loader.to_owned(),
                None,
            )
            .await?;
        }

        // We only take first subject now as one credential only contains one credential schema
        let subject = credential
            .credential_subject
            .subject
            .values()
            .next()
            .ok_or(FormatterError::JsonMapping(
                "subject is not defined".to_string(),
            ))?
            .as_object()
            .ok_or(FormatterError::JsonMapping(
                "subject is not an Object".to_string(),
            ))?;

        let claims = CredentialSubject {
            values: subject
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        };

        Ok(DetailCredential {
            id: credential.id.map(|url| url.to_string()),
            valid_from: credential.valid_from.or(credential.issuance_date),
            valid_until: credential.valid_until,
            update_at: None,
            invalid_before: None,
            issuer_did: Some(credential.issuer.to_did_value()),
            subject: credential.credential_subject.id,
            claims,
            status: credential.credential_status,
            credential_schema: credential.credential_schema,
        })
    }

    async fn extract_presentation_internal(
        &self,
        json_ld: &str,
        verification_fn: Option<VerificationFn>,
    ) -> Result<Presentation, FormatterError> {
        let presentation: LdPresentation = serde_json::from_str(json_ld)
            .map_err(|e| FormatterError::CouldNotExtractPresentation(e.to_string()))?;

        if let Some(verification_fn) = verification_fn {
            verify_presentation_signature(
                presentation.clone(),
                verification_fn,
                &*self.crypto,
                self.caching_loader.to_owned(),
            )
            .await?;
        }

        let credentials: Vec<String> = presentation
            .verifiable_credential
            .iter()
            .map(|token| {
                if token.contains_key("type") && token["type"] == "EnvelopedVerifiableCredential" {
                    let enveloped: CredentialEnvelope =
                        serde_json::from_value(serde_json::Value::Object(token.to_owned()))?;

                    Ok(enveloped.get_token())
                } else {
                    serde_json::to_string(token)
                }
            })
            .collect::<Result<_, _>>()
            .map_err(|err| FormatterError::CouldNotExtractCredentials(err.to_string()))?;

        Ok(Presentation {
            id: None,
            issued_at: Some(presentation.issuance_date),
            expires_at: None,
            issuer_did: Some(presentation.holder.to_did_value()),
            nonce: presentation.nonce,
            credentials,
        })
    }
}

pub(super) async fn verify_credential_signature(
    mut ld_credential: LdCredential,
    verification_fn: VerificationFn,
    crypto: &dyn CryptoProvider,
    caching_loader: ContextCache,
    extra_information: Option<&[u8]>,
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

    // In case the node proof does not have a dedicated context, we should use the one from the credential
    if proof.context.is_none() {
        proof.context = Some(ld_credential.context.to_owned());
    }

    let proof_hash = prepare_proof_hash(
        &ld_credential,
        crypto,
        &proof,
        caching_loader,
        extra_information,
    )
    .await?;
    verify_proof_signature(
        &proof_hash,
        &proof_value,
        &issuer_did.to_did_value(),
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
    crypto: &dyn CryptoProvider,
    caching_loader: ContextCache,
) -> Result<(), FormatterError> {
    // Remove proof for canonicalization
    let mut proof = presentation
        .proof
        .take()
        .ok_or(FormatterError::CouldNotVerify("Missing proof".to_owned()))?;
    let proof_value = proof.proof_value.ok_or(FormatterError::CouldNotVerify(
        "Missing proof_value".to_owned(),
    ))?;
    let key_id = proof.verification_method.as_str();
    let issuer_did = &presentation.holder;

    if proof.context.is_none() {
        proof.context = Some(presentation.context.clone());
    }

    // Remove proof value for canonicalization
    proof.proof_value = None;

    let proof_hash =
        prepare_proof_hash(&presentation, crypto, &proof, caching_loader, None).await?;
    verify_proof_signature(
        &proof_hash,
        &proof_value,
        &issuer_did.to_did_value(),
        key_id,
        &proof.cryptosuite,
        verification_fn,
    )
    .await?;

    Ok(())
}

pub(super) async fn verify_proof_signature(
    proof_hash: &[u8],
    proof_value_bs58: &str,
    issuer_did: &DidValue,
    key_id: &str,
    cryptosuite: &str,
    verification_fn: VerificationFn,
) -> Result<(), FormatterError> {
    if !proof_value_bs58.starts_with('z') {
        return Err(FormatterError::CouldNotVerify(format!(
            "Only base58 multibase encoding is supported for suite {}",
            cryptosuite
        )));
    }

    let signature = bs58::decode(&proof_value_bs58[1..])
        .into_vec()
        .map_err(|_| FormatterError::CouldNotVerify("Hash decoding error".to_owned()))?;

    let algorithm = match cryptosuite {
        // todo: check if `eddsa-2022` is correct as the VCDM test suite is sending this
        "eddsa-rdfc-2022" | "eddsa-2022" => "EDDSA",
        "ecdsa-rdfc-2019" => "ES256",
        "ecdsa-xi-2023" => "ES256",
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
        .map_err(|e| FormatterError::CouldNotVerify(format!("Verification error: {e}")))?;

    Ok(())
}

pub(super) async fn sign_proof_hash(
    proof_hash: &[u8],
    auth_fn: AuthenticationFn,
) -> Result<String, FormatterError> {
    let signature = auth_fn
        .sign(proof_hash)
        .await
        .map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

    Ok(format!("z{}", bs58::encode(signature).into_string()))
}

pub(super) async fn prepare_proof_hash<T>(
    object: &T,
    crypto: &dyn CryptoProvider,
    proof: &LdProof,
    caching_loader: ContextCache,
    extra_information: Option<&[u8]>,
) -> Result<Vec<u8>, FormatterError>
where
    T: Serialize,
{
    let transformed_document = json_ld::canonize_any(object, caching_loader.clone()).await?;

    let transformed_proof_config = json_ld::canonize_any(proof, caching_loader).await?;

    let hashing_function = "sha-256";
    let hasher = crypto.get_hasher(hashing_function).map_err(|_| {
        FormatterError::CouldNotFormat(format!("Hasher {} unavailable", hashing_function))
    })?;

    let mut transformed_proof_config_hash = hasher
        .hash(transformed_proof_config.as_bytes())
        .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

    let transformed_document_hash = hasher
        .hash(transformed_document.as_bytes())
        .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

    transformed_proof_config_hash.extend(transformed_document_hash);

    if let Some(extra_information) = extra_information {
        let extra_information_hash = hasher
            .hash(extra_information)
            .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

        transformed_proof_config_hash.extend(extra_information_hash);
    }

    Ok(transformed_proof_config_hash)
}
