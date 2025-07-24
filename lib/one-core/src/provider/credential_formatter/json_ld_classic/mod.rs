use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use itertools::Itertools;
use one_crypto::{CryptoProvider, Hasher};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::{DurationSeconds, serde_as};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use url::Url;

use super::model::{CredentialData, HolderBindingCtx, IdentifierDetails, PublicKeySource};
use super::vcdm::{VcdmCredential, VcdmCredentialSubject, VcdmProof};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::Identifier;
use crate::model::revocation_list::StatusListType;
use crate::provider::caching_loader::json_ld_context::{ContextCache, JsonLdCachingLoader};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialPresentation, CredentialSubject, DetailCredential, Features,
    FormatterCapabilities, Issuer, VerificationFn,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::rdf_canonization::{json_ld_processor_options, rdf_canonize};
use crate::util::vcdm_jsonld_contexts::{
    DEFAULT_ALLOWED_CONTEXTS, is_context_list_valid, jsonld_forbidden_claim_names,
};
#[cfg(test)]
mod test;

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
    #[serde(default)]
    embed_layout_properties: bool,
    allowed_contexts: Option<Vec<Url>>,
}

#[async_trait]
impl CredentialFormatter for JsonLdClassic {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let mut vcdm = credential_data.vcdm;

        let holder_did = credential_data
            .holder_identifier
            .as_ref()
            .and_then(|identifier| identifier.did.as_ref())
            .map(|did| did.did.clone().into_url());

        if let Some(cs) = vcdm
            .credential_subject
            .first_mut()
            .filter(|cs| cs.id.is_none())
        {
            cs.id = holder_did;
        }

        let key_algorithm = auth_fn.get_key_algorithm().map_err(|key_type| {
            FormatterError::CouldNotFormat(format!("Unsupported algorithm: {key_type}"))
        })?;

        if !self.params.embed_layout_properties {
            vcdm.remove_layout_properties();
        }

        let vcdm = self.add_proof(vcdm, key_algorithm, auth_fn).await?;

        serde_json::to_string(&vcdm).map_err(|e| FormatterError::CouldNotFormat(e.to_string()))
    }

    async fn format_status_list(
        &self,
        revocation_list_url: String,
        issuer_identifier: &Identifier,
        encoded_list: String,
        algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        if status_list_type != StatusListType::BitstringStatusList {
            return Err(FormatterError::Failed(
                "Only BitstringStatusList can be formatted with JSON_LD_CLASSIC formatter"
                    .to_string(),
            ));
        }

        let issuer = issuer_identifier
            .as_url()
            .map(Issuer::Url)
            .ok_or(FormatterError::Failed("Invalid issuer DID".to_string()))?;

        let credential_subject_id: Url =
            format!("{revocation_list_url}#list").parse().map_err(|_| {
                FormatterError::Failed("Invalid issuer credential subject id".to_string())
            })?;
        let credential_subject = VcdmCredentialSubject::new([
            ("type", json!("BitstringStatusList")),
            ("statusPurpose", json!(status_purpose)),
            ("encodedList", json!(encoded_list)),
        ])
        .with_id(credential_subject_id);

        let credential_id = Url::parse(&revocation_list_url).map_err(|_| {
            FormatterError::Failed("Revocation list is not a valid URL".to_string())
        })?;

        let credential = VcdmCredential::new_v2(issuer, credential_subject)
            .with_id(credential_id)
            .add_type("BitstringStatusListCredential".to_string())
            .with_valid_from(OffsetDateTime::now_utc());

        let credential = self.add_proof(credential, algorithm, auth_fn).await?;

        serde_json::to_string(&credential).map_err(|err| {
            FormatterError::Failed(format!(
                "Failed formatting BitstringStatusList credential {err}"
            ))
        })
    }

    async fn extract_credentials<'a>(
        &self,
        credential: &str,
        _credential_schema: Option<&'a CredentialSchema>,
        verification_fn: VerificationFn,
        _holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(credential, Some(verification_fn))
            .await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        credential: &str,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(credential, None).await
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
        _holder_binding_ctx: Option<HolderBindingCtx>,
        _holder_binding_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError> {
        Ok(credential.token)
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway.whole_seconds() as u64
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![KeyAlgorithmType::Eddsa, KeyAlgorithmType::Ecdsa],
            features: vec![Features::SupportsCredentialDesign],
            selective_disclosure: vec![],
            issuance_did_methods: vec![DidType::Key, DidType::Web, DidType::Jwk, DidType::WebVh],
            issuance_exchange_protocols: vec![IssuanceProtocolType::OpenId4VciDraft13],
            proof_exchange_protocols: vec![
                VerificationProtocolType::OpenId4VpDraft20,
                VerificationProtocolType::OpenId4VpDraft25,
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::OpenId4VpProximityDraft00,
            ],
            revocation_methods: vec![
                RevocationType::None,
                RevocationType::BitstringStatusList,
                RevocationType::Lvvc,
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
            verification_key_algorithms: vec![KeyAlgorithmType::Eddsa, KeyAlgorithmType::Ecdsa],
            verification_key_storages: vec![
                KeyStorageType::Internal,
                KeyStorageType::AzureVault,
                KeyStorageType::SecureElement,
            ],
            forbidden_claim_names: [jsonld_forbidden_claim_names(), vec!["0".to_string()]].concat(),
            issuance_identifier_types: vec![IdentifierType::Did],
            verification_identifier_types: vec![IdentifierType::Did, IdentifierType::Certificate],
            holder_identifier_types: vec![IdentifierType::Did],
            holder_key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            holder_did_methods: vec![DidType::Web, DidType::Key, DidType::Jwk, DidType::WebVh],
        }
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
        let vcdm: VcdmCredential = serde_json::from_str(credential)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        if let Some(verification_fn) = verification_fn {
            verify_credential_signature(
                vcdm.clone(),
                verification_fn,
                &*self.crypto,
                self.caching_loader.to_owned(),
                None,
            )
            .await?;
        }

        if !is_context_list_valid(
            &vcdm.context,
            self.params.allowed_contexts.as_ref(),
            &DEFAULT_ALLOWED_CONTEXTS,
            vcdm.credential_schema.as_ref(),
            vcdm.id.as_ref(),
        ) {
            return Err(FormatterError::CouldNotVerify(
                "Used context is not allowed".to_string(),
            ));
        }

        // We only take first subject now as one credential only contains one credential schema
        let credential_subject = vcdm.credential_subject.into_iter().next().ok_or_else(|| {
            FormatterError::CouldNotExtractCredentials(
                "Missing credential subject in JSON-LD credential".to_string(),
            )
        })?;

        let claims = CredentialSubject {
            id: credential_subject.id.clone(),
            claims: HashMap::from_iter(credential_subject.claims),
        };

        Ok(DetailCredential {
            id: vcdm.id.map(|url| url.to_string()),
            valid_from: vcdm.valid_from.or(vcdm.issuance_date),
            valid_until: vcdm.valid_until.or(vcdm.expiration_date),
            update_at: None,
            invalid_before: None,
            issuer: IdentifierDetails::Did(vcdm.issuer.to_did_value()?),
            subject: credential_subject
                .id
                .and_then(|id| DidValue::from_did_url(id).ok())
                .map(IdentifierDetails::Did),
            claims,
            status: vcdm.credential_status,
            credential_schema: vcdm.credential_schema.map(|v| v[0].clone()),
        })
    }

    async fn add_proof(
        &self,
        mut vcdm: VcdmCredential,
        algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
    ) -> Result<VcdmCredential, FormatterError> {
        let cryptosuite = match algorithm {
            KeyAlgorithmType::Eddsa => "eddsa-rdfc-2022",
            KeyAlgorithmType::Ecdsa => "ecdsa-rdfc-2019",
            _ => {
                return Err(FormatterError::CouldNotFormat(format!(
                    "Unsupported algorithm: {algorithm}"
                )));
            }
        };

        let key_id = auth_fn.get_key_id().ok_or(FormatterError::CouldNotFormat(
            "Missing jwk key id".to_string(),
        ))?;

        let mut proof = VcdmProof::builder()
            .context(vcdm.context.clone())
            .created(OffsetDateTime::now_utc())
            .proof_purpose("assertionMethod")
            .cryptosuite(cryptosuite)
            .verification_method(key_id)
            .build();

        let proof_hash = prepare_proof_hash(
            &vcdm,
            &proof,
            &*self.crypto,
            self.caching_loader.to_owned(),
            None,
            json_ld_processor_options(),
        )
        .await?;

        let signed_proof = sign_proof_hash(&proof_hash, auth_fn).await?;

        proof.proof_value = Some(signed_proof);
        // we remove the context proof since the same context is already present in the VC
        proof.context = None;
        vcdm.proof = Some(proof);

        Ok(vcdm)
    }
}

pub(super) async fn verify_credential_signature(
    mut vcdm: VcdmCredential,
    verification_fn: VerificationFn,
    crypto: &dyn CryptoProvider,
    caching_loader: ContextCache,
    extra_information: Option<&[u8]>,
) -> Result<(), FormatterError> {
    let mut proof = vcdm
        .proof
        .as_ref()
        .ok_or(FormatterError::CouldNotVerify("Missing proof".to_owned()))?
        .clone();
    let proof_value = proof.proof_value.ok_or(FormatterError::CouldNotVerify(
        "Missing proof_value".to_owned(),
    ))?;
    let key_id = proof.verification_method.as_str();
    let issuer_did = vcdm.issuer.to_did_value()?;

    // Remove proof value and proof for canonicalization
    proof.proof_value = None;
    vcdm.proof = None;

    // In case the node proof does not have a dedicated context, we should use the one from the credential
    if proof.context.is_none() {
        proof.context = Some(vcdm.context.to_owned());
    }

    let proof_hash = prepare_proof_hash(
        &vcdm,
        &proof,
        crypto,
        caching_loader,
        extra_information,
        json_ld_processor_options(),
    )
    .await?;
    verify_proof_signature(
        &proof_hash,
        &proof_value,
        &issuer_did,
        key_id,
        &proof.cryptosuite,
        verification_fn,
    )
    .await?;

    Ok(())
}

pub(crate) async fn verify_proof_signature(
    proof_hash: &[u8],
    proof_value_bs58: &str,
    issuer_did: &DidValue,
    key_id: &str,
    cryptosuite: &str,
    verification_fn: VerificationFn,
) -> Result<(), FormatterError> {
    if !proof_value_bs58.starts_with('z') {
        return Err(FormatterError::CouldNotVerify(format!(
            "Only base58 multibase encoding is supported for suite {cryptosuite}"
        )));
    }

    let signature = bs58::decode(&proof_value_bs58[1..])
        .into_vec()
        .map_err(|_| FormatterError::CouldNotVerify("Hash decoding error".to_owned()))?;

    let algorithm = match cryptosuite {
        // todo: check if `eddsa-2022` is correct as the VCDM test suite is sending this
        "eddsa-rdfc-2022" | "eddsa-2022" => KeyAlgorithmType::Eddsa,
        "ecdsa-rdfc-2019" | "ecdsa-xi-2023" => KeyAlgorithmType::Ecdsa,
        _ => {
            return Err(FormatterError::CouldNotVerify(format!(
                "Unsupported cryptosuite: {cryptosuite}"
            )));
        }
    };

    let params = PublicKeySource::Did {
        did: Cow::Borrowed(issuer_did),
        key_id: Some(key_id),
    };
    verification_fn
        .verify(params, algorithm, proof_hash, &signature)
        .await
        .map_err(|e| FormatterError::CouldNotVerify(format!("Verification error: {e}")))?;

    Ok(())
}

pub(crate) async fn sign_proof_hash(
    proof_hash: &[u8],
    auth_fn: AuthenticationFn,
) -> Result<String, FormatterError> {
    let signature = auth_fn
        .sign(proof_hash)
        .await
        .map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

    Ok(format!("z{}", bs58::encode(signature).into_string()))
}

pub(crate) async fn prepare_proof_hash(
    document: &impl Serialize,
    proof: &VcdmProof,
    crypto: &dyn CryptoProvider,
    caching_loader: ContextCache,
    extra_information: Option<&[u8]>,
    options: json_ld::Options,
) -> Result<Vec<u8>, FormatterError> {
    fn proof_hash(
        hasher: &dyn Hasher,
        document: &[u8],
        proof: &[u8],
        extra_information: Option<&[u8]>,
    ) -> Result<Vec<u8>, FormatterError> {
        [proof, document]
            .into_iter()
            .chain(extra_information)
            .map(|bytes| {
                hasher
                    .hash(bytes)
                    .map_err(|err| FormatterError::CouldNotFormat(format!("Hasher error: `{err}`")))
            })
            .flatten_ok()
            .try_collect()
    }

    let hashing_function = "sha-256";
    let hasher = crypto.get_hasher(hashing_function).map_err(|_| {
        FormatterError::CouldNotFormat(format!("Hasher {hashing_function} unavailable"))
    })?;

    let transformed_document = rdf_canonize(document, &caching_loader, options.clone()).await?;
    let transformed_proof_config = rdf_canonize(proof, &caching_loader, options).await?;

    proof_hash(
        &*hasher,
        transformed_document.as_bytes(),
        transformed_proof_config.as_bytes(),
        extra_information,
    )
}
