use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use itertools::Itertools;
use one_crypto::{Hasher, get_hasher};
use proc_macros::Provider;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{CredentialFormat, DidValue, RevocationMethodId, SerializedCredential};
use standardized_types::iana::HashAlgorithm;
use time::Duration;
use url::Url;
use uuid::Uuid;

use super::error::FormatterError;
use super::json_claims::{parse_claims, prepare_identifier};
use super::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential, Features,
    FormatterCapabilities, IdentifierDetails, Issuer, PublicKeySource, TokenVerifier,
    VerificationFn,
};
use super::vcdm::{VcdmCredential, VcdmCredentialSubject, VcdmProof, vcdm_metadata_claims};
use super::{CredentialFormatter, MetadataClaimSchema};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::error::ContextWithErrorCode;
use crate::model::credential::{CredentialCommon, CredentialStateEnum};
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::IdentifierData;
use crate::model::organisation::Organisation;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::json_ld_context::{ContextCache, JsonLdCachingLoader};
use crate::provider::credential_formatter::mapper::{
    default_2_years, first_certificate, to_format_with_mappings,
};
use crate::provider::credential_formatter::model::ParsedCredential;
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::key_selection::SelectedKey;
use crate::util::rdf_canonization::{json_ld_processor_options, rdf_canonize};
use crate::util::vcdm_jsonld_contexts::{is_context_list_valid, jsonld_forbidden_claim_names};
#[cfg(test)]
mod test;

#[derive(Provider)]
pub struct JsonLdClassic {
    config_id: CredentialFormat,
    caching_loader: ContextCache,
    data_type_provider: Arc<dyn DataTypeProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    params: Params,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway_seconds: Duration,
    #[serde(default)]
    embed_layout_properties: bool,
    allowed_contexts: Option<Vec<Url>>,
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "default_2_years")]
    expiration_seconds: Duration,
    revocation_method: Option<RevocationMethodId>,
}

#[async_trait]
impl CredentialFormatter for JsonLdClassic {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<SerializedCredential, FormatterError> {
        let mut vcdm = credential_data.credential.into_vcdm()?;

        let now = crate::clock::now_utc();
        if vcdm.valid_from.is_none() {
            vcdm.valid_from = Some(now);
        }

        let holder_did = match credential_data
            .holder_identifier
            .as_ref()
            .map(|identifier| &identifier.data)
        {
            Some(IdentifierData::Did(did)) => Some(did.as_ref().await?.did.clone().into_url()),
            _ => None,
        };

        if let Some(cs) = vcdm
            .credential_subject
            .first_mut()
            .filter(|cs| cs.id.is_none())
        {
            cs.id = holder_did;
        }

        let key_algorithm = auth_fn
            .get_key_algorithm()
            .error_while("getting key algorithm")?;

        if !self.params.embed_layout_properties {
            vcdm.remove_layout_properties();
        }

        let vcdm = self.add_proof(vcdm, key_algorithm, auth_fn).await?;

        Ok(serde_json::to_string(&vcdm)?.into())
    }

    async fn format_status_list<'a>(
        &self,
        revocation_list_url: String,
        issuer: SelectedKey,
        encoded_list: String,
        algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: RevocationType,
    ) -> Result<Vec<u8>, FormatterError> {
        if status_list_type != RevocationType::BitstringStatusList {
            return Err(FormatterError::CouldNotFormat(
                "Only BitstringStatusList can be formatted with JSON_LD_CLASSIC formatter"
                    .to_string(),
            ));
        }

        let SelectedKey::Did { did, .. } = issuer else {
            return Err(FormatterError::CouldNotFormat(
                "Status list issuer must be a DID".to_string(),
            ));
        };
        let issuer = Issuer::Url(did.did.clone().into_url());

        let credential_subject_id: Url = format!("{revocation_list_url}#list").parse()?;
        let credential_subject = VcdmCredentialSubject::new([
            ("type", json!("BitstringStatusList")),
            ("statusPurpose", json!(status_purpose)),
            ("encodedList", json!(encoded_list)),
        ])?
        .with_id(credential_subject_id);

        let credential_id = Url::parse(&revocation_list_url)?;

        let credential = VcdmCredential::new_v2(issuer, credential_subject)
            .with_id(credential_id)
            .add_type("BitstringStatusListCredential".to_string())
            .with_valid_from(crate::clock::now_utc());

        let credential = self.add_proof(credential, algorithm, auth_fn).await?;

        Ok(serde_json::to_string(&credential)?.into_bytes())
    }

    async fn extract_credentials<'a>(
        &self,
        credential: &SerializedCredential,
        _credential_schema: Option<&'a CredentialSchema>,
        verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(credential, Some(verification_fn))
            .await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        credential: &SerializedCredential,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(credential, None).await
    }

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        Ok(credential.token.into())
    }

    fn get_leeway(&self) -> Duration {
        self.params.leeway_seconds
    }

    fn get_default_expiration(&self) -> Duration {
        self.params.expiration_seconds
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![KeyAlgorithmType::Eddsa, KeyAlgorithmType::Ecdsa],
            features: vec![
                Features::SupportsCredentialDesign,
                Features::SupportsCombinedPresentation,
                Features::SupportsTxCode,
            ],
            selective_disclosure: vec![],
            issuance_did_methods: vec![
                DidType::Key,
                DidType::Web,
                DidType::Jwk,
                DidType::Tdw,
                DidType::Webvh,
            ],
            issuance_exchange_protocols: vec![IssuanceProtocolType::OpenId4VciFinal1_0],
            proof_exchange_protocols: vec![
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::OpenId4VpProximityDraft00,
            ],
            revocation_methods: vec![RevocationType::BitstringStatusList],
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
                "EAA_CATEGORY".to_string(),
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
            holder_did_methods: vec![
                DidType::Web,
                DidType::Key,
                DidType::Jwk,
                DidType::Tdw,
                DidType::Webvh,
            ],
        }
    }

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        vcdm_metadata_claims(None)
    }

    fn user_claims_path(&self) -> Vec<String> {
        vec!["credentialSubject".to_string()]
    }

    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<ParsedCredential, FormatterError> {
        let now = crate::clock::now_utc();

        let vcdm: VcdmCredential = serde_json::from_str(credential.as_ref())?;

        verify_credential_signature(
            vcdm.clone(),
            verification,
            self.caching_loader.to_owned(),
            None,
        )
        .await?;

        let revocation_method = if let Some(status) = vcdm.credential_status.first() {
            match status.r#type.as_str() {
                "BitstringStatusListEntry" => Some(RevocationType::BitstringStatusList),
                _ => {
                    return Err(FormatterError::CouldNotExtractCredentials(format!(
                        "Unknown revocation method: {}",
                        status.r#type
                    )));
                }
            }
        } else {
            None
        };

        let credential_id = Uuid::new_v4().into();
        let vc_types = vcdm.r#type.clone();
        let schema_name = vc_types
            .iter()
            .find(|t| t != &"VerifiableCredential")
            .cloned()
            .unwrap_or_else(|| "VerifiableCredential".to_string());

        let metadata_claims = vcdm.get_metadata_claims(
            &self
                .get_metadata_claims()
                .into_iter()
                .map(|c| c.key)
                .collect::<Vec<_>>(),
            &[],
        )?;

        // Parse claims from credential subject
        let credential_subject = vcdm.credential_subject.first().ok_or_else(|| {
            FormatterError::CouldNotExtractCredentials("Missing credential subject".to_string())
        })?;

        let (mut claims, mut claim_schemas) = parse_claims(
            HashMap::from_iter(credential_subject.claims.clone()),
            self.data_type_provider.as_ref(),
        )
        .await?;

        // Add parsed metadata claims
        let (metadata_claims, metadata_claim_schemas) =
            parse_claims(metadata_claims, self.data_type_provider.as_ref()).await?;
        claims.extend(metadata_claims);
        claim_schemas.extend(metadata_claim_schemas);

        let schema_id = vcdm
            .credential_schema
            .as_ref()
            .and_then(|schema| schema.first())
            .map(|s| s.id.clone())
            .unwrap_or_else(|| schema_name.clone());

        let credential_schema_id = Uuid::new_v4().into();
        let format = to_format_with_mappings(
            self.config_id.clone(),
            credential_schema_id,
            schema_id,
            &claim_schemas,
            now,
        );
        let schema = CredentialSchema {
            expiration: None,
            ecosystem: None,
            id: credential_schema_id,
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: schema_name,
            wallet_attestation: Default::default(),
            layout_properties: None,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            claim_schemas: claim_schemas.into(),
            organisation: organisation.clone().into(),
            transaction_code: None,
            formats: vec![format.clone()].into(),
            batch_size: None,
            allow_revocation: revocation_method.is_some(),
            translations: Default::default(),
            embedded_disclosure_policy: None,
        };

        let issuer_identifier = prepare_identifier(
            &IdentifierDetails::Did(vcdm.issuer.to_did_value()?),
            self.key_algorithm_provider.as_ref(),
            self.did_method_provider.as_ref(),
            organisation.to_owned(),
        )?;

        let credential_subject = vcdm.credential_subject.into_iter().next().ok_or_else(|| {
            FormatterError::CouldNotExtractCredentials(
                "Missing credential subject in JSON-LD credential".to_string(),
            )
        })?;
        let holder_identifier = credential_subject
            .id
            .and_then(|id| DidValue::from_did_url(id).ok())
            .map(IdentifierDetails::Did)
            .map(|details| {
                prepare_identifier(
                    &details,
                    self.key_algorithm_provider.as_ref(),
                    self.did_method_provider.as_ref(),
                    organisation,
                )
            })
            .transpose()?;

        Ok(ParsedCredential {
            common: CredentialCommon {
                expires_at: vcdm.valid_until.or(vcdm.expiration_date),
                ecosystem: None,
                id: credential_id,
                created_date: now,
                issuance_date: vcdm.issuance_date,
                last_modified: now,
                deleted_at: None,
                protocol: "".to_string(),
                redirect_uri: None,
                state: CredentialStateEnum::Accepted,
                profile: None,
                schema: schema.into(),
                interaction: None,
            },
            claims: claims.into(),
            issuer: crate::model::credential::IssuerIdentity {
                certificate: first_certificate(&issuer_identifier).await?.map(Into::into),
                identifier: issuer_identifier.into(),
            },
            holder_identifier: holder_identifier.map(Into::into),
            format: format.into(),
        })
    }

    fn revocation_method_id(&self) -> Option<&RevocationMethodId> {
        self.params.revocation_method.as_ref()
    }

    fn config_name(&self) -> &CredentialFormat {
        &self.config_id
    }
}

impl JsonLdClassic {
    pub fn new(
        config_id: CredentialFormat,
        params: serde_json::Value,
        caching_loader: JsonLdCachingLoader,
        data_type_provider: Arc<dyn DataTypeProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_id,
            params,
            caching_loader: ContextCache::new(caching_loader, client),
            data_type_provider,
            key_algorithm_provider,
            did_method_provider,
        })
    }

    async fn extract_credentials_internal(
        &self,
        credential: &SerializedCredential,
        verification_fn: Option<VerificationFn>,
    ) -> Result<DetailCredential, FormatterError> {
        let vcdm: VcdmCredential = serde_json::from_str(credential.as_ref())?;

        if let Some(verification_fn) = verification_fn {
            verify_credential_signature(
                vcdm.clone(),
                verification_fn,
                self.caching_loader.to_owned(),
                None,
            )
            .await?;
        }

        is_context_list_valid(
            &vcdm.context,
            self.params.allowed_contexts.as_ref(),
            vcdm.credential_schema.as_ref(),
        )?;

        let metadata_claims = vcdm.get_metadata_claims(
            &self
                .get_metadata_claims()
                .into_iter()
                .map(|c| c.key)
                .collect::<Vec<_>>(),
            &[],
        )?;
        // We only take first subject now as one credential only contains one credential schema
        let credential_subject = vcdm.credential_subject.into_iter().next().ok_or_else(|| {
            FormatterError::CouldNotExtractCredentials(
                "Missing credential subject in JSON-LD credential".to_string(),
            )
        })?;

        let mut claims = HashMap::from_iter(credential_subject.claims);
        claims.extend(metadata_claims);

        Ok(DetailCredential {
            issuance_date: vcdm.proof.and_then(|proof| proof.created),
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
            .created(crate::clock::now_utc())
            .proof_purpose("assertionMethod")
            .cryptosuite(cryptosuite)
            .verification_method(key_id)
            .build();

        let proof_hash = prepare_proof_hash(
            &vcdm,
            &proof,
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

    let signature = bs58::decode(&proof_value_bs58[1..]).into_vec()?;

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
        .error_while("verifying")?;

    Ok(())
}

pub(crate) async fn sign_proof_hash(
    proof_hash: &[u8],
    auth_fn: AuthenticationFn,
) -> Result<String, FormatterError> {
    let signature = auth_fn.sign(proof_hash).await.error_while("signing")?;

    Ok(format!("z{}", bs58::encode(signature).into_string()))
}

pub(crate) async fn prepare_proof_hash(
    document: &impl Serialize,
    proof: &VcdmProof,
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
            .map(|bytes| Ok(hasher.hash(bytes)?))
            .flatten_ok()
            .try_collect()
    }

    let hashing_function = HashAlgorithm::Sha256;
    let hasher = get_hasher(hashing_function)?;

    let transformed_document = rdf_canonize(document, &caching_loader, options.clone()).await?;
    let transformed_proof_config = rdf_canonize(proof, &caching_loader, options).await?;

    proof_hash(
        &*hasher,
        transformed_document.as_bytes(),
        transformed_proof_config.as_bytes(),
        extra_information,
    )
}
