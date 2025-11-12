//! Implementation of JSON-LD credential format with BBS+ signatures, allowing for selective disclosure.
//! https://www.w3.org/TR/vc-di-bbs/

use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use mapper::convert_to_detail_credential;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use serde_json::json;
use serde_with::{DurationSeconds, serde_as};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use verify_proof::extract_mandatory_pointers;

use super::error::FormatterError;
use super::json_claims::{parse_claims, prepare_identifier};
use super::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential, Features,
    FormatterCapabilities, HolderBindingCtx, IdentifierDetails, Issuer, SelectiveDisclosure,
    VerificationFn,
};
use super::vcdm::{VcdmCredential, VcdmCredentialSubject, vcdm_metadata_claims};
use super::{CredentialFormatter, MetadataClaimSchema};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::identifier::Identifier;
use crate::model::revocation_list::StatusListType;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::json_ld_context::{ContextCache, JsonLdCachingLoader};
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::rdf_canonization::json_ld_processor_options;
use crate::util::vcdm_jsonld_contexts::jsonld_forbidden_claim_names;

mod data_integrity;
mod mapper;
pub mod model;
mod verify_proof;

#[cfg(test)]
mod test;

pub struct JsonLdBbsplus {
    crypto: Arc<dyn CryptoProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    data_type_provider: Arc<dyn DataTypeProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    caching_loader: ContextCache,
    params: Params,
}

#[serde_with::serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway: Duration,
    #[serde(default)]
    pub embed_layout_properties: bool,
    pub allowed_contexts: Option<Vec<Url>>,
}

impl JsonLdBbsplus {
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        data_type_provider: Arc<dyn DataTypeProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        caching_loader: JsonLdCachingLoader,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            params,
            crypto,
            did_method_provider,
            data_type_provider,
            key_algorithm_provider,
            caching_loader: ContextCache::new(caching_loader, client),
        }
    }
}

#[async_trait]
impl CredentialFormatter for JsonLdBbsplus {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        if auth_fn.get_key_algorithm() != Ok(KeyAlgorithmType::BbsPlus) {
            return Err(FormatterError::BBSOnly);
        }

        let verification_method = auth_fn
            .get_key_id()
            .ok_or_else(|| FormatterError::CouldNotFormat("Missing jwk key id".to_string()))?;

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

        let mandatory_pointers = generate_mandatory_pointers(&vcdm);
        let proof = data_integrity::create_base_proof(
            &vcdm,
            mandatory_pointers,
            verification_method,
            &self.caching_loader,
            &*self.crypto.get_hasher("sha-256")?,
            &*auth_fn,
            json_ld_processor_options(),
        )
        .await?;

        vcdm.proof = Some(proof);

        serde_json::to_string(&vcdm).map_err(|e| FormatterError::CouldNotFormat(e.to_string()))
    }

    async fn format_status_list(
        &self,
        revocation_list_url: String,
        issuer_identifier: &Identifier,
        encoded_list: String,
        _algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        if status_list_type != StatusListType::BitstringStatusList {
            return Err(FormatterError::Failed(
                "Only BitstringStatusList can be formatted with JSON_LD_BBSPLUS formatter"
                    .to_string(),
            ));
        }
        if auth_fn.get_key_algorithm() != Ok(KeyAlgorithmType::BbsPlus) {
            return Err(FormatterError::BBSOnly);
        }

        let issuer = Issuer::Url(
            issuer_identifier
                .as_url()
                .ok_or(FormatterError::Failed("Invalid issuer DID".to_string()))?,
        );

        let credential_subject_id: Url =
            format!("{revocation_list_url}#list").parse().map_err(|_| {
                FormatterError::Failed("Invalid issuer credential subject id".to_string())
            })?;
        let credential_subject = VcdmCredentialSubject::new([
            ("type", json!("BitstringStatusList")),
            ("statusPurpose", json!(status_purpose)),
            ("encodedList", json!(encoded_list)),
        ])?
        .with_id(credential_subject_id);

        let credential_id = Url::parse(&revocation_list_url).map_err(|_| {
            FormatterError::Failed("Revocation list is not a valid URL".to_string())
        })?;

        let mut vcdm = VcdmCredential::new_v2(issuer, credential_subject)
            .with_id(credential_id)
            .add_type("BitstringStatusListCredential".to_string())
            .with_valid_from(OffsetDateTime::now_utc());

        let verification_method = auth_fn
            .get_key_id()
            .ok_or_else(|| FormatterError::CouldNotFormat("Missing jwk key id".to_string()))?;

        let mut mandatory_pointers = generate_mandatory_pointers(&vcdm);
        mandatory_pointers.push("/credentialSubject".to_string());

        let proof = data_integrity::create_base_proof(
            &vcdm,
            mandatory_pointers,
            verification_method,
            &self.caching_loader,
            &*self.crypto.get_hasher("sha-256")?,
            &*auth_fn,
            json_ld_processor_options(),
        )
        .await?;

        vcdm.proof = Some(proof);

        serde_json::to_string(&vcdm).map_err(|e| FormatterError::CouldNotFormat(e.to_string()))
    }

    async fn extract_credentials<'a>(
        &self,
        credential: &str,
        _credential_schema: Option<&'a CredentialSchema>,
        verification_fn: VerificationFn,
        _holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        self.verify(credential, verification_fn).await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        credential: &str,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        let vc: VcdmCredential = serde_json::from_str(credential).map_err(|e| {
            FormatterError::CouldNotVerify(format!("Could not deserialize base proof: {e}"))
        })?;

        let metadata_claims = self
            .get_metadata_claims()
            .into_iter()
            .map(|c| c.key)
            .collect::<Vec<_>>();
        let mandatory_pointers = extract_mandatory_pointers(&vc)?;
        convert_to_detail_credential(vc, mandatory_pointers, &metadata_claims)
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
        _holder_binding_ctx: Option<HolderBindingCtx>,
        _holder_binding_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError> {
        let mut vcdm: VcdmCredential = serde_json::from_str(&credential.token).map_err(|e| {
            FormatterError::CouldNotFormat(format!("Could not deserialize base proof: {e}"))
        })?;

        let Some(proof) = vcdm.proof.take() else {
            return Err(FormatterError::CouldNotFormat("Missing proof".to_string()));
        };

        if proof.cryptosuite != "bbs-2023" {
            return Err(FormatterError::CouldNotFormat(
                "Incorrect cryptosuite".to_string(),
            ));
        }

        let disclosed_keys = credential
            .disclosed_keys
            .into_iter()
            .map(|key| {
                if key.starts_with("/") {
                    format!("/credentialSubject{key}")
                } else {
                    format!("/credentialSubject/{key}")
                }
            })
            .collect();
        let revealed_document = data_integrity::add_derived_proof(
            &vcdm,
            &proof,
            disclosed_keys,
            None,
            &self.caching_loader,
            json_ld_processor_options(),
        )
        .await?;

        let resp = serde_json::to_string(&revealed_document)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        Ok(resp)
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway.whole_seconds() as u64
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![KeyAlgorithmType::BbsPlus],
            features: vec![
                Features::SupportsCredentialDesign,
                Features::SelectiveDisclosure,
                Features::SupportsCombinedPresentation,
            ],
            selective_disclosure: vec![SelectiveDisclosure::AnyLevel],
            issuance_did_methods: vec![DidType::Key, DidType::Web, DidType::Jwk, DidType::WebVh],
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
            issuance_exchange_protocols: vec![
                IssuanceProtocolType::OpenId4VciDraft13,
                IssuanceProtocolType::OpenId4VciFinal1_0,
            ],
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
            verification_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Dilithium,
            ],
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

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        let selectively_disclosable_vcdm_claims = vec![
            // VCDM 2.0
            MetadataClaimSchema {
                key: "validFrom".to_string(),
                data_type: "DATE".to_string(),
                array: false,
                required: false,
            },
            MetadataClaimSchema {
                key: "validUntil".to_string(),
                data_type: "DATE".to_string(),
                array: false,
                required: false,
            },
            // VCDM v1.1
            MetadataClaimSchema {
                key: "issuanceDate".to_string(),
                data_type: "DATE".to_string(),
                array: false,
                required: false,
            },
            MetadataClaimSchema {
                key: "expirationDate".to_string(),
                data_type: "DATE".to_string(),
                array: false,
                required: false,
            },
        ];

        [
            vcdm_metadata_claims(None),
            selectively_disclosable_vcdm_claims,
        ]
        .concat()
    }

    fn user_claims_path(&self) -> Vec<String> {
        vec!["credentialSubject".to_string()]
    }

    async fn parse_credential(&self, credential: &str) -> Result<Credential, FormatterError> {
        let now = OffsetDateTime::now_utc();

        let vcdm: VcdmCredential = serde_json::from_str(credential).map_err(|e| {
            FormatterError::CouldNotVerify(format!("Could not deserialize base proof: {e}"))
        })?;

        let revocation_method = if let Some(status) = vcdm.credential_status.first() {
            match status.r#type.as_str() {
                "LVVC" => RevocationType::Lvvc,
                "BitstringStatusListEntry" => RevocationType::BitstringStatusList,
                _ => {
                    return Err(FormatterError::Failed(format!(
                        "Unknown revocation method: {}",
                        status.r#type
                    )));
                }
            }
        } else {
            RevocationType::None
        };

        let metadata_claims = vcdm.get_metadata_claims(
            &self
                .get_metadata_claims()
                .into_iter()
                .map(|c| c.key)
                .collect::<Vec<_>>(),
            &[],
        )?;
        let vc_types = vcdm.r#type;
        let schema_name = vc_types
            .iter()
            .find(|t| t != &"VerifiableCredential")
            .cloned()
            .unwrap_or_else(|| "VerifiableCredential".to_string());

        // Parse claims from credential subject
        let credential_subject = vcdm
            .credential_subject
            .first()
            .ok_or_else(|| FormatterError::Failed("Missing credential subject".to_string()))?;

        let credential_id = Uuid::new_v4().into();
        let (mut claims, mut claim_schemas) = parse_claims(
            HashMap::from_iter(credential_subject.claims.clone()),
            self.data_type_provider.as_ref(),
            credential_id,
        )?;

        // Add parsed metadata claims
        let (metadata_claims, metadata_claim_schemas) = parse_claims(
            metadata_claims,
            self.data_type_provider.as_ref(),
            credential_id,
        )?;
        claims.extend(metadata_claims);
        claim_schemas.extend(metadata_claim_schemas);

        let schema_id = vcdm
            .credential_schema
            .as_ref()
            .and_then(|schema| schema.first())
            .map(|s| s.id.clone())
            .unwrap_or_else(|| schema_name.clone());

        let schema = CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: schema_name,
            format: "JSON_LD_BBSPLUS".to_string(),
            revocation_method: revocation_method.to_string(),
            wallet_storage_type: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            requires_app_attestation: false,
            claim_schemas: Some(claim_schemas),
            organisation: None,
        };

        let issuer_identifier = prepare_identifier(
            &IdentifierDetails::Did(vcdm.issuer.to_did_value()?),
            self.key_algorithm_provider.as_ref(),
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
            .map(|details| prepare_identifier(&details, self.key_algorithm_provider.as_ref()))
            .transpose()?;

        Ok(Credential {
            id: credential_id,
            created_date: now,
            issuance_date: vcdm.issuance_date,
            last_modified: now,
            deleted_at: None,
            protocol: "".to_string(),
            redirect_uri: None,
            role: CredentialRole::Holder,
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
            profile: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
            wallet_app_attestation_blob_id: None,
            claims: Some(claims),
            issuer_certificate: issuer_identifier
                .certificates
                .as_ref()
                .and_then(|certs| certs.first().cloned()),
            issuer_identifier: Some(issuer_identifier),
            holder_identifier,
            schema: Some(schema),
            interaction: None,
            key: None,
        })
    }
}

fn generate_mandatory_pointers(vcdm: &VcdmCredential) -> Vec<String> {
    let mut pointers = vec!["/issuer", "/type"];

    if !vcdm.credential_status.is_empty() {
        pointers.push("/credentialStatus");
    }

    if vcdm.id.is_some() {
        pointers.push("/id");
    }

    if vcdm.valid_from.is_some() {
        pointers.push("/validFrom");
    }

    if vcdm.valid_until.is_some() {
        pointers.push("/validUntil");
    }

    if vcdm.issuance_date.is_some() {
        pointers.push("/issuanceDate");
    }

    if vcdm.expiration_date.is_some() {
        pointers.push("/expirationDate");
    }

    if vcdm.credential_schema.is_some() {
        pointers.push("/credentialSchema");
    }

    if vcdm.name.is_some() {
        pointers.push("/name");
    }

    if vcdm.description.is_some() {
        pointers.push("/description");
    }

    if vcdm.evidence.is_some() {
        pointers.push("/evidence");
    }

    if vcdm.terms_of_use.is_some() {
        pointers.push("/termsOfUse");
    }

    if vcdm.refresh_service.is_some() {
        pointers.push("/refreshService");
    }

    pointers.iter().map(ToString::to_string).collect()
}
