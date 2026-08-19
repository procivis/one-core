//! Implementation of JSON-LD credential format with BBS+ signatures, allowing for selective disclosure.
//! https://www.w3.org/TR/vc-di-bbs/

use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use mapper::convert_to_detail_credential;
use one_crypto::CryptoProvider;
use proc_macros::Provider;
use serde::Deserialize;
use serde_json::json;
use serde_with::DurationSeconds;
use shared_types::{CredentialFormat, DidValue, RevocationMethodId, SerializedCredential};
use time::Duration;
use url::Url;
use uuid::Uuid;
use verify_proof::extract_mandatory_pointers;

use super::error::FormatterError;
use super::json_claims::{parse_claims, prepare_identifier};
use super::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential, Features,
    FormatterCapabilities, IdentifierDetails, Issuer, SelectiveDisclosure, TokenVerifier,
    VerificationFn,
};
use super::vcdm::{VcdmCredential, VcdmCredentialSubject, vcdm_metadata_claims};
use super::{CredentialFormatter, MetadataClaimSchema};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::identifier::IdentifierData;
use crate::model::organisation::Organisation;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::json_ld_context::{ContextCache, JsonLdCachingLoader};
use crate::provider::credential_formatter::json_ld_bbsplus::mapper::{
    mark_claims_selectively_disclosable, metadata_claims_with_sd_flags,
};
use crate::provider::credential_formatter::mapper::{
    default_2_years, first_certificate, to_format_with_mappings,
};
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::key_selection::SelectedKey;
use crate::util::rdf_canonization::json_ld_processor_options;
use crate::util::vcdm_jsonld_contexts::jsonld_forbidden_claim_names;

mod data_integrity;
mod mapper;
pub mod model;
mod verify_proof;

#[cfg(test)]
mod test;

#[derive(Provider)]
pub struct JsonLdBbsplus {
    config_id: CredentialFormat,
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
struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway_seconds: Duration,
    #[serde(default)]
    #[expect(unused)]
    embed_layout_properties: bool,
    allowed_contexts: Option<Vec<Url>>,
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "default_2_years")]
    expiration_seconds: Duration,
    revocation_method: Option<RevocationMethodId>,
}

impl JsonLdBbsplus {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        config_id: CredentialFormat,
        params: serde_json::Value,
        crypto: Arc<dyn CryptoProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        data_type_provider: Arc<dyn DataTypeProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        caching_loader: JsonLdCachingLoader,
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
            crypto,
            did_method_provider,
            data_type_provider,
            key_algorithm_provider,
            caching_loader: ContextCache::new(caching_loader, client),
        })
    }
}

#[async_trait]
impl CredentialFormatter for JsonLdBbsplus {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<SerializedCredential, FormatterError> {
        if let Ok(alg) = auth_fn.get_key_algorithm()
            && alg != KeyAlgorithmType::BbsPlus
        {
            return Err(FormatterError::BBSOnly);
        }

        let verification_method = auth_fn
            .get_key_id()
            .ok_or_else(|| FormatterError::CouldNotFormat("Missing jwk key id".to_string()))?;

        let mut vcdm = credential_data.vcdm;

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

        let mandatory_pointers = generate_mandatory_pointers(&vcdm);
        let proof = data_integrity::base_proof::create_base_proof(
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

        Ok(serde_json::to_string(&vcdm)?.into())
    }

    async fn format_status_list<'a>(
        &self,
        revocation_list_url: String,
        issuer: SelectedKey,
        encoded_list: String,
        _algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: RevocationType,
    ) -> Result<Vec<u8>, FormatterError> {
        if status_list_type != RevocationType::BitstringStatusList {
            return Err(FormatterError::CouldNotFormat(
                "Only BitstringStatusList can be formatted with JSON_LD_BBSPLUS formatter"
                    .to_string(),
            ));
        }
        if let Ok(alg) = auth_fn.get_key_algorithm()
            && alg != KeyAlgorithmType::BbsPlus
        {
            return Err(FormatterError::BBSOnly);
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

        let mut vcdm = VcdmCredential::new_v2(issuer, credential_subject)
            .with_id(credential_id)
            .add_type("BitstringStatusListCredential".to_string())
            .with_valid_from(crate::clock::now_utc());

        let verification_method = auth_fn
            .get_key_id()
            .ok_or_else(|| FormatterError::CouldNotFormat("Missing jwk key id".to_string()))?;

        let mut mandatory_pointers = generate_mandatory_pointers(&vcdm);
        mandatory_pointers.push("/credentialSubject".to_string());

        let proof = data_integrity::base_proof::create_base_proof(
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

        Ok(serde_json::to_string(&vcdm)?.into_bytes())
    }

    async fn extract_credentials<'a>(
        &self,
        credential: &SerializedCredential,
        _credential_schema: Option<&'a CredentialSchema>,
        verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        let mut vcdm: VcdmCredential = serde_json::from_str(credential.as_ref())?;
        let mandatory_pointers = self.verify(&mut vcdm, verification_fn).await?;
        let metadata_claims = self
            .get_metadata_claims()
            .into_iter()
            .map(|c| c.key)
            .collect::<Vec<_>>();
        convert_to_detail_credential(vcdm, mandatory_pointers, &metadata_claims)
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        credential: &SerializedCredential,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        let vc: VcdmCredential = serde_json::from_str(credential.as_ref())?;

        let metadata_claims = self
            .get_metadata_claims()
            .into_iter()
            .map(|c| c.key)
            .collect::<Vec<_>>();
        let mandatory_pointers = extract_mandatory_pointers(&vc)?;
        convert_to_detail_credential(vc, mandatory_pointers, &metadata_claims)
    }

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        let mut vcdm: VcdmCredential = serde_json::from_str(credential.token.as_ref())?;

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

        let resp = serde_json::to_string(&revealed_document)?;

        Ok(resp)
    }

    fn get_leeway(&self) -> Duration {
        self.params.leeway_seconds
    }

    fn get_default_expiration(&self) -> Duration {
        self.params.expiration_seconds
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![KeyAlgorithmType::BbsPlus],
            features: vec![
                Features::SupportsCredentialDesign,
                Features::SelectiveDisclosure,
                Features::SupportsCombinedPresentation,
                Features::SupportsTxCode,
            ],
            selective_disclosure: vec![SelectiveDisclosure::AnyLevel],
            issuance_did_methods: vec![DidType::Key, DidType::Web, DidType::Jwk, DidType::WebVh],
            ecosystem_schema_ids: vec![],
            pid_schema_ids: vec![],
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
            issuance_exchange_protocols: vec![IssuanceProtocolType::OpenId4VciFinal1_0],
            proof_exchange_protocols: vec![
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::OpenId4VpProximityDraft00,
            ],
            revocation_methods: vec![RevocationType::BitstringStatusList],
            verification_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::MlDsa,
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

    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<Credential, FormatterError> {
        let now = crate::clock::now_utc();

        let mut vcdm: VcdmCredential = serde_json::from_str(credential.as_ref())?;

        let revocation_method = if let Some(status) = vcdm.credential_status.first() {
            match status.r#type.as_str() {
                "BitstringStatusListEntry" => Some(RevocationType::BitstringStatusList),
                _ => {
                    return Err(FormatterError::CouldNotVerify(format!(
                        "Unknown revocation method: {}",
                        status.r#type
                    )));
                }
            }
        } else {
            None
        };

        let mandatory_pointers = self.verify(&mut vcdm, verification).await?;
        let metadata_claim_keys = self
            .get_metadata_claims()
            .into_iter()
            .map(|c| c.key)
            .collect::<Vec<_>>();
        let metadata_claims =
            metadata_claims_with_sd_flags(&vcdm, &mandatory_pointers, &metadata_claim_keys)?;
        let vc_types = vcdm.r#type;
        let schema_name = vc_types
            .iter()
            .find(|t| t != &"VerifiableCredential")
            .cloned()
            .unwrap_or_else(|| "VerifiableCredential".to_string());

        // Parse claims from credential subject
        let credential_subject = vcdm.credential_subject.first().ok_or_else(|| {
            FormatterError::CouldNotExtractCredentials("Missing credential subject".to_string())
        })?;

        let credential_id = Uuid::new_v4().into();
        let mut claims = HashMap::from_iter(credential_subject.claims.clone());
        mark_claims_selectively_disclosable(&mut claims, mandatory_pointers);
        let (mut claims, mut claim_schemas) =
            parse_claims(claims, self.data_type_provider.as_ref(), credential_id).await?;

        // Add parsed metadata claims
        let (metadata_claims, metadata_claim_schemas) = parse_claims(
            metadata_claims,
            self.data_type_provider.as_ref(),
            credential_id,
        )
        .await?;
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
            key_storage_security: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            requires_wallet_instance_attestation: false,
            claim_schemas: claim_schemas.into(),
            organisation: organisation.clone().into(),
            transaction_code: None,
            formats: vec![format].into(),
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

        Ok(Credential {
            expires_at: vcdm.valid_until.or(vcdm.expiration_date),
            ecosystem: None,
            id: credential_id,
            created_date: now,
            issuance_date: vcdm.issuance_date,
            last_modified: now,
            deleted_at: None,
            consumed_at: None,
            protocol: "".to_string(),
            redirect_uri: None,
            role: CredentialRole::Holder,
            r#type: CredentialType::Single,
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
            profile: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            claims: claims.into(),
            issuer_certificate: first_certificate(&issuer_identifier).await?.map(Into::into),
            issuer_identifier: Some(issuer_identifier.into()),
            holder_identifier: holder_identifier.map(Into::into),
            schema: schema.into(),
            interaction: None,
            key: None,
            webhook_url: None,
            parent: None,
            embedded_disclosure_policy: None,
            subscriber_information: None,
        })
    }

    fn revocation_method_id(&self) -> Option<&RevocationMethodId> {
        self.params.revocation_method.as_ref()
    }

    fn config_name(&self) -> &CredentialFormat {
        &self.config_id
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
