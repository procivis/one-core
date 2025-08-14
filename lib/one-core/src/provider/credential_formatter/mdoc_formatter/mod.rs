//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ciborium::Value;
use coset::iana::{self, EnumI64};
use coset::{CoseKey, CoseKeyBuilder, Header, HeaderBuilder, SignatureContext};
use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
use indexmap::{IndexMap, IndexSet};
use one_crypto::SignerError;
use one_crypto::utilities::generate_random_bytes;
use serde::Deserialize;
use serde_json::json;
use serde_with::{DurationSeconds, serde_as};
use sha2::{Digest, Sha256, Sha384, Sha512};
use shared_types::{CredentialSchemaId, DidValue};
use time::format_description::FormatItem;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, Duration, OffsetDateTime};

use super::nest_claims;
use crate::common_mapper::{NESTED_CLAIM_MARKER, decode_cbor_base64, encode_cbor_base64};
use crate::config::core_config::{
    DatatypeConfig, DatatypeType, DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType,
    KeyStorageType, RevocationType, VerificationProtocolType,
};
use crate::model::credential_schema::CredentialSchemaType;
use crate::model::identifier::Identifier;
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::revocation_list::StatusListType;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialClaim, CredentialClaimValue, CredentialData,
    CredentialPresentation, CredentialSchema, CredentialSchemaMetadata, CredentialSubject,
    DetailCredential, Features, FormatterCapabilities, HolderBindingCtx, IdentifierDetails,
    PublicKeySource, PublishedClaim, SelectiveDisclosure, TokenVerifier, VerificationFn,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;
use crate::util::cose::{CoseSign1, CoseSign1Builder};
use crate::util::mdoc::{
    Bstr, DataElementValue, DateTime, DeviceKey, DeviceKeyInfo, DigestAlgorithm, DigestIDs,
    EmbeddedCbor, IssuerSigned, IssuerSignedItem, MobileSecurityObject,
    MobileSecurityObjectVersion, Namespace, Namespaces, ValidityInfo, ValueDigests,
    extract_algorithm_from_header, extract_certificate_from_x5chain_header,
    try_build_algorithm_header, try_extract_holder_public_key, try_extract_mobile_security_object,
};
use crate::util::x509::pem_chain_into_x5c;

#[cfg(test)]
mod test;

const FULL_DATE_FORMAT: &[FormatItem<'_>] = format_description!("[year]-[month]-[day]");

static LAYOUT_NAMESPACE: &str = "ch.procivis.mdoc_layout.1";

pub struct MdocFormatter {
    certificate_validator: Arc<dyn CertificateValidator>,
    params: Params,
    did_method_provider: Arc<dyn DidMethodProvider>,
    datatype_config: DatatypeConfig,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub mso_expires_in: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub mso_expected_update_in: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub mso_minimum_refresh_time: Duration,
    pub leeway: u64,
    pub embed_layout_properties: Option<bool>,
}

impl MdocFormatter {
    pub fn new(
        params: Params,
        certificate_validator: Arc<dyn CertificateValidator>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        datatype_config: DatatypeConfig,
    ) -> Self {
        Self {
            certificate_validator,
            params,
            did_method_provider,
            datatype_config,
        }
    }
}

#[async_trait]
impl CredentialFormatter for MdocFormatter {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let vcdm = credential_data.vcdm;
        let credential_schema = vcdm
            .credential_schema
            .and_then(|schema| schema.into_iter().next())
            .ok_or_else(|| {
                FormatterError::Failed("MDOC credential missing credential schema".to_string())
            })?;

        let mut claims = nest_claims(credential_data.claims.clone())?;

        if let Some(metadata) = credential_schema.metadata {
            let layout_value = match self.params.embed_layout_properties {
                Some(true) => {
                    json!({
                        "id": credential_schema.id,
                        "layoutProperties": metadata.layout_properties,
                        "layoutType": metadata.layout_type,
                    })
                }
                _ => {
                    json!({
                        "id": credential_schema.id
                    })
                }
            };

            claims.insert(LAYOUT_NAMESPACE.to_string(), layout_value);
        }

        let namespaces =
            try_build_namespaces(claims, credential_data.claims, &self.datatype_config)?;

        let holder_did = credential_data
            .holder_identifier
            .as_ref()
            .and_then(|identifier| identifier.did.as_ref())
            .ok_or(FormatterError::CouldNotFormat(
                "Missing holder did for mdoc".to_string(),
            ))?;

        let cose_key = try_build_cose_key(&*self.did_method_provider, &holder_did.did).await?;

        let device_key_info = DeviceKeyInfo {
            device_key: DeviceKey(cose_key),
            key_authorizations: None,
            key_info: None,
        };

        let validity_info = ValidityInfo {
            signed: DateTime(OffsetDateTime::now_utc()),
            valid_from: DateTime(OffsetDateTime::now_utc()),
            valid_until: DateTime(OffsetDateTime::now_utc() + self.params.mso_expires_in),
            expected_update: Some(DateTime(
                OffsetDateTime::now_utc() + self.params.mso_expected_update_in,
            )),
        };

        let digest_algorithm = DigestAlgorithm::Sha256;
        let mso = MobileSecurityObject {
            version: MobileSecurityObjectVersion::V1_0,
            digest_algorithm,
            value_digests: try_build_value_digests(&namespaces, digest_algorithm)?,
            device_key_info,
            doc_type: credential_schema.id,
            validity_info,
        };
        let mso = EmbeddedCbor::<MobileSecurityObject>::new(mso)
            .map_err(|err| {
                FormatterError::Failed(format!(
                    "CBOR serialization failed for MobileSecurityObjectBytes: {err}"
                ))
            })?
            .into_bytes();

        let key_algorithm = auth_fn
            .get_key_algorithm()
            .map_err(|key_type| FormatterError::Failed(format!("Failed mapping algorithm `{key_type}` to name compatible with allowed COSE Algorithms")))?;

        let algorithm_header = try_build_algorithm_header(key_algorithm)?;

        let x5c = if let Some(certificate) = credential_data.issuer_certificate {
            pem_chain_into_x5c(&certificate.chain).map_err(|err| {
                FormatterError::Failed(format!("failed to create x5c header param: {err}"))
            })?
        } else {
            return Err(FormatterError::Failed(
                "Missing issuer certificate".to_string(),
            ));
        };
        let x5chain_header = build_x5chain_header(&x5c)?;

        let cose_sign1 = CoseSign1Builder::new()
            .protected(algorithm_header)
            .unprotected(x5chain_header)
            .payload(mso)
            .try_create_signature_with_provider(&[], &*auth_fn)
            .await
            .map_err(|err| FormatterError::CouldNotSign(err.to_string()))?
            .build();

        let issuer_signed = IssuerSigned {
            name_spaces: Some(namespaces),
            issuer_auth: CoseSign1(cose_sign1),
        };

        encode_cbor_base64(issuer_signed)
    }

    async fn format_status_list(
        &self,
        _revocation_list_url: String,
        _issuer_identifier: &Identifier,
        _encoded_list: String,
        _algorithm: KeyAlgorithmType,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        Err(FormatterError::Failed(
            "Cannot format StatusList with MDOC formatter".to_string(),
        ))
    }

    async fn extract_credentials<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a crate::model::credential_schema::CredentialSchema>,
        _verification: VerificationFn,
        _holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(&*self.certificate_validator, token, true).await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a crate::model::credential_schema::CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(&*self.certificate_validator, token, false).await
    }

    // Extract issuer_signed, keep only the claims that the verifier asked for, re-encode issuer_signed that back to the same format
    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
        _holder_binding_ctx: Option<HolderBindingCtx>,
        _holder_binding_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError> {
        let mut issuer_signed: IssuerSigned = decode_cbor_base64(&credential.token)?;

        let Some(namespaces) = issuer_signed.name_spaces.as_mut() else {
            return Err(FormatterError::Failed(
                "IssuerSigned object is missing namespaces".to_owned(),
            ));
        };

        let mut disclosed_keys: IndexSet<&str> = credential
            .disclosed_keys
            .iter()
            .map(|key| key.as_str())
            .collect();

        if namespaces.contains_key(LAYOUT_NAMESPACE) {
            // We would like to disclose that namespace as well
            disclosed_keys.insert(LAYOUT_NAMESPACE);
        }

        let mut paths_for_namespace = IndexMap::new();
        for disclosed_key in disclosed_keys {
            if let Some((namespace, path)) = disclosed_key.split_once('/') {
                paths_for_namespace
                    .entry(namespace)
                    .or_insert(vec![])
                    .push(path);
            } else {
                // we ask for the entire namespace
                paths_for_namespace.insert(disclosed_key, vec![]);
            }
        }

        // keep only the claims that we were asked for
        namespaces.retain(|namespace, claims| {
            let Some(related_paths) = paths_for_namespace.get(namespace.as_str()) else {
                return false;
            };

            // we're going to keep the whole namespace
            if related_paths.is_empty() {
                return true;
            }

            claims.retain(|claim| {
                // we pull in everything starting with `path` since a `disclosed_key` for an object will contain only name of the object
                related_paths
                    .iter()
                    .any(|path| claim.inner().element_identifier.starts_with(path))
            });

            !claims.is_empty()
        });

        if namespaces.is_empty() {
            return Err(FormatterError::Failed(
                "No matching claims were found in namespaces".to_owned(),
            ));
        }

        encode_cbor_base64(issuer_signed)
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            features: vec![
                Features::SelectiveDisclosure,
                Features::RequiresSchemaId,
                Features::SupportsCredentialDesign,
                Features::RequiresPresentationEncryption,
            ],
            allowed_schema_ids: vec![],
            selective_disclosure: vec![SelectiveDisclosure::SecondLevel],
            issuance_did_methods: vec![],
            issuance_exchange_protocols: vec![IssuanceProtocolType::OpenId4VciDraft13],
            proof_exchange_protocols: vec![
                VerificationProtocolType::OpenId4VpDraft20,
                VerificationProtocolType::OpenId4VpDraft25,
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::IsoMdl,
                VerificationProtocolType::OpenId4VpProximityDraft00,
            ],
            revocation_methods: vec![
                RevocationType::None,
                RevocationType::MdocMsoUpdateSuspension,
            ],
            signing_key_algorithms: vec![KeyAlgorithmType::Eddsa, KeyAlgorithmType::Ecdsa],
            verification_key_algorithms: vec![KeyAlgorithmType::Eddsa, KeyAlgorithmType::Ecdsa],
            verification_key_storages: vec![KeyStorageType::Internal],
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
                "MDL_PICTURE".to_string(),
            ],
            forbidden_claim_names: vec!["0".to_string(), LAYOUT_NAMESPACE.to_string()],
            issuance_identifier_types: vec![IdentifierType::Certificate],
            verification_identifier_types: vec![IdentifierType::Did, IdentifierType::Certificate],
            holder_identifier_types: vec![IdentifierType::Did],
            holder_key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            holder_did_methods: vec![DidType::Web, DidType::Key, DidType::Jwk, DidType::WebVh],
        }
    }

    fn credential_schema_id(
        &self,
        _id: CredentialSchemaId,
        request: &CreateCredentialSchemaRequestDTO,
        _core_base_url: &str,
    ) -> Result<String, FormatterError> {
        request
            .schema_id
            .clone()
            .ok_or(FormatterError::Failed("Missing schema_id".to_string()))
    }
}

async fn extract_credentials_internal(
    certificate_validator: &dyn CertificateValidator,
    token: &str,
    verify: bool,
) -> Result<DetailCredential, FormatterError> {
    let issuer_signed: IssuerSigned = decode_cbor_base64(token)?;
    let issuer_cert = extract_certificate_from_x5chain_header(
        certificate_validator,
        &issuer_signed.issuer_auth,
        verify,
    )
    .await?;
    let mso = try_extract_mobile_security_object(&issuer_signed.issuer_auth)?;
    let Some(namespaces) = issuer_signed.name_spaces else {
        return Err(FormatterError::Failed(
            "IssuerSigned object is missing namespaces".to_owned(),
        ));
    };

    let issuer_auth = &issuer_signed.issuer_auth;
    let holder_jwk = try_extract_holder_public_key(issuer_auth)?;

    if verify {
        let digest_algo = mso.digest_algorithm;
        let digest_fn = |data: &[u8]| match digest_algo {
            DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        };

        let digest_values = mso.value_digests;

        for (namespace, signed_items) in &namespaces {
            let digest_ids = digest_values
                .get(namespace)
                .ok_or(FormatterError::CouldNotVerify(format!(
                    "Missing digest value for namespace {namespace}"
                )))?;

            for signed_item in signed_items {
                let digest_id = digest_ids.get(&signed_item.inner().digest_id).ok_or(
                    FormatterError::CouldNotExtractCredentials("Missing digest_ids".to_owned()),
                )?;

                let item_as_cbor = signed_item.bytes();
                let digest = digest_fn(item_as_cbor);

                if digest != digest_id.0 {
                    return Err(FormatterError::CouldNotExtractCredentials(
                        "Invalid digest_id".to_owned(),
                    ));
                }
            }
        }
    }

    let mut claims = try_extract_claims(namespaces)?;

    let layout = claims.remove(LAYOUT_NAMESPACE);

    let metadata: Option<CredentialSchemaMetadata> =
        layout.and_then(|layout| serde_json::from_value(layout.value.into()).ok());

    Ok(DetailCredential {
        id: None,
        issuance_date: Some(mso.validity_info.signed.into()),
        valid_from: Some(mso.validity_info.valid_from.into()),
        valid_until: Some(mso.validity_info.valid_until.into()),
        update_at: mso
            .validity_info
            .expected_update
            .map(|update| update.into()),
        invalid_before: None,
        issuer: IdentifierDetails::Certificate(issuer_cert),
        subject: Some(IdentifierDetails::Key(holder_jwk)),
        claims: CredentialSubject { claims, id: None },
        status: vec![],
        credential_schema: Some(CredentialSchema {
            id: mso.doc_type,
            r#type: CredentialSchemaType::Mdoc.to_string(),
            metadata,
        }),
    })
}

pub async fn try_verify_detached_signature_with_provider(
    device_signature: &coset::CoseSign1,
    payload: &[u8],
    external_aad: &[u8],
    issuer_key: &PublicKeyJwk,
    verifier: &dyn TokenVerifier,
) -> Result<(), SignerError> {
    let sig_data = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        device_signature.protected.clone(),
        None,
        external_aad,
        payload,
    );

    let algorithm = extract_algorithm_from_header(device_signature).ok_or(
        SignerError::CouldNotVerify("Missing or invalid signature algorithm".to_string()),
    )?;

    let signature = &device_signature.signature;

    let params = PublicKeySource::Jwk {
        jwk: Cow::Borrowed(issuer_key),
    };
    verifier
        .verify(params, algorithm, &sig_data, signature)
        .await
}

fn try_build_namespaces(
    claims: IndexMap<String, serde_json::Value>,
    flat_claims: Vec<PublishedClaim>,
    datatype_config: &DatatypeConfig,
) -> Result<Namespaces, FormatterError> {
    let mut namespaces = Namespaces::new();

    let mut digest_id: u64 = 0;

    for (namespace_key, namespace_value) in claims.iter() {
        let namespace = namespaces.entry(namespace_key.to_owned()).or_default();

        let namespace_object = namespace_value
            .as_object()
            .ok_or(FormatterError::Failed("Expected an object".to_string()))?;

        for (item_key, item_value) in namespace_object {
            // random has to be minimum 16 bytes
            let random = Bstr(generate_random_bytes::<32>().to_vec());

            let signed_item = IssuerSignedItem {
                digest_id,
                random,
                element_identifier: item_key.to_owned(),
                element_value: build_ciborium_value(
                    item_value,
                    &format!("{namespace_key}/{item_key}"),
                    &flat_claims,
                    datatype_config,
                )?,
            };

            namespace.push(EmbeddedCbor::new(signed_item).map_err(|err| {
                FormatterError::Failed(format!(
                    "CBOR serialization failed for IssuerSignedItem: {err}"
                ))
            })?);
            digest_id += 1;
        }
    }

    Ok(namespaces)
}

fn build_ciborium_value(
    value: &serde_json::Value,
    this_path: &str,
    claims: &Vec<PublishedClaim>,
    datatype_config: &DatatypeConfig,
) -> Result<DataElementValue, FormatterError> {
    match value {
        serde_json::Value::Object(object) => {
            let mut items: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
            for (key, value) in object {
                items.push((
                    ciborium::Value::Text(key.to_owned()),
                    build_ciborium_value(
                        value,
                        &format!("{this_path}/{key}"),
                        claims,
                        datatype_config,
                    )?,
                ));
            }
            Ok(ciborium::Value::Map(items))
        }
        serde_json::Value::Array(array) => {
            let mut items: Vec<ciborium::Value> = Vec::new();
            for (i, value) in array.iter().enumerate() {
                items.push(build_ciborium_value(
                    value,
                    &format!("{this_path}/{i}"),
                    claims,
                    datatype_config,
                )?);
            }
            Ok(ciborium::Value::Array(items))
        }
        serde_json::Value::Null => Ok(ciborium::Value::Null),
        serde_json::Value::String(value)
            if this_path
                .chars()
                .take_while(|c| c != &NESTED_CLAIM_MARKER)
                .eq(LAYOUT_NAMESPACE.chars()) =>
        {
            let claim = PublishedClaim {
                key: this_path.to_string(),
                value: crate::provider::credential_formatter::model::PublishedClaimValue::String(
                    value.to_string(),
                ),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            };
            map_to_ciborium_value(&claim, datatype_config)
        }
        _ => {
            let claim =
                claims
                    .iter()
                    .find(|c| c.key == this_path)
                    .ok_or(FormatterError::Failed(format!(
                        "Missing claim: {this_path}"
                    )))?;
            map_to_ciborium_value(claim, datatype_config)
        }
    }
}

// full-date (ISO mDL 7.2.1)
const FULL_DATE_TAG: u64 = 1004;
const TDATE_TAG: u64 = 0;

fn map_to_ciborium_value(
    claim: &PublishedClaim,
    datatype_config: &DatatypeConfig,
) -> Result<Value, FormatterError> {
    let data_type = claim
        .datatype
        .as_ref()
        .ok_or(FormatterError::Failed("Missing data type".to_string()))?;
    let fields = datatype_config
        .get_fields(data_type)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

    let value_as_string = claim.value.to_string();
    Ok(match fields.r#type {
        DatatypeType::String => ciborium::Value::Text(value_as_string),
        DatatypeType::Number => {
            let value = value_as_string
                .parse::<i128>()
                .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;
            ciborium::Value::from(value)
        }
        DatatypeType::Date => {
            let tag = if Date::parse(&value_as_string, FULL_DATE_FORMAT).is_ok() {
                FULL_DATE_TAG
            } else if OffsetDateTime::parse(&value_as_string, &Rfc3339).is_ok() {
                TDATE_TAG
            } else {
                return Err(FormatterError::CouldNotFormat(format!(
                    "Invalid mdoc date format. Expected tdate or full-date got: {value_as_string}"
                )));
            };

            ciborium::Value::Tag(tag, ciborium::Value::from(value_as_string).into())
        }
        DatatypeType::Boolean => {
            let value: bool = match value_as_string.as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(FormatterError::CouldNotFormat(format!(
                        "Invalid boolean value: {}",
                        claim.value
                    )));
                }
            };
            ciborium::Value::Bool(value)
        }
        DatatypeType::File => {
            let mut file_parts = value_as_string.splitn(2, ',');

            let mime_type = file_parts.next().ok_or(FormatterError::Failed(
                "Missing data type of base64".to_string(),
            ))?;

            let content = file_parts
                .next()
                .ok_or(FormatterError::Failed("Missing base64 data".to_string()))?;

            if let Some(params) = &fields.params {
                if let Some(public) = &params.public {
                    if public["encodeAsMdlPortrait"].as_bool().unwrap_or(false) {
                        let decoded = Base64::decode_to_vec(content, None).map_err(|e| {
                            FormatterError::CouldNotFormat(format!(
                                "Base64url decoding failed: {e}"
                            ))
                        })?;
                        return Ok(ciborium::Value::Bytes(decoded));
                    }
                }
            }

            ciborium::Value::Array(vec![
                ciborium::Value::Text(mime_type.to_string()),
                ciborium::Value::Bytes(content.as_bytes().to_vec()),
            ])
        }
        _ => {
            return Err(FormatterError::CouldNotFormat(format!(
                "Invalid datatype: {}",
                fields.r#type
            )));
        }
    })
}

fn build_x5chain_header(x5c: &[String]) -> Result<Header, FormatterError> {
    let x5chain_label = coset::iana::HeaderParameter::X5Chain.to_i64();

    let mut chain = vec![];
    for cert in x5c {
        let bytes = Base64::decode_to_vec(cert, None).map_err(|e| {
            FormatterError::CouldNotFormat(format!("failed to build x5c header: {e}"))
        })?;
        chain.push(ciborium::Value::Bytes(bytes));
    }

    let x5chain_value = if chain.len() == 1 {
        chain.remove(0)
    } else {
        ciborium::Value::Array(chain)
    };
    Ok(HeaderBuilder::new()
        .value(x5chain_label, x5chain_value)
        .build())
}

fn try_build_value_digests(
    namespaces: &Namespaces,
    digest_alg: DigestAlgorithm,
) -> Result<ValueDigests, FormatterError> {
    let digest_fn = |data| match digest_alg {
        DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    };

    let mut value_digests = IndexMap::<Namespace, DigestIDs>::new();

    for (namespace, signed_items) in namespaces {
        let digest_ids = value_digests.entry(namespace.to_owned()).or_default();

        for signed_item in signed_items {
            let digest = digest_fn(signed_item.bytes());
            let digest_id = signed_item.inner().digest_id;
            digest_ids.insert(digest_id, Bstr(digest));
        }
    }

    Ok(value_digests)
}

async fn try_build_cose_key(
    did_resolver: &dyn DidMethodProvider,
    holder_did: &DidValue,
) -> Result<CoseKey, FormatterError> {
    let mut did_document = did_resolver
        .resolve(holder_did)
        .await
        .map_err(|err| FormatterError::Failed(format!("Failed resolving did {err}")))?;

    let base64decode = |v| {
        Base64UrlSafeNoPadding::decode_to_vec(v, None)
            .map_err(|err| FormatterError::Failed(format!("Failed base64 decoding key {err}")))
    };

    let cose_key = match did_document
        .verification_method
        .swap_remove(0)
        .public_key_jwk
    {
        PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            crv, x, y: Some(y), ..
        }) if &crv == "P-256" => {
            let x = base64decode(x)?;
            let y = base64decode(y)?;

            CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y).build()
        }

        PublicKeyJwk::Okp(key) if key.crv == "Ed25519" => {
            let x = base64decode(key.x)?;

            CoseKeyBuilder::new_okp_key()
                .param(
                    iana::Ec2KeyParameter::Crv.to_i64(),
                    ciborium::Value::from(iana::EllipticCurve::Ed25519.to_i64()),
                )
                .param(iana::Ec2KeyParameter::X as i64, ciborium::Value::from(x))
                .build()
        }
        key => {
            return Err(FormatterError::Failed(format!(
                "Key not available for mdoc {key:?}"
            )));
        }
    };

    Ok(cose_key)
}

fn build_json_value(value: DataElementValue) -> Result<serde_json::Value, FormatterError> {
    match value {
        Value::Text(text) => Ok(serde_json::Value::String(text)),
        Value::Bool(bool_value) => Ok(serde_json::Value::String(if bool_value {
            "true".to_string()
        } else {
            "false".to_string()
        })),
        Value::Integer(number) => {
            let number_value: i128 = number.into();
            Ok(serde_json::Value::String(number_value.to_string()))
        }
        Value::Tag(tag, tag_value) => match tag {
            TDATE_TAG => {
                let datetime = tag_value.into_text().map_err(|v| {
                    FormatterError::Failed(format!("Expected tdate value. Got: {v:#?}",))
                })?;
                OffsetDateTime::parse(&datetime, &Rfc3339).map_err(|err| {
                    FormatterError::Failed(format!("Invalid tdate `{datetime}`: {err}",))
                })?;

                Ok(serde_json::Value::String(datetime))
            }
            FULL_DATE_TAG => {
                let date = tag_value.into_text().map_err(|v| {
                    FormatterError::Failed(format!("Expected tdate value. Got: {v:#?}",))
                })?;
                Date::parse(&date, FULL_DATE_FORMAT).map_err(|err| {
                    FormatterError::Failed(format!("Invalid full-date `{date}`: {err}",))
                })?;

                Ok(serde_json::Value::String(date))
            }
            _ => Err(FormatterError::Failed(format!(
                "Unexpected CBOR tag: {tag}"
            ))),
        },
        Value::Bytes(bytes) => handle_bytes(&bytes),
        Value::Array(array) => handle_array(array),
        Value::Map(map) => {
            let mut map_content = serde_json::Map::new();
            for (key, value) in map {
                let key = key
                    .as_text()
                    .ok_or(FormatterError::Failed("Expected a text".to_string()))?;
                map_content.insert(key.to_owned(), build_json_value(value)?);
            }
            Ok(serde_json::Value::Object(map_content))
        }
        Value::Null => Ok(serde_json::Value::Null),
        _ => Err(FormatterError::Failed(format!(
            "Unexpected element value. Got: {value:#?}"
        ))),
    }
}

fn handle_array(array: Vec<Value>) -> Result<serde_json::Value, FormatterError> {
    // Check if array has all elements with the same type
    let Some(first) = array.first() else {
        return Ok(serde_json::Value::Array(vec![]));
    };

    // Collect items if a homogenous array
    if array.iter().all(|item| is_same_type(item, first)) {
        let items = array
            .into_iter()
            .map(build_json_value)
            .collect::<Result<Vec<_>, _>>()?;

        return Ok(serde_json::Value::Array(items));
    }

    // PICTURE
    if array.len() == 2 {
        let bytes = array[1]
            .as_bytes()
            .ok_or_else(|| FormatterError::Failed("Not a byte array".to_owned()))?;
        let value = String::from_utf8_lossy(bytes);

        let data_type_value = array[0]
            .as_text()
            .ok_or_else(|| FormatterError::Failed("Expected String value for key".to_owned()))?;

        return Ok(serde_json::Value::String(format!(
            "{data_type_value},{value}"
        )));
    }

    Err(FormatterError::Failed("Unhandled array".to_owned()))
}

fn is_same_type(a: &Value, b: &Value) -> bool {
    a.is_array() && b.is_array()
        || a.is_map() && b.is_map()
        || a.is_text() && b.is_text()
        || a.is_bool() && b.is_bool()
        || a.is_bytes() && b.is_bytes()
        || (a.is_integer() || a.is_float()) && (b.is_integer() || b.is_float())
        || a.is_tag()
            && b.is_tag()
            && a.as_tag()
                .is_some_and(|(tag_a, _)| b.as_tag().is_some_and(|(tag_b, _)| tag_a == tag_b))
}

fn handle_bytes(bytes: &[u8]) -> Result<serde_json::Value, FormatterError> {
    let value = Base64::encode_to_string(bytes)
        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;
    Ok(serde_json::Value::String(format!(
        "data:image/jpeg;base64,{value}"
    )))
}

fn try_extract_claims(
    namespaces: Namespaces,
) -> Result<HashMap<String, CredentialClaim>, FormatterError> {
    let mut result = HashMap::new();
    for (namespace, inner_claims) in namespaces {
        let mut namespace_object_content = HashMap::new();

        for issuer_signed_item in inner_claims {
            let issuer_signed_item = issuer_signed_item.into_inner();
            let val = build_json_value(issuer_signed_item.element_value)?;
            namespace_object_content.insert(
                issuer_signed_item.element_identifier,
                CredentialClaim {
                    selectively_disclosable: true,
                    value: val.try_into()?,
                },
            );
        }
        result.insert(
            namespace,
            CredentialClaim {
                selectively_disclosable: true,
                value: CredentialClaimValue::Object(namespace_object_content),
            },
        );
    }

    Ok(result)
}

pub async fn try_extracting_mso_from_token(
    token: &str,
) -> Result<MobileSecurityObject, FormatterError> {
    let issuer_signed: IssuerSigned = decode_cbor_base64(token)?;
    try_extract_mobile_security_object(&issuer_signed.issuer_auth)
}
