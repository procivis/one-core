//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use coset::cwt::{ClaimsSetBuilder, Timestamp};
use coset::iana::{EnumI64, HeaderParameter};
use coset::{
    AsCborValue, CborSerializable, HeaderBuilder, ProtectedHeader, SignatureContext,
    TaggedCborSerializable,
};
use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
use futures::future::BoxFuture;
use indexmap::{IndexMap, IndexSet};
use one_crypto::utilities::generate_random_bytes;
use proc_macros::Provider;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use sha2::{Digest, Sha256, Sha384, Sha512};
use shared_types::{
    CredentialFormat, CredentialId, CredentialSchemaFormatId, CredentialSchemaId, DidValue,
    OrganisationId, RevocationMethodId, SerializedCredential,
};
use standardized_types::jwk::PublicJwk;
use time::format_description::FormatItem;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, Duration, OffsetDateTime};
use uuid::Uuid;

use self::util::{
    Bstr, DataElementValue, DateTime, DeviceKey, DeviceKeyInfo, DigestAlgorithm, DigestIDs,
    EmbeddedCbor, IssuerSigned, IssuerSignedItem, MobileSecurityObject, Namespace, Namespaces,
    ValidityInfo, ValueDigests, build_algorithm_header_value, create_status,
    extract_algorithm_from_header, extract_certificate_from_x5chain_header, parse_status,
    try_extract_holder_public_key, try_extract_mobile_security_object,
};
use super::error::FormatterError;
use super::json_claims::prepare_identifier;
use super::mapper::first_certificate;
use super::mdoc_formatter::util::StatusListEncoded;
use super::model::{
    AuthenticationFn, CredentialClaim, CredentialClaimValue, CredentialData,
    CredentialPresentation, DetailCredential, Features, FormatterCapabilities, IdentifierDetails,
    PublicKeySource, PublishedClaim, SelectiveDisclosure, TokenVerifier, VerificationFn,
};
use super::{CredentialFormatter, MetadataClaimSchema, nest_claims};
use crate::config::core_config::{
    DatatypeConfig, DatatypeType, DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType,
    KeyStorageType, RevocationType, VerificationProtocolType,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::x509::pem_chain_into_x5c;
use crate::mapper::{NESTED_CLAIM_MARKER, decode_cbor_base64, encode_cbor_base64};
use crate::model::certificate::Certificate;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::identifier;
use crate::model::organisation::Organisation;
use crate::proto::certificate_validator::{CertificateValidationOptions, CertificateValidator};
use crate::proto::cose::{CoseSign1, CoseSign1Builder};
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::TokenError;
use crate::provider::data_type::model::ExtractedClaim;
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::key_selection::SelectedKey;

pub(crate) mod util;

#[cfg(test)]
mod test;

const FULL_DATE_FORMAT: &[FormatItem<'_>] = format_description!("[year]-[month]-[day]");

#[derive(Provider)]
pub struct MdocFormatter {
    config_id: CredentialFormat,
    certificate_validator: Arc<dyn CertificateValidator>,
    params: Params,
    did_method_provider: Arc<dyn DidMethodProvider>,
    datatype_config: DatatypeConfig,
    datatype_provider: Arc<dyn DataTypeProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    base_url: Option<Arc<str>>,
    client: Arc<dyn HttpClient>,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expiration_seconds: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub mso_expected_update_in_seconds: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub mso_minimum_refresh_seconds: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway_seconds: Duration,
    pub revocation_method: Option<RevocationMethodId>,
}

impl MdocFormatter {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        base_url: Option<Arc<str>>,
        config_id: CredentialFormat,
        params: serde_json::Value,
        certificate_validator: Arc<dyn CertificateValidator>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        datatype_config: DatatypeConfig,
        datatype_provider: Arc<dyn DataTypeProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            base_url,
            config_id,
            certificate_validator,
            params,
            did_method_provider,
            datatype_config,
            datatype_provider,
            key_algorithm_provider,
            client,
        })
    }
}

#[async_trait]
impl CredentialFormatter for MdocFormatter {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<SerializedCredential, FormatterError> {
        let Some(base_url) = self.base_url.as_ref() else {
            return Err(
                InitializationError::MissingDependency("base_url".to_string())
                    .error_while("missing base_url")
                    .into(),
            );
        };
        let vcdm = credential_data.vcdm;
        let credential_schema = vcdm
            .credential_schema
            .and_then(|schema| schema.into_iter().next())
            .ok_or_else(|| {
                FormatterError::CouldNotFormat(
                    "MDOC credential missing credential schema".to_string(),
                )
            })?;

        let claims = nest_claims(credential_data.claims.clone())?;

        let namespaces =
            try_build_namespaces(claims, credential_data.claims, &self.datatype_config)?;

        let holder_identifier =
            credential_data
                .holder_identifier
                .ok_or(FormatterError::CouldNotFormat(
                    "Missing holder identifier".to_string(),
                ))?;

        let holder_key = match &holder_identifier.data {
            identifier::IdentifierData::Key(key) => {
                let key = key.as_ref().await?;

                self.key_algorithm_provider
                    .key_algorithm_from_key(&key)
                    .error_while("getting key algorithm")?
                    .reconstruct_key(&key.public_key, None, None)
                    .error_while("reconstructing key")?
                    .public_key_as_cose()
                    .error_while("getting CoseKey")?
            }
            identifier::IdentifierData::Did(did) => {
                let did = did.as_ref().await?.to_owned();
                let jwk = try_extract_did(
                    self.did_method_provider.as_ref(),
                    &did.did,
                    credential_data.holder_key_id.as_ref(),
                )
                .await?;

                self.key_algorithm_provider
                    .parse_jwk(&jwk)
                    .error_while("parsing JWK")?
                    .key
                    .public_key_as_cose()
                    .error_while("getting CoseKey")?
            }
            _ => {
                return Err(FormatterError::CouldNotFormat(
                    "Invalid holder identifier".to_string(),
                ));
            }
        };

        let device_key_info = DeviceKeyInfo {
            device_key: DeviceKey(holder_key),
            key_authorizations: None,
            key_info: None,
        };

        let validity_info = ValidityInfo {
            signed: DateTime(crate::clock::now_utc()),
            valid_from: DateTime(crate::clock::now_utc()),
            valid_until: DateTime(
                vcdm.valid_until
                    .unwrap_or_else(|| crate::clock::now_utc() + self.params.expiration_seconds),
            ),
            expected_update: Some(DateTime(
                crate::clock::now_utc() + self.params.mso_expected_update_in_seconds,
            )),
        };

        let digest_algorithm = DigestAlgorithm::Sha256;
        let mso = MobileSecurityObject {
            version: Default::default(),
            digest_algorithm,
            value_digests: try_build_value_digests(&namespaces, digest_algorithm)?,
            device_key_info,
            doc_type: credential_schema.id,
            validity_info,
            status: create_status(vcdm.credential_status)?,
        };
        let mso = EmbeddedCbor::<MobileSecurityObject>::new(mso)?.into_bytes();

        let key_algorithm = auth_fn
            .get_key_algorithm()
            .map_err(|key_type| FormatterError::CouldNotFormat(format!("Failed mapping algorithm `{key_type}` to name compatible with allowed COSE Algorithms")))?;

        let Some(certificate) = credential_data.issuer_certificate else {
            return Err(FormatterError::CouldNotFormat(
                "Missing issuer certificate".to_string(),
            ));
        };

        let unprotected_headers = HeaderBuilder::new()
            .add_header(
                HeaderParameter::X5Chain,
                build_x5chain_header_value(
                    &certificate.chain,
                    Some(self.certificate_validator.as_ref()),
                )
                .await?,
            )
            .add_header(
                HeaderParameter::X5U,
                build_x5url_header(&certificate, base_url),
            )
            .build();

        let protected_headers = HeaderBuilder::new()
            .algorithm(build_algorithm_header_value(key_algorithm)?)
            .add_header(
                HeaderParameter::X5T,
                build_x5thumbprint_header(&certificate)?,
            )
            .build();

        let cose_sign1 = CoseSign1Builder::new()
            .protected(ProtectedHeader {
                original_data: None,
                header: protected_headers,
            })
            .unprotected(unprotected_headers)
            .payload(mso)
            .try_create_signature_with_provider(&[], &*auth_fn)
            .await
            .error_while("creating signature")?
            .build();

        let issuer_signed = IssuerSigned {
            name_spaces: Some(namespaces),
            issuer_auth: CoseSign1(cose_sign1),
        };

        encode_cbor_base64(issuer_signed).map(Into::into)
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
        if status_purpose != StatusPurpose::Revocation {
            return Err(FormatterError::CouldNotFormat(format!(
                "Unsupported status list purpose: {status_purpose}"
            )));
        }
        if status_list_type != RevocationType::TokenStatusList {
            return Err(FormatterError::CouldNotFormat(format!(
                "Unsupported status list type: {status_list_type}"
            )));
        }

        let SelectedKey::Certificate { certificate, .. } = &issuer else {
            return Err(FormatterError::CouldNotFormat(
                "Unsupported issuer identifier".to_string(),
            ));
        };

        let list = Base64UrlSafeNoPadding::decode_to_vec(encoded_list, None)?;

        let protected_headers = HeaderBuilder::new()
            .algorithm(build_algorithm_header_value(algorithm)?)
            .add_header(
                HeaderParameter::ObjectContentType,
                ciborium::Value::Text("application/statuslist+cwt".to_string()),
            )
            .add_header(
                HeaderParameter::X5Chain,
                build_x5chain_header_value(&certificate.chain, None).await?,
            )
            .build();
        let unprotected_headers = {
            let mut unprotected_headers = HeaderBuilder::new();
            if let Some(kid) = auth_fn.get_key_id() {
                unprotected_headers = unprotected_headers.add_header(
                    HeaderParameter::Kid,
                    ciborium::Value::Bytes(kid.into_bytes()),
                );
            }
            unprotected_headers.build()
        };
        let payload = {
            let mut payload = ClaimsSetBuilder::new()
                .subject(revocation_list_url)
                .issued_at(Timestamp::WholeSeconds(
                    crate::clock::now_utc().unix_timestamp(),
                ))
                .build()
                .to_cbor_value()?;

            let status_list = ciborium::cbor!(StatusListEncoded {
                bits: 1,
                list: Bstr(list),
                aggregation_uri: None,
            })?;

            payload
                .as_map_mut()
                .ok_or(FormatterError::CouldNotFormat(
                    "invalid CWT payload".to_string(),
                ))?
                .push((65533u16.into(), status_list));

            payload.to_vec()?
        };
        let cose_sign1 = CoseSign1Builder::new()
            .protected(ProtectedHeader {
                original_data: None,
                header: protected_headers,
            })
            .unprotected(unprotected_headers)
            .payload(payload)
            .try_create_signature_with_provider(&[], &*auth_fn)
            .await
            .error_while("creating signature")?
            .build();

        Ok(cose_sign1.to_tagged_vec()?)
    }

    async fn extract_credentials<'a>(
        &self,
        token: &SerializedCredential,
        _credential_schema: Option<&'a crate::model::credential_schema::CredentialSchema>,
        _verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(&*self.certificate_validator, &*self.client, token, true).await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &SerializedCredential,
        _credential_schema: Option<&'a crate::model::credential_schema::CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(&*self.certificate_validator, &*self.client, token, false)
            .await
    }

    // Extract issuer_signed, keep only the claims that the verifier asked for, re-encode issuer_signed that back to the same format
    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        let mut issuer_signed: IssuerSigned = decode_cbor_base64(credential.token.as_ref())?;

        let Some(namespaces) = issuer_signed.name_spaces.as_mut() else {
            return Err(FormatterError::CouldNotFormat(
                "IssuerSigned object is missing namespaces".to_owned(),
            ));
        };

        let disclosed_keys: IndexSet<&str> = credential
            .disclosed_keys
            .iter()
            .map(|key| key.as_str())
            .collect();
        let mut elements_for_namespace = IndexMap::new();
        for disclosed_key in disclosed_keys {
            match disclosed_key.split_once(NESTED_CLAIM_MARKER) {
                Some((namespace, path)) => {
                    let element = match path.split_once(NESTED_CLAIM_MARKER) {
                        Some((element, _)) => element,
                        None => path,
                    };

                    elements_for_namespace
                        .entry(namespace.to_owned())
                        .or_insert(vec![])
                        .push(element.to_string());
                }
                None => {
                    // the entire namespace is requested
                    elements_for_namespace.insert(disclosed_key.to_string(), vec![]);
                }
            }
        }

        // keep only the namespaces/claims that we were asked for
        namespaces.retain(|namespace, claims| {
            let Some(elements) = elements_for_namespace.get(namespace.as_str()) else {
                return false;
            };

            // disclose the whole namespace
            if elements.is_empty() {
                return true;
            }

            claims.retain(|claim| elements.contains(&claim.inner().element_identifier));

            !claims.is_empty()
        });

        if namespaces.is_empty() {
            return Err(FormatterError::CouldNotFormat(
                "No matching claims were found in namespaces".to_owned(),
            ));
        }

        encode_cbor_base64(issuer_signed)
    }

    fn get_leeway(&self) -> Duration {
        self.params.leeway_seconds
    }

    fn get_default_expiration(&self) -> Duration {
        self.params.expiration_seconds
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            features: vec![
                Features::SelectiveDisclosure,
                Features::SupportsSchemaId,
                Features::SupportsCredentialDesign,
                Features::RequiresPresentationEncryption,
                Features::SupportsCombinedPresentation,
                Features::SupportsTxCode,
                Features::RequiresNamespaces,
                Features::SupportsTransactionData,
            ],
            selective_disclosure: vec![SelectiveDisclosure::FirstLevel],
            issuance_did_methods: vec![],
            issuance_exchange_protocols: vec![IssuanceProtocolType::OpenId4VciFinal1_0],
            proof_exchange_protocols: vec![
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::IsoMdl,
                VerificationProtocolType::OpenId4VpProximityDraft00,
            ],
            revocation_methods: vec![RevocationType::TokenStatusList],
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
                "EAA_CATEGORY".to_string(),
            ],
            forbidden_claim_names: vec!["0".to_string()],
            issuance_identifier_types: vec![IdentifierType::Certificate],
            verification_identifier_types: vec![IdentifierType::Did, IdentifierType::Certificate],
            holder_identifier_types: vec![IdentifierType::Did, IdentifierType::Key],
            holder_key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            holder_did_methods: vec![DidType::Web, DidType::Key, DidType::Jwk, DidType::WebVh],
        }
    }

    fn credential_schema_id<'a>(
        &self,
        id: CredentialSchemaId,
        _organisation_id: OrganisationId,
        ecosystem_schema_id: Option<&'a str>,
        _core_base_url: &'a str,
        _format: &CredentialFormat,
    ) -> Result<String, FormatterError> {
        Ok(ecosystem_schema_id
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| id.to_string()))
    }

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        vec![MetadataClaimSchema {
            key: "doctype".to_string(),
            data_type: "STRING".to_string(),
            array: false,
            required: true,
        }]
    }

    fn user_claims_path(&self) -> Vec<String> {
        vec![]
    }

    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        _verification: Box<dyn TokenVerifier>,
    ) -> Result<Credential, FormatterError> {
        let issuer_signed: IssuerSigned = decode_cbor_base64(credential.as_ref())?;
        let issuer_certificate = extract_certificate_from_x5chain_header(
            &*self.certificate_validator,
            &*self.client,
            &issuer_signed.issuer_auth,
            true,
        )
        .await?;

        let mso = try_extract_mobile_security_object(&issuer_signed.issuer_auth)?;
        let Some(namespaces) = issuer_signed.name_spaces else {
            return Err(FormatterError::CouldNotExtractCredentials(
                "IssuerSigned object is missing namespaces".to_owned(),
            ));
        };
        verify_digests(&mso, &namespaces)?;

        let now = crate::clock::now_utc();
        let doctype = mso.doc_type;
        let credential_id = Uuid::new_v4().into();
        let credential_format_id = Uuid::new_v4().into();
        let (mut claims, mut mappings) = parse_claims(
            namespaces,
            self.datatype_provider.as_ref(),
            credential_id,
            credential_format_id,
        )
        .await?;
        let doctype_schema_id = Uuid::new_v4().into();
        claims.push(Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: Some(doctype.to_owned()),
            path: "doctype".to_string(),
            selectively_disclosable: false,
            schema: ClaimSchema {
                id: doctype_schema_id,
                created_date: now,
                last_modified: now,
                key: "doctype".to_string(),
                data_type: "STRING".to_owned(),
                array: false,
                metadata: true,
                required: false,
                translations: Default::default(),
            }
            .into(),
        });
        let doctype_mapping = CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            credential_schema_format_id: credential_format_id,
            claim_schema_id: doctype_schema_id,
            technical_key: "doctype".to_string(),
            namespace: None,
        };
        mappings.push(doctype_mapping);

        // Collect unique claim schemas
        let mut claim_schemas: Vec<ClaimSchema> = vec![];
        for claim in &claims {
            let schema = claim.schema.as_ref().await?;
            if !claim_schemas.iter().any(|s| s.key == schema.key) {
                claim_schemas.push(schema.to_owned());
            }
        }

        let credential_schema_id = Uuid::new_v4().into();
        let format = CredentialSchemaFormat {
            id: credential_format_id,
            created_date: now,
            last_modified: now,
            credential_schema_id,
            format: self.config_id.clone(),
            ecosystem_schema_id: doctype.to_owned(),
            claim_mappings: mappings.into(),
        };
        let credential_schema = crate::model::credential_schema::CredentialSchema {
            expiration: None,
            ecosystem: None,
            id: credential_schema_id,
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: doctype,
            wallet_attestation: Default::default(),
            layout_properties: None,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            organisation: organisation.clone().into(),
            claim_schemas: claim_schemas.into(),
            transaction_code: None,
            formats: vec![format.clone()].into(),
            batch_size: None,
            allow_revocation: mso.status.is_some(),
            translations: Default::default(),
            embedded_disclosure_policy: None,
        };

        let issuer_identifier = prepare_identifier(
            &IdentifierDetails::Certificate(issuer_certificate),
            self.key_algorithm_provider.as_ref(),
            self.did_method_provider.as_ref(),
            organisation.to_owned(),
        )?;

        let holder_jwk = try_extract_holder_public_key(&issuer_signed.issuer_auth)?;
        let holder_identifier = prepare_identifier(
            &IdentifierDetails::Key(holder_jwk),
            self.key_algorithm_provider.as_ref(),
            self.did_method_provider.as_ref(),
            organisation,
        )?;

        Ok(Credential {
            expires_at: Some(mso.validity_info.valid_until.into()),
            ecosystem: None,
            id: credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            issuance_date: Some(mso.validity_info.signed.into()),
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
            wallet_key_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            issuer_certificate: first_certificate(&issuer_identifier).await?.map(Into::into),
            issuer_identifier: Some(issuer_identifier.into()),
            holder_identifier: Some(holder_identifier.into()),
            schema: credential_schema.into(),
            interaction: None,
            key: None,
            claims: claims.into(),
            webhook_url: None,
            parent: None,
            embedded_disclosure_policy: None,
            subscriber_information: None,
            format: Some(format.into()),
        })
    }

    fn revocation_method_id(&self) -> Option<&RevocationMethodId> {
        self.params.revocation_method.as_ref()
    }

    fn config_name(&self) -> &CredentialFormat {
        &self.config_id
    }
}

async fn extract_credentials_internal(
    certificate_validator: &dyn CertificateValidator,
    http_client: &dyn HttpClient,
    token: &SerializedCredential,
    verify: bool,
) -> Result<DetailCredential, FormatterError> {
    let issuer_signed: IssuerSigned = decode_cbor_base64(token.as_ref())?;
    let issuer_cert = extract_certificate_from_x5chain_header(
        certificate_validator,
        http_client,
        &issuer_signed.issuer_auth,
        verify,
    )
    .await?;
    let mso = try_extract_mobile_security_object(&issuer_signed.issuer_auth)?;
    let Some(namespaces) = issuer_signed.name_spaces else {
        return Err(FormatterError::CouldNotExtractCredentials(
            "IssuerSigned object is missing namespaces".to_owned(),
        ));
    };

    let issuer_auth = &issuer_signed.issuer_auth;
    let holder_jwk = try_extract_holder_public_key(issuer_auth)?;

    if verify {
        verify_digests(&mso, &namespaces)?;
    }

    let mut claims = extract_claims(namespaces)?;
    claims.insert(
        "doctype".to_string(),
        CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: CredentialClaimValue::String(mso.doc_type.clone()),
        },
    );

    Ok(DetailCredential {
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
        claims,
        status: parse_status(mso.status),
    })
}

fn verify_digests(
    mso: &MobileSecurityObject,
    namespaces: &Namespaces,
) -> Result<(), FormatterError> {
    let digest_algo = mso.digest_algorithm;
    let digest_fn = |data: &[u8]| match digest_algo {
        DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    };

    let digest_values = &mso.value_digests;

    for (namespace, signed_items) in namespaces {
        let digest_ids = digest_values
            .get(namespace)
            .ok_or(FormatterError::CouldNotVerify(format!(
                "Missing digests for namespace {namespace}"
            )))?;

        for signed_item in signed_items {
            let expected_digest = &digest_ids
                .get(&signed_item.inner().digest_id)
                .ok_or(FormatterError::CouldNotExtractCredentials(
                    "Missing digest_ids".to_owned(),
                ))?
                .0;

            let item_as_cbor = signed_item.bytes();
            let digest = digest_fn(item_as_cbor);

            if &digest != expected_digest {
                return Err(FormatterError::CouldNotExtractCredentials(
                    "Invalid digest".to_owned(),
                ));
            }
        }
    }

    Ok(())
}

pub async fn try_verify_detached_signature_with_provider(
    device_signature: &coset::CoseSign1,
    payload: &[u8],
    external_aad: &[u8],
    issuer_key: &PublicJwk,
    verifier: &dyn TokenVerifier,
) -> Result<(), TokenError> {
    let sig_data = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        device_signature.protected.clone(),
        None,
        external_aad,
        payload,
    );

    let algorithm = extract_algorithm_from_header(device_signature).ok_or(
        TokenError::MissingJOSEAlgorithm("Missing or invalid signature algorithm".to_string()),
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
            .ok_or(FormatterError::JsonMapping(
                "Expected an object".to_string(),
            ))?;

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

            namespace.push(EmbeddedCbor::new(signed_item)?);
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
        _ => {
            let claim = claims.iter().find(|c| c.key == this_path).ok_or(
                FormatterError::CouldNotFormat(format!("Missing claim: {this_path}")),
            )?;
            map_to_ciborium_value(claim, datatype_config)
        }
    }
}

// full-date (ISO mDL 7.2.1)
pub(crate) const FULL_DATE_TAG: u64 = 1004;
pub(crate) const TDATE_TAG: u64 = 0;

fn map_to_ciborium_value(
    claim: &PublishedClaim,
    datatype_config: &DatatypeConfig,
) -> Result<ciborium::Value, FormatterError> {
    let data_type = claim
        .datatype
        .as_ref()
        .ok_or(FormatterError::CouldNotFormat(
            "Missing data type".to_string(),
        ))?;
    let fields = datatype_config
        .get_fields(data_type)
        .error_while("getting datatype config")?;

    let value_as_string = claim.value.to_string();
    Ok(match fields.r#type {
        DatatypeType::String | DatatypeType::Enum => ciborium::Value::Text(value_as_string),
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
        DatatypeType::Picture => {
            let mut file_parts = value_as_string.splitn(2, ',');

            let mime_type = file_parts.next().ok_or(FormatterError::CouldNotFormat(
                "Missing data type of base64".to_string(),
            ))?;

            let content = file_parts.next().ok_or(FormatterError::CouldNotFormat(
                "Missing base64 data".to_string(),
            ))?;

            if let Some(params) = &fields.params
                && let Some(public) = &params.public
                && public["encodeAsMdlPortrait"].as_bool().unwrap_or(false)
            {
                let decoded = Base64::decode_to_vec(content, None)?;
                return Ok(ciborium::Value::Bytes(decoded));
            }

            ciborium::Value::Array(vec![
                ciborium::Value::Text(mime_type.to_string()),
                ciborium::Value::Bytes(content.as_bytes().to_vec()),
            ])
        }
        DatatypeType::SwiyuPicture => {
            return Err(FormatterError::CouldNotFormat(format!(
                "Unsupported datatype: {}",
                fields.r#type
            )));
        }
        DatatypeType::Object | DatatypeType::Array => {
            return Err(FormatterError::CouldNotFormat(format!(
                "Unexpected container datatype: {}",
                fields.r#type
            )));
        }
    })
}

/// <https://www.rfc-editor.org/info/rfc9360/#section-2-5.3>
pub(crate) async fn build_x5chain_header_value(
    pem_chain: &str,
    strip_root_ca: Option<&dyn CertificateValidator>,
) -> Result<ciborium::Value, FormatterError> {
    let x5c = pem_chain_into_x5c(pem_chain).error_while("parsing PEM chain")?;

    let mut chain = Vec::with_capacity(x5c.len());
    for cert in x5c {
        let bytes = Base64::decode_to_vec(cert, None)?;
        chain.push(ciborium::Value::Bytes(bytes));
    }

    // mdoc should not contain the root CA (IACA)
    if let Some(validator) = strip_root_ca
        && chain.len() > 1
        && validator
            .parse_pem_chain(
                pem_chain,
                CertificateValidationOptions {
                    require_root_termination: true,
                    ..CertificateValidationOptions::no_validation()
                },
            )
            .await
            .is_ok()
    {
        chain.pop();
    }

    let x5chain_value = if chain.len() == 1 {
        chain.swap_remove(0)
    } else {
        ciborium::Value::Array(chain)
    };

    Ok(x5chain_value)
}

fn build_x5url_header(certificate: &Certificate, base_url: &str) -> ciborium::Value {
    let url = format!("{base_url}/ssi/certificate/{}", certificate.id);
    ciborium::Value::Text(url)
}

fn build_x5thumbprint_header(certificate: &Certificate) -> Result<ciborium::Value, FormatterError> {
    let der_thumbprint = hex::decode(&certificate.fingerprint)?;
    Ok(ciborium::Value::Array(vec![
        ciborium::Value::Integer(coset::iana::Algorithm::SHA_256.to_i64().into()),
        ciborium::Value::Bytes(der_thumbprint),
    ]))
}

pub(crate) trait HeaderBuilderExt {
    fn add_header(self, name: HeaderParameter, value: ciborium::Value) -> Self;
}

impl HeaderBuilderExt for HeaderBuilder {
    fn add_header(self, name: HeaderParameter, value: ciborium::Value) -> Self {
        self.value(name.to_i64(), value)
    }
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

async fn try_extract_did(
    did_resolver: &dyn DidMethodProvider,
    holder_did: &DidValue,
    holder_key_id: Option<&String>,
) -> Result<PublicJwk, FormatterError> {
    let did_document = did_resolver
        .resolve(holder_did)
        .await
        .error_while("resolving did")?;

    for verification_method in did_document.verification_method {
        if holder_key_id.is_some_and(|key_id| key_id != &verification_method.id) {
            continue;
        }

        return Ok(verification_method.public_key_jwk);
    }

    Err(FormatterError::CouldNotVerify(format!(
        "Verification method not found: did:{holder_did}, keyId:{holder_key_id:?}"
    )))
}

fn build_json_value(value: DataElementValue) -> Result<serde_json::Value, FormatterError> {
    match value {
        ciborium::Value::Text(text) => Ok(serde_json::Value::String(text)),
        ciborium::Value::Bool(bool_value) => Ok(serde_json::Value::String(if bool_value {
            "true".to_string()
        } else {
            "false".to_string()
        })),
        ciborium::Value::Integer(number) => {
            let number_value: i128 = number.into();
            Ok(serde_json::Value::String(number_value.to_string()))
        }
        ciborium::Value::Tag(tag, tag_value) => match tag {
            TDATE_TAG => {
                let datetime = tag_value.into_text().map_err(|v| {
                    FormatterError::CouldNotExtractCredentials(format!(
                        "Expected tdate value. Got: {v:#?}",
                    ))
                })?;
                OffsetDateTime::parse(&datetime, &Rfc3339).map_err(|err| {
                    FormatterError::CouldNotExtractCredentials(format!(
                        "Invalid tdate `{datetime}`: {err}",
                    ))
                })?;

                Ok(serde_json::Value::String(datetime))
            }
            FULL_DATE_TAG => {
                let date = tag_value.into_text().map_err(|v| {
                    FormatterError::CouldNotExtractCredentials(format!(
                        "Expected tdate value. Got: {v:#?}",
                    ))
                })?;
                Date::parse(&date, FULL_DATE_FORMAT).map_err(|err| {
                    FormatterError::CouldNotExtractCredentials(format!(
                        "Invalid full-date `{date}`: {err}",
                    ))
                })?;

                Ok(serde_json::Value::String(date))
            }
            _ => Err(FormatterError::CouldNotExtractCredentials(format!(
                "Unexpected CBOR tag: {tag}"
            ))),
        },
        ciborium::Value::Bytes(bytes) => handle_bytes(&bytes),
        ciborium::Value::Array(array) => handle_array(array),
        ciborium::Value::Map(map) => {
            let mut map_content = serde_json::Map::new();
            for (key, value) in map {
                let key = key
                    .as_text()
                    .ok_or(FormatterError::CouldNotExtractCredentials(
                        "Expected a text".to_string(),
                    ))?;
                map_content.insert(key.to_owned(), build_json_value(value)?);
            }
            Ok(serde_json::Value::Object(map_content))
        }
        ciborium::Value::Null => Ok(serde_json::Value::Null),
        _ => Err(FormatterError::CouldNotExtractCredentials(format!(
            "Unexpected element value. Got: {value:#?}"
        ))),
    }
}

fn handle_array(array: Vec<ciborium::Value>) -> Result<serde_json::Value, FormatterError> {
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
        let data_type_value = array
            .first()
            .ok_or_else(|| FormatterError::CouldNotExtractCredentials("Invalid index".to_owned()))?
            .as_text()
            .ok_or_else(|| {
                FormatterError::CouldNotExtractCredentials(
                    "Expected String value for key".to_owned(),
                )
            })?;

        let bytes = array
            .get(1)
            .ok_or_else(|| FormatterError::CouldNotExtractCredentials("Invalid index".to_owned()))?
            .as_bytes()
            .ok_or_else(|| {
                FormatterError::CouldNotExtractCredentials("Not a byte array".to_owned())
            })?;
        let value = String::from_utf8_lossy(bytes);

        return Ok(serde_json::Value::String(format!(
            "{data_type_value},{value}"
        )));
    }

    Err(FormatterError::CouldNotExtractCredentials(
        "Unhandled array".to_owned(),
    ))
}

fn is_same_type(a: &ciborium::Value, b: &ciborium::Value) -> bool {
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
    let value = Base64::encode_to_string(bytes)?;
    Ok(serde_json::Value::String(format!(
        "data:image/jpeg;base64,{value}"
    )))
}

fn extract_claims(
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
                    metadata: false,
                    value: val.try_into()?,
                },
            );
        }
        result.insert(
            namespace,
            CredentialClaim {
                selectively_disclosable: true,
                metadata: false,
                value: CredentialClaimValue::Object(namespace_object_content),
            },
        );
    }

    Ok(result)
}

async fn parse_claims(
    namespaces: Namespaces,
    datatype_provider: &dyn DataTypeProvider,
    credential_id: CredentialId,
    credential_schema_format_id: CredentialSchemaFormatId,
) -> Result<(Vec<Claim>, Vec<CredentialSchemaFormatClaimSchema>), FormatterError> {
    let mut claims_with_schemas = vec![];
    let mut claim_mappings = vec![];
    for (namespace, inner_claims) in namespaces {
        for issuer_signed_item in inner_claims {
            let issuer_signed_item = issuer_signed_item.into_inner();
            let paths = Paths::new(
                issuer_signed_item.element_identifier.as_str(),
                namespace.as_str(),
            );
            let (claims, mappings) = parse_claim(
                paths,
                issuer_signed_item.element_value,
                datatype_provider,
                credential_id,
                credential_schema_format_id,
            )
            .await?;

            claims_with_schemas.extend(claims);
            claim_mappings.extend(mappings);
        }
    }

    let mut known_schemas: HashMap<String, ClaimSchema> = HashMap::new();
    for claim in claims_with_schemas.iter_mut() {
        let schema: ClaimSchema = claim.schema.as_ref().await?.to_owned();

        match known_schemas.get(&schema.key) {
            Some(matching_schema) => {
                let parsed_datatype = &schema.data_type;
                if &matching_schema.data_type != parsed_datatype {
                    tracing::warn!(
                        "Mismatch of detected datatype ({parsed_datatype:?}) of array claim: '{}'",
                        claim.path
                    );
                }

                // reuse the already inserted schema here (to match ids) of array siblings
                claim.schema = matching_schema.to_owned().into();
            }
            None => {
                known_schemas.insert(schema.key.to_owned(), schema);
            }
        };
    }
    // Only keep mappings of known schemas
    claim_mappings.retain(|m| known_schemas.values().any(|cs| cs.id == m.claim_schema_id));
    Ok((claims_with_schemas, claim_mappings))
}

struct Paths {
    claim_schema_path: String,
    claim_path: String,
    technical_path: String,
    namespace: String,
    root_level: bool,
}

impl Paths {
    fn new(root_identifier: &str, namespace: &str) -> Self {
        Self {
            claim_schema_path: root_identifier.to_owned(),
            claim_path: root_identifier.to_owned(),
            technical_path: root_identifier.to_owned(),
            namespace: namespace.to_owned(),
            root_level: true,
        }
    }
    fn claim_schema_path(&self) -> String {
        if self.root_level {
            return format!("{}_{}", self.namespace, self.claim_schema_path);
        }
        self.claim_schema_path.to_owned()
    }

    fn claim_path(&self) -> String {
        if self.root_level {
            return format!("{}_{}", self.namespace, self.claim_path);
        }
        self.claim_path.to_owned()
    }

    fn technical_path(&self) -> String {
        self.technical_path.to_owned()
    }

    fn namespace(&self) -> Option<String> {
        Some(self.namespace.to_owned())
    }

    fn is_root_level(&self) -> bool {
        self.root_level
    }

    fn nest_object_property(&self, property_name: &str) -> Self {
        Self {
            claim_schema_path: format!(
                "{}{NESTED_CLAIM_MARKER}{}",
                self.claim_schema_path(),
                property_name
            ),
            claim_path: format!(
                "{}{NESTED_CLAIM_MARKER}{}",
                self.claim_path(),
                property_name
            ),
            technical_path: format!(
                "{}{NESTED_CLAIM_MARKER}{}",
                self.technical_path(),
                property_name
            ),
            namespace: self.namespace.to_owned(),
            root_level: false,
        }
    }

    fn nest_array_index(&self, index: usize) -> Self {
        Self {
            claim_schema_path: self.claim_schema_path(),
            claim_path: format!("{}{NESTED_CLAIM_MARKER}{}", self.claim_path(), index),
            technical_path: self.technical_path(),
            namespace: self.namespace.to_owned(),
            root_level: false,
        }
    }
}

type ParsedClaims = (Vec<Claim>, Vec<CredentialSchemaFormatClaimSchema>);

// Boxed because the future is recursive.
fn parse_claim(
    paths: Paths,
    value: ciborium::Value,
    datatype_provider: &dyn DataTypeProvider,
    credential_id: CredentialId,
    credential_schema_format_id: CredentialSchemaFormatId,
) -> BoxFuture<'_, Result<ParsedClaims, FormatterError>> {
    Box::pin(parse_claim_inner(
        paths,
        value,
        datatype_provider,
        credential_id,
        credential_schema_format_id,
    ))
}

async fn parse_claim_inner(
    paths: Paths,
    value: ciborium::Value,
    datatype_provider: &dyn DataTypeProvider,
    credential_id: CredentialId,
    credential_schema_format_id: CredentialSchemaFormatId,
) -> Result<(Vec<Claim>, Vec<CredentialSchemaFormatClaimSchema>), FormatterError> {
    let now = crate::clock::now_utc();

    // specific case of encoding picture claim as array
    if matches!(value, ciborium::Value::Array(_))
        && let Ok(ExtractedClaim { data_type, value }) =
            datatype_provider.extract_cbor_claim(&value)
    {
        let claim = claim_with_schema(&paths, credential_id, now, data_type, Some(value));
        let mapping = mapping_for_claim(&claim, &paths, credential_schema_format_id);
        return Ok((vec![claim], vec![mapping]));
    }

    Ok(match value {
        ciborium::Value::Array(values) => {
            // Check if array has all elements with the same type
            let Some(first) = values.first() else {
                return Ok((vec![], vec![]));
            };
            if !values.iter().all(|item| is_same_type(item, first)) {
                return Err(FormatterError::CouldNotExtractCredentials(format!(
                    "Non-homogenous array at: {}",
                    paths.claim_path()
                )));
            }

            let mut claims = vec![];
            let mut mappings = vec![];
            for (index, value) in values.into_iter().enumerate() {
                let child_paths = paths.nest_array_index(index);
                let (child_claims, child_mappings) = parse_claim(
                    child_paths,
                    value,
                    datatype_provider,
                    credential_id,
                    credential_schema_format_id,
                )
                .await?;
                claims.extend(child_claims);
                mappings.extend(child_mappings);
            }

            // data type of the array elements based on first item data_type
            let Some(first) = claims.first() else {
                return Ok((vec![], vec![]));
            };
            let first_data_type = first.schema.as_ref().await?.data_type.to_owned();

            let mut claim = claim_with_schema(&paths, credential_id, now, first_data_type, None);
            claim.schema.as_mut().await?.array = true;
            let mapping = mapping_for_claim(&claim, &paths, credential_schema_format_id);
            // Insert parent claim & mapping _first_ so that it's schema (with the array flag set) will be used
            // as the main schema for all child claims.
            claims.insert(0, claim);
            mappings.push(mapping);
            (claims, mappings)
        }
        ciborium::Value::Map(map) => {
            let mut claims = vec![];
            let mut mappings = vec![];
            for (key, value) in map {
                let key = key.as_text().ok_or(FormatterError::JsonMapping(
                    "Expected a text map key".to_string(),
                ))?;
                let item_paths = paths.nest_object_property(key);
                let (child_claims, child_mappings) = parse_claim(
                    item_paths,
                    value,
                    datatype_provider,
                    credential_id,
                    credential_schema_format_id,
                )
                .await?;
                claims.extend(child_claims);
                mappings.extend(child_mappings);
            }

            let claim = claim_with_schema(&paths, credential_id, now, "OBJECT".to_owned(), None);
            let mapping = mapping_for_claim(&claim, &paths, credential_schema_format_id);
            claims.push(claim);
            mappings.push(mapping);
            (claims, mappings)
        }
        simple_value => {
            let ExtractedClaim { data_type, value } = datatype_provider
                .extract_cbor_claim(&simple_value)
                .error_while("extracting CBOR claim")?;

            let claim = claim_with_schema(&paths, credential_id, now, data_type, Some(value));
            let mapping = mapping_for_claim(&claim, &paths, credential_schema_format_id);
            (vec![claim], vec![mapping])
        }
    })
}

fn mapping_for_claim(
    claim: &Claim,
    paths: &Paths,
    credential_schema_format_id: CredentialSchemaFormatId,
) -> CredentialSchemaFormatClaimSchema {
    CredentialSchemaFormatClaimSchema {
        id: Uuid::new_v4().into(),
        created_date: claim.created_date,
        last_modified: claim.last_modified,
        credential_schema_format_id,
        claim_schema_id: claim.schema.id(),
        technical_key: paths.technical_path(),
        namespace: paths.namespace(),
    }
}

fn claim_with_schema(
    paths: &Paths,
    credential_id: CredentialId,
    now: OffsetDateTime,
    data_type: String,
    value: Option<String>,
) -> Claim {
    Claim {
        id: Uuid::new_v4().into(),
        credential_id,
        created_date: now,
        last_modified: now,
        value,
        path: paths.claim_path(),
        selectively_disclosable: paths.is_root_level(),
        schema: ClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            key: paths.claim_schema_path(),
            data_type,
            array: false,
            metadata: false,
            required: false,
            translations: Default::default(),
        }
        .into(),
    }
}
