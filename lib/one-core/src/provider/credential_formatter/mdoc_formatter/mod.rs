use std::sync::Arc;

use async_trait::async_trait;
use coset::iana::{self, EnumI64};
use coset::{CoseKey, CoseKeyBuilder, Header, HeaderBuilder, ProtectedHeader};
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use indexmap::IndexMap;
use rand::RngCore;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use sha2::{Digest, Sha256, Sha384, Sha512};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::did_method::dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO};
use crate::provider::did_method::provider::DidMethodProvider;

use self::cose::CoseSign1Builder;
use self::mdoc::{
    Bstr, DateTime, DeviceKey, DeviceKeyInfo, DigestAlgorithm, DigestIDs, IssuerAuth, IssuerSigned,
    IssuerSignedItem, IssuerSignedItemBytes, MobileSecurityObject, MobileSecurityObjectBytes,
    MobileSecurityObjectVersion, Namespace, Namespaces, ValidityInfo, ValueDigests,
};

use super::model::{CredentialPresentation, Presentation};
use super::{
    AuthenticationFn, CredentialData, CredentialFormatter, FormatterCapabilities, VerificationFn,
};

mod cose;
mod mdoc;

#[cfg(test)]
mod test;

pub struct MdocFormatter {
    params: Params,
    did_method_provider: Arc<dyn DidMethodProvider>,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub mso_expires_in: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub mso_expected_update_in: Duration,
}

impl MdocFormatter {
    #[allow(clippy::new_without_default)]
    pub fn new(params: Params, did_method_provider: Arc<dyn DidMethodProvider>) -> Self {
        Self {
            params,
            did_method_provider,
        }
    }
}

#[async_trait]
impl CredentialFormatter for MdocFormatter {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &DidValue,
        algorithm: &str,
        _additional_context: Vec<String>,
        _additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        _json_ld_context_url: Option<String>,
        _custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        let credential_schema_id = credential.schema.id.ok_or_else(|| {
            FormatterError::Failed(
                "Cannot format credential, missing credential schema id".to_string(),
            )
        })?;

        let namespaces = try_build_namespaces(credential.claims)?;

        let cose_key = try_build_cose_key(&*self.did_method_provider, holder_did).await?;

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
        let payload = MobileSecurityObject {
            version: MobileSecurityObjectVersion::V1_0,
            digest_algorithm,
            value_digests: try_build_value_digests(&namespaces, digest_algorithm)?,
            device_key_info,
            doc_type: credential_schema_id,
            validity_info,
        };
        let payload = MobileSecurityObjectBytes(payload)
            .to_cbor_bytes()
            .map_err(|err| {
                FormatterError::Failed(format!(
                    "CBOR serialization failed for MobileSecurityObjectBytes: {err}"
                ))
            })?;

        let algorithm_header = try_build_algorithm_header(algorithm)?;

        let x5chain_header = build_x5chain_header(credential.issuer_did);

        let cose_sign1 = CoseSign1Builder::new()
            .protected(algorithm_header)
            .unprotected(x5chain_header)
            .payload(payload)
            .try_create_signature_with_provider(&[], &*auth_fn)
            .await
            .map_err(|err| FormatterError::CouldNotSign(err.to_string()))?
            .build();

        let issuer_signed = IssuerSigned {
            name_spaces: Some(namespaces),
            issuer_auth: IssuerAuth(cose_sign1),
        };

        let issuer_signed = issuer_signed.to_cbor().map_err(|err| {
            FormatterError::Failed(format!("CBOR serialization failed for IssuerSigned: {err}"))
        })?;

        Base64UrlSafeNoPadding::encode_to_string(issuer_signed)
            .map_err(|err| FormatterError::Failed(format!("Base64 encoding failed: {err}")))
    }

    async fn extract_credentials(
        &self,
        _credentials: &str,
        _verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        todo!()
    }

    async fn extract_credentials_unverified(
        &self,
        _token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        todo!()
    }

    async fn format_presentation(
        &self,
        _tokens: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _nonce: Option<String>,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn extract_presentation(
        &self,
        _token: &str,
        _verification: VerificationFn,
    ) -> Result<Presentation, FormatterError> {
        todo!()
    }

    async fn format_credential_presentation(
        &self,
        _credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    fn get_leeway(&self) -> u64 {
        todo!()
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            features: vec!["SELECTIVE_DISCLOSURE".to_string()],
            issuance_exchange_protocols: vec!["OPENID4VC".to_string()],
            proof_exchange_protocols: vec![],
            revocation_methods: vec!["NONE".to_string()],
            signing_key_algorithms: vec!["EDDSA".to_string(), "ES256".to_string()],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        _token: &str,
    ) -> Result<Presentation, FormatterError> {
        todo!()
    }
}

fn try_build_namespaces(claims: Vec<(String, String)>) -> Result<Namespaces, FormatterError> {
    let mut namespaces = IndexMap::<String, Vec<IssuerSignedItemBytes>>::new();

    for (digest_id, (path, value)) in claims.into_iter().enumerate() {
        let (namespace, name) = path.split_once('/').ok_or_else(|| {
            FormatterError::Failed(format!(
                "Invalid claim path without top-level object: {path}"
            ))
        })?;

        // random has to be minimum 16 bytes
        let random = {
            let mut r = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut r);

            Bstr(r)
        };

        let signed_item = IssuerSignedItem {
            digest_id: digest_id as u64,
            random,
            element_identifier: name.to_owned(),
            element_value: ciborium::Value::from(value),
        };

        namespaces
            .entry(namespace.to_owned())
            .or_default()
            .push(IssuerSignedItemBytes(signed_item));
    }

    Ok(namespaces)
}

fn build_x5chain_header(issuer_did: DidValue) -> Header {
    let x5chain_label = coset::iana::HeaderParameter::X5Chain;
    let x5chain_value = ciborium::Value::Bytes(issuer_did.to_string().into_bytes());

    HeaderBuilder::new()
        .value(x5chain_label.to_i64(), x5chain_value)
        .build()
}

fn try_build_algorithm_header(algorithm: &str) -> Result<ProtectedHeader, FormatterError> {
    let algorithm = match algorithm {
        "ES256" => iana::Algorithm::ES256,
        "EDDSA" => iana::Algorithm::EdDSA,
        _ => {
            return Err(FormatterError::Failed(format!(
                "Failed mapping algorithm `{algorithm}` to name compatible with allowed COSE Algorithms"
            )))
        }
    };
    let algorithm_header = coset::HeaderBuilder::new().algorithm(algorithm).build();

    Ok(ProtectedHeader {
        original_data: None,
        header: algorithm_header,
    })
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

        for signed_item_bytes @ IssuerSignedItemBytes(item) in signed_items {
            let item_as_cbor = signed_item_bytes.to_embedded_cbor().map_err(|err| {
                FormatterError::Failed(format!(
                    "Failed encoding signed item as embedded CBOR : {err}"
                ))
            })?;
            let digest = digest_fn(item_as_cbor);

            let digest_id = item.digest_id;
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
        PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
            crv, x, y: Some(y), ..
        }) if &crv == "P-256" => {
            let x = base64decode(x)?;
            let y = base64decode(y)?;

            CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y).build()
        }

        PublicKeyJwkDTO::Okp(key) if key.crv == "Ed25519" => {
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
            )))
        }
    };

    Ok(cose_key)
}
