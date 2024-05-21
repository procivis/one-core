use std::any::type_name;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use coset::iana::{self, EnumI64};
use coset::{
    CoseKey, CoseKeyBuilder, Header, HeaderBuilder, Label, ProtectedHeader,
    RegisteredLabelWithPrivate, SignatureContext,
};
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use indexmap::{IndexMap, IndexSet};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use sha2::{Digest, Sha256, Sha384, Sha512};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use crate::crypto::signer::error::SignerError;
use crate::model::credential_schema::CredentialSchemaType;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::did_method::dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO};
use crate::provider::did_method::provider::DidMethodProvider;

use self::cose::CoseSign1Builder;
use self::mdoc::{
    Bstr, Bytes, CoseSign1, DateTime, DeviceAuth, DeviceAuthentication, DeviceKey, DeviceKeyInfo,
    DeviceResponse, DeviceResponseVersion, DeviceSigned, DigestAlgorithm, DigestIDs, Document,
    IssuerSigned, IssuerSignedItem, MobileSecurityObject, MobileSecurityObjectVersion, Namespace,
    Namespaces, OID4VPHandover, SessionTranscript, ValidityInfo, ValueDigests,
};

use super::common::nest_claims;
use super::model::{CredentialPresentation, CredentialSchema, CredentialSubject, Presentation};
use super::{
    AuthenticationFn, CredentialData, CredentialFormatter, ExtractCredentialsCtx,
    ExtractPresentationCtx, FormatPresentationCtx, FormatterCapabilities, SignatureProvider,
    TokenVerifier, VerificationFn,
};

mod cose;
mod mdoc;

#[cfg(test)]
mod test;

pub struct MdocFormatter {
    params: Params,
    did_method_provider: Arc<dyn DidMethodProvider>,
    base_url: Option<String>,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub mso_expires_in: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub mso_expected_update_in: Duration,
    pub leeway: u64,
}

impl MdocFormatter {
    #[allow(clippy::new_without_default)]
    pub fn new(
        params: Params,
        did_method_provider: Arc<dyn DidMethodProvider>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            params,
            did_method_provider,
            base_url,
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
        let mso = MobileSecurityObject {
            version: MobileSecurityObjectVersion::V1_0,
            digest_algorithm,
            value_digests: try_build_value_digests(&namespaces, digest_algorithm)?,
            device_key_info,
            doc_type: credential_schema_id,
            validity_info,
        };
        let mso = Bytes::<MobileSecurityObject>(mso)
            .to_cbor_bytes()
            .map_err(|err| {
                FormatterError::Failed(format!(
                    "CBOR serialization failed for MobileSecurityObjectBytes: {err}"
                ))
            })?;

        let algorithm_header = try_build_algorithm_header(algorithm)?;

        let x5chain_header = build_x5chain_header(credential.issuer_did)?;

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

    async fn extract_credentials(
        &self,
        token: &str,
        _verification: VerificationFn,
        ctx: ExtractCredentialsCtx,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(token, true, ctx)
    }

    async fn extract_credentials_unverified(
        &self,
        token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(token, false, ExtractCredentialsCtx::default())
    }

    async fn format_presentation(
        &self,
        tokens: &[String],
        _holder_did: &DidValue,
        algorithm: &str,
        auth_fn: AuthenticationFn,
        context: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        let FormatPresentationCtx {
            nonce: Some(nonce),
            mdoc_generated_nonce: Some(mdoc_generated_nonce),
            client_id: Some(client_id),
            response_uri: Some(response_uri),
        } = context
        else {
            return Err(FormatterError::Failed(format!(
                "Cannot format mdoc presentation invalid context `{context:?}`. All fields must be present."
            )));
        };

        let mut documents = Vec::with_capacity(tokens.len());
        for token in tokens {
            let issuer_signed: IssuerSigned = decode_cbor_base64(token)?;
            let mso = try_extract_mobile_security_object(&issuer_signed.issuer_auth)?;
            let doc_type = mso.doc_type;

            let device_signed = try_build_device_signed(
                &*auth_fn,
                algorithm,
                &nonce,
                &mdoc_generated_nonce,
                &doc_type,
                &client_id,
                &response_uri,
            )
            .await?;

            let document = Document {
                doc_type,
                issuer_signed,
                device_signed,
                errors: None,
            };

            documents.push(document);
        }

        let device_response = DeviceResponse {
            version: DeviceResponseVersion::V1_0,
            documents: Some(documents),
            document_errors: None,
            // this will be != 0 if document errors is not None
            status: 0,
        };

        encode_cbor_base64(device_response)
    }

    async fn extract_presentation(
        &self,
        token: &str,
        verification: VerificationFn,
        context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let device_response_signed: DeviceResponse = decode_cbor_base64(token)?;

        let documents =
            device_response_signed
                .documents
                .ok_or(FormatterError::CouldNotExtractPresentation(
                    "Missing docs".to_string(),
                ))?;

        let mut tokens: Vec<String> = Vec::with_capacity(documents.len());

        let holder_did = context.holder_did.ok_or_else(|| {
            FormatterError::Failed(
                "Extract presentation context for MDOC is missing holder DID".to_owned(),
            )
        })?;

        let nonce = &context
            .nonce
            .ok_or(FormatterError::CouldNotExtractPresentation(
                "Missing nonce".to_owned(),
            ))?;

        for document in documents {
            let issuer_signed = document.issuer_signed;
            let issuer_did = extract_did_from_x5chain_header(&issuer_signed.issuer_auth)?;

            try_verify_issuer_auth(&issuer_signed.issuer_auth, &issuer_did, &verification).await?;
            let _holder_public_key = try_extract_holder_public_key(&issuer_signed.issuer_auth)?;

            //try verify device signed
            let device_signed = document.device_signed;
            let doc_type = document.doc_type;

            let signature: coset::CoseSign1 = device_signed
                .device_auth
                .device_signature
                .ok_or(FormatterError::CouldNotExtractPresentation(
                    "Missing device signature".to_owned(),
                ))?
                .0;

            let base_url =
                self.base_url
                    .as_ref()
                    .ok_or(FormatterError::CouldNotExtractPresentation(
                        "Missing base_url".to_owned(),
                    ))?;

            let client_id = Url::parse(&format!("{}/ssi/oidc-verifier/v1/response", base_url))
                .map_err(|_| {
                    FormatterError::CouldNotExtractPresentation(
                        "Could not create client_id for validation".to_owned(),
                    )
                })?;

            let mdoc_generated_nonce = context.mdoc_generated_nonce.as_ref().ok_or(
                FormatterError::CouldNotExtractPresentation(
                    "Missing mdoc_generated_nonce".to_owned(),
                ),
            )?;

            try_verify_device_signed(
                nonce,
                // todo: this needs to be extracted from the JWE params
                mdoc_generated_nonce,
                &doc_type,
                &client_id,
                &client_id,
                &signature,
                &holder_did,
                &verification,
            )
            .await?;

            tokens.push(encode_cbor_base64(issuer_signed)?)
        }

        // todo transfer issued and expires from the token
        Ok(Presentation {
            id: Some(Uuid::new_v4().to_string()),
            issued_at: context.issuance_date,
            expires_at: context.expiration_date,
            issuer_did: Some(holder_did),
            nonce: Some(nonce.clone()),
            credentials: tokens,
        })
    }

    // Extract issuer_signed, keep only the claims that the verifier asked for, re-encode issuer_signed that back to the same format
    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        let mut issuer_signed: IssuerSigned = decode_cbor_base64(&credential.token)?;

        let Some(namespaces) = issuer_signed.name_spaces.as_mut() else {
            return Err(FormatterError::Failed(
                "IssuerSigned object is missing namespaces".to_owned(),
            ));
        };

        let (root_keys, suffix_paths): (IndexSet<_>, IndexSet<_>) = credential
            .disclosed_keys
            .iter()
            .filter_map(|key| key.split_once('/'))
            .unzip();

        // keep only the claims that we were asked for
        namespaces.retain(|root, claims| {
            if !root_keys.contains(root.as_str()) {
                return false;
            }

            claims.retain(|claim| suffix_paths.contains(&claim.0.element_identifier.as_str()));
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
            features: vec!["SELECTIVE_DISCLOSURE".to_string()],
            issuance_did_methods: vec!["MDL".to_string()],
            issuance_exchange_protocols: vec!["OPENID4VC".to_string()],
            proof_exchange_protocols: vec!["OPENID4VC".to_string()],
            revocation_methods: vec!["NONE".to_string()],
            signing_key_algorithms: vec!["EDDSA".to_string(), "ES256".to_string()],
            verification_key_algorithms: vec!["EDDSA".to_string(), "ES256".to_string()],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let device_response_signed: DeviceResponse = decode_cbor_base64(token)?;

        let documents =
            device_response_signed
                .documents
                .ok_or(FormatterError::CouldNotExtractPresentation(
                    "Missing docs".to_string(),
                ))?;

        let tokens = documents
            .into_iter()
            .map(|doc| encode_cbor_base64(doc.issuer_signed))
            .collect::<Result<Vec<String>, FormatterError>>()?;

        // todo transfer issued and expires from the token
        Ok(Presentation {
            id: Some(Uuid::new_v4().to_string()),
            issued_at: context.issuance_date,
            expires_at: context.expiration_date,
            issuer_did: None,
            nonce: context.nonce,
            credentials: tokens,
        })
    }
}

fn try_extract_holder_public_key(
    CoseSign1(issuer_auth): &CoseSign1,
) -> Result<PublicKeyJwkDTO, FormatterError> {
    let mso = issuer_auth
        .payload
        .as_ref()
        .ok_or_else(|| FormatterError::Failed("Issuer auth missing mso object".to_owned()))?;

    let Bytes(mso): Bytes<MobileSecurityObject> = ciborium::from_reader(&mso[..])
        .map_err(|err| FormatterError::Failed(format!("Failed deserializing MSO: {err}")))?;

    let DeviceKey(cose_key) = mso.device_key_info.device_key;

    let get_param_value = |key| {
        cose_key
            .params
            .iter()
            .find_map(|(k, v)| (k == &key).then_some(v))
    };

    match cose_key.kty {
        coset::RegisteredLabel::Assigned(iana::KeyType::EC2) => (|| -> anyhow::Result<_> {
            let _crv = get_param_value(Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))
                .and_then(|v| v.as_integer())
                .filter(|v| v == &iana::EllipticCurve::P_256.to_i64().into())
                .context("Missing P-256 curve in params")?;

            let x = get_param_value(Label::Int(iana::Ec2KeyParameter::X.to_i64()))
                .and_then(|v| v.as_bytes())
                .and_then(|v| Base64UrlSafeNoPadding::encode_to_string(v).ok())
                .context("Missing P-256 X value in params")?;

            let y = get_param_value(Label::Int(iana::Ec2KeyParameter::Y.to_i64()))
                .and_then(|v| v.as_bytes())
                .and_then(|v| Base64UrlSafeNoPadding::encode_to_string(v).ok())
                .context("Missing P-256  Y value in params")?;

            let key = PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
                r#use: None,
                crv: "P-256".to_owned(),
                x,
                y: Some(y),
            });

            Ok(key)
        })()
        .map_err(|err| {
            FormatterError::Failed(format!("Cannot build P-256 public key from CoseKey: {err}"))
        }),

        coset::RegisteredLabel::Assigned(iana::KeyType::OKP) => (|| -> anyhow::Result<_> {
            let _crv = get_param_value(Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))
                .and_then(|v| v.as_integer())
                .filter(|v| v == &iana::EllipticCurve::Ed25519.to_i64().into())
                .context("Missing Ed25519 curve in params")?;

            let x = get_param_value(Label::Int(iana::Ec2KeyParameter::X.to_i64()))
                .and_then(|v| v.as_bytes())
                .and_then(|v| Base64UrlSafeNoPadding::encode_to_string(v).ok())
                .context("Missing Ed25519 X value in params")?;

            let key = PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
                r#use: None,
                crv: "Ed25519".to_owned(),
                x,
                y: None,
            });

            Ok(key)
        })()
        .map_err(|err| {
            FormatterError::Failed(format!(
                "Cannot build Ed25519 public key from CoseKey: {err}"
            ))
        }),
        other => Err(FormatterError::Failed(format!(
            "CoseKey contains invalid kty `{other:?}`, only EC2 and OKP keys are supported"
        ))),
    }
}

async fn try_verify_issuer_auth(
    CoseSign1(cose_sign1): &CoseSign1,
    issuer_did: &DidValue,
    verifier: &dyn TokenVerifier,
) -> Result<(), FormatterError> {
    let token = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        cose_sign1.protected.clone(),
        None,
        &[],
        cose_sign1.payload.as_ref().unwrap_or(&vec![]),
    );

    let algorithm = extract_algorithm_from_header(cose_sign1).ok_or_else(|| {
        FormatterError::CouldNotVerify("IssuerAuth is missing algorithm information".to_owned())
    })?;

    let signature = &cose_sign1.signature;

    verifier
        .verify(
            Some(issuer_did.clone()),
            None,
            &algorithm,
            &token,
            signature,
        )
        .await
        .map_err(|err| FormatterError::CouldNotVerify(err.to_string()))
}

fn extract_credentials_internal(
    token: &str,
    verify: bool,
    ctx: ExtractCredentialsCtx,
) -> Result<DetailCredential, FormatterError> {
    let token = Base64UrlSafeNoPadding::decode_to_vec(token, None)
        .map_err(|err| FormatterError::Failed(format!("Base64 decoding failed: {err}")))?;

    let issuer_signed: IssuerSigned = ciborium::from_reader(&token[..])
        .map_err(|err| FormatterError::Failed(format!("Issuer signed decoding failed: {err}")))?;

    let issuer_did = extract_did_from_x5chain_header(&issuer_signed.issuer_auth)?;
    let mso = try_extract_mobile_security_object(&issuer_signed.issuer_auth)?;
    let Some(namespaces) = issuer_signed.name_spaces else {
        return Err(FormatterError::Failed(
            "IssuerSigned object is missing namespaces".to_owned(),
        ));
    };

    if verify {
        let digest_algo = mso.digest_algorithm;
        let digest_fn = |data: Vec<u8>| match digest_algo {
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

            for signed_item_bytes in signed_items {
                let signed_item = &signed_item_bytes.0;
                let digest_id = digest_ids.get(&signed_item.digest_id).ok_or(
                    FormatterError::CouldNotExtractCredentials("Missing digest_ids".to_owned()),
                )?;

                let item_as_cbor = signed_item_bytes.to_cbor_bytes().map_err(|err| {
                    FormatterError::Failed(format!(
                        "Failed encoding signed item as embedded CBOR : {err}"
                    ))
                })?;

                let digest = digest_fn(item_as_cbor);

                if digest != digest_id.0 {
                    return Err(FormatterError::CouldNotExtractCredentials(
                        "Invalid digest_id".to_owned(),
                    ));
                }
            }
        }
    }

    let claims = try_extract_claims(namespaces)?;

    Ok(DetailCredential {
        id: None,
        issued_at: Some(mso.validity_info.valid_from.into()),
        expires_at: Some(mso.validity_info.valid_until.into()),
        invalid_before: None,
        issuer_did: Some(issuer_did),
        subject: ctx.holder_did,
        claims: CredentialSubject { values: claims },
        status: vec![],
        credential_schema: Some(CredentialSchema {
            id: mso.doc_type,
            r#type: CredentialSchemaType::Mdoc,
        }),
    })
}

async fn try_build_device_signed(
    auth_fn: &dyn SignatureProvider,
    algorithm: &str,
    nonce: &str,
    mdoc_generated_nonce: &str,
    doctype: &str,
    client_id: &Url,
    response_uri: &Url,
) -> Result<DeviceSigned, FormatterError> {
    let session_transcript = SessionTranscript {
        handover: OID4VPHandover::compute(client_id, response_uri, nonce, mdoc_generated_nonce),
    };
    let device_namespaces_bytes = Bytes([].into());

    let device_auth = DeviceAuthentication {
        session_transcript: Bytes(session_transcript),
        doctype: doctype.to_owned(),
        device_namespaces: device_namespaces_bytes.clone(),
    };
    let device_auth_bytes = Bytes(device_auth).to_cbor_bytes().map_err(|err| {
        FormatterError::Failed(format!(
            "CBOR serialization failed for DeviceAuthentication: {err}"
        ))
    })?;

    let algorithm_header = try_build_algorithm_header(algorithm)?;
    let cose_sign1 = CoseSign1Builder::new()
        .protected(algorithm_header)
        .try_create_detached_signature_with_provider(&device_auth_bytes, &[], auth_fn)
        .await
        .map_err(|err| FormatterError::CouldNotSign(err.to_string()))?
        .build();

    let device_auth = DeviceAuth {
        device_signature: Some(cose_sign1.into()),
    };

    let device_signed = DeviceSigned {
        name_spaces: device_namespaces_bytes,
        device_auth,
    };

    Ok(device_signed)
}

#[allow(clippy::too_many_arguments)]
async fn try_verify_device_signed(
    nonce: &str,
    mdoc_generated_nonce: &str,
    doctype: &str,
    client_id: &Url,
    response_uri: &Url,
    signature: &coset::CoseSign1,
    holder_did: &shared_types::DidValue,
    verify_fn: &VerificationFn,
) -> Result<(), FormatterError> {
    let session_transcript = SessionTranscript {
        handover: OID4VPHandover::compute(client_id, response_uri, nonce, mdoc_generated_nonce),
    };
    let device_namespaces_bytes = Bytes([].into());

    let device_auth = DeviceAuthentication {
        session_transcript: Bytes(session_transcript),
        doctype: doctype.to_owned(),
        device_namespaces: device_namespaces_bytes,
    };
    let device_auth_bytes = Bytes(device_auth).to_cbor_bytes().map_err(|err| {
        FormatterError::Failed(format!(
            "CBOR serialization failed for DeviceAuthentication: {err}"
        ))
    })?;

    try_verify_detached_signature_with_provider(
        signature,
        &device_auth_bytes,
        &[],
        holder_did,
        verify_fn,
    )
    .await
    .map_err(|e| FormatterError::CouldNotSign(e.to_string()))
}

pub async fn try_verify_detached_signature_with_provider(
    device_signature: &coset::CoseSign1,
    payload: &[u8],
    external_aad: &[u8],
    issuer_did_value: &DidValue,
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

    verifier
        .verify(
            Some(issuer_did_value.to_owned()),
            None, /* take the first one */
            &algorithm,
            &sig_data,
            signature,
        )
        .await
}

fn try_build_namespaces(claims: Vec<(String, String)>) -> Result<Namespaces, FormatterError> {
    let mut namespaces = Namespaces::new();

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
            .push(Bytes::<IssuerSignedItem>(signed_item));
    }

    Ok(namespaces)
}

fn build_x5chain_header(issuer_did: DidValue) -> Result<Header, FormatterError> {
    let x5chain_label = coset::iana::HeaderParameter::X5Chain.to_i64();

    let body = issuer_did
        .as_str()
        .strip_prefix("did:mdl:certificate:")
        .ok_or_else(|| FormatterError::CouldNotFormat("Invalid mdl did".into()))?;

    let decoded = Base64UrlSafeNoPadding::decode_to_vec(body, None)
        .map_err(|e| FormatterError::CouldNotFormat(format!("Base64url decoding failed: {e}")))?;

    let x5chain_value = ciborium::Value::Bytes(decoded);

    Ok(HeaderBuilder::new()
        .value(x5chain_label, x5chain_value)
        .build())
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

fn extract_did_from_x5chain_header(
    CoseSign1(cose_sign1): &CoseSign1,
) -> Result<DidValue, FormatterError> {
    let x5chain_label = Label::Int(coset::iana::HeaderParameter::X5Chain.to_i64());

    cose_sign1
        .unprotected
        .rest
        .iter()
        .find(|(label, _)| label == &x5chain_label)
        .context(anyhow::anyhow!("Missing x5chain header"))
        .and_then(|(_, value)| {
            let value = value
                .as_bytes()
                .context(anyhow::anyhow!("Invalid value for x5chain header"))?;

            let (_, _certificate) = x509_parser::parse_x509_certificate(value)
                .map_err(|err| anyhow::anyhow!("Invalid x509 certificate: {err}"))?;

            let did = Base64UrlSafeNoPadding::encode_to_string(value)
                .map(|cert| format!("did:mdl:certificate:{cert}"))
                .map_err(|err| anyhow::anyhow!("Base64 encoding failed: {err}"))?;

            match DidValue::from_str(&did) {
                Ok(did) => Ok(did),
                Err(err) => match err {},
            }
        })
        .map_err(|err| FormatterError::Failed(format!("Failed extracting x5chain header {err}")))
}

fn extract_algorithm_from_header(cose_sign1: &coset::CoseSign1) -> Option<String> {
    let alg = &cose_sign1.protected.header.alg;

    if let Some(RegisteredLabelWithPrivate::Assigned(algorithm)) = alg {
        match algorithm {
            iana::Algorithm::ES256 => Some("ES256".to_owned()),
            iana::Algorithm::EdDSA => Some("EDDSA".to_owned()),
            _ => None,
        }
    } else {
        None
    }
}

fn try_extract_mobile_security_object(
    CoseSign1(cose_sign1): &CoseSign1,
) -> Result<MobileSecurityObject, FormatterError> {
    let Some(payload) = &cose_sign1.payload else {
        return Err(FormatterError::Failed(
            "IssuerAuth doesn't contain payload".to_owned(),
        ));
    };

    let Bytes::<MobileSecurityObject>(mso) =
        ciborium::from_reader(&payload[..]).map_err(|err| {
            FormatterError::Failed(format!(
                "IssuerAuth payload cannot be converted to MSO: {err}"
            ))
        })?;

    Ok(mso)
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

        for signed_item_bytes @ Bytes::<IssuerSignedItem>(item) in signed_items {
            let item_as_cbor = signed_item_bytes.to_cbor_bytes().map_err(|err| {
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

fn try_extract_claims(
    namespaces: Namespaces,
) -> Result<HashMap<String, serde_json::Value>, FormatterError> {
    let mut claims = vec![];

    for (root, inner_claims) in namespaces {
        for Bytes::<IssuerSignedItem>(claim) in inner_claims {
            let path = format!("{root}/{}", claim.element_identifier);
            let value = claim.element_value.into_text().map_err(|err| {
                FormatterError::Failed(format!(
                    "Expected String value for key `{path}` got {err:?}"
                ))
            })?;

            claims.push((path, value))
        }
    }

    nest_claims(claims)
}

fn encode_cbor_base64<T: Serialize>(t: T) -> Result<String, FormatterError> {
    let type_name = type_name::<T>();
    let mut bytes = vec![];

    ciborium::ser::into_writer(&t, &mut bytes).map_err(|err| {
        FormatterError::Failed(format!("CBOR serialization of `{type_name}` failed: {err}"))
    })?;

    Base64UrlSafeNoPadding::encode_to_string(bytes)
        .map_err(|err| FormatterError::Failed(format!("Base64 encoding failed: {err}")))
}

fn decode_cbor_base64<T: DeserializeOwned>(s: &str) -> Result<T, FormatterError> {
    let bytes = Base64UrlSafeNoPadding::decode_to_vec(s, None)
        .map_err(|err| FormatterError::Failed(format!("Base64 decoding failed: {err}")))?;

    let type_name = type_name::<T>();
    ciborium::de::from_reader(&bytes[..]).map_err(|err| {
        FormatterError::Failed(format!(
            "CBOR deserialization into `{type_name}` failed: {err}"
        ))
    })
}
