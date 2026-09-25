use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use standardized_types::etsi_119_602::json::OtherLoTEPointer;
use standardized_types::etsi_119_602::{json, xml};
use standardized_types::xades::SIGNED_PROPERTIES_TYPE;
use time::OffsetDateTime;

use super::LoteContentType;
use super::preprocessing::{merge_lote, preprocess_lote};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::did::KeyRole;
use crate::proto::certificate_validator::{CertificateValidationOptions, CertificateValidator};
use crate::proto::http_client::{HttpClient, is_media_type};
use crate::proto::jwt::Jwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::xades::{XAdESProto, XAdESSignedXML, XAdESVerified};
use crate::provider::caching_loader::{ResolveResult, Resolver, ResolverError};
use crate::provider::credential_formatter::model::PublicKeySource;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

/// PEM of the pointer's first `ServiceDigitalIdentity` X.509 cert.
fn pointer_signer_cert_pem(pointer: &OtherLoTEPointer) -> Option<String> {
    let cert_b64 = pointer
        .service_digital_identities
        .iter()
        .find_map(|identity| identity.x509_certificates.as_ref())
        .and_then(|certs| certs.first())
        .map(|pki| pki.val.clone())?;
    x5c_into_pem_chain(std::slice::from_ref(&cert_b64)).ok()
}

fn assert_lote_signature_policy(
    verified: &XAdESVerified,
    leeway: time::Duration,
    now: OffsetDateTime,
) -> Result<(), ResolverError> {
    if verified.signing_time > now + leeway {
        return Err(ResolverError::InvalidResponse(
            "LoTE signing time is in the future".to_string(),
        ));
    }
    let doc_ok = verified.references.iter().any(|r| r.uri.is_empty());
    if !doc_ok {
        return Err(ResolverError::InvalidResponse(
            "LoTE signature does not cover the document".to_string(),
        ));
    }
    let sp_ok = verified
        .references
        .iter()
        .any(|r| r.r#type.as_deref() == Some(SIGNED_PROPERTIES_TYPE));
    if !sp_ok {
        return Err(ResolverError::InvalidResponse(
            "LoTE signature does not cover the SignedProperties".to_string(),
        ));
    }
    Ok(())
}

pub struct EtsiLoteResolver {
    client: Arc<dyn HttpClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    xades_proto: Arc<dyn XAdESProto>,
    content_type: LoteContentType,
    leeway: time::Duration,
    /// Maximum `PointersToOtherLoTE` depth to follow; `None` = no limit.
    max_pointer_depth: Option<usize>,
}

impl EtsiLoteResolver {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        xades_proto: Arc<dyn XAdESProto>,
        content_type: LoteContentType,
        leeway: time::Duration,
        max_pointer_depth: Option<usize>,
    ) -> Self {
        Self {
            client,
            did_method_provider,
            key_algorithm_provider,
            certificate_validator,
            xades_proto,
            content_type,
            leeway,
            max_pointer_depth,
        }
    }
}

impl EtsiLoteResolver {
    /// Fetch a LoTE from `url`, verify its signature, and check expiry. `pin`,
    /// when set, is the parent pointer's certificate the recovered signer must
    /// match; the root LoTE passes `None`.
    async fn fetch_and_verify(
        &self,
        url: &str,
        pin: Option<&str>,
    ) -> Result<json::LoTEPayload, ResolverError> {
        let content_type = self.content_type.to_string();
        let response = async {
            self.client
                .get(url)
                .header("Accept", &content_type)
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("Downloading ETSI LoTE")?;
        let response_content_type = response
            .header_get("Content-Type")
            .ok_or_else(|| {
                ResolverError::InvalidResponse("header Content-Type not present".to_string())
            })?
            .to_owned();
        if !is_media_type(&response_content_type, &content_type) {
            return Err(ResolverError::InvalidResponse(format!(
                "Unexpected content type `{response_content_type}`, expected `{content_type}`"
            )));
        }

        let (lote, signer_pem) =
            match self.content_type {
                LoteContentType::Jwt => {
                    let decomposed_token =
                        Jwt::<json::LoTEDocument>::decompose_token(str::from_utf8(&response.body)?)
                            .error_while("parsing ETSI LoTE JWT")?;

                    let x5c = decomposed_token.header.x5c.as_ref().ok_or(
                        ResolverError::InvalidResponse("missing x5c header claim".to_string()),
                    )?;
                    let signer_pem = x5c_into_pem_chain(x5c).error_while("parsing x5c")?;

                    let pub_key_source = PublicKeySource::X5c { x5c };
                    let verification = KeyVerification {
                        did_method_provider: self.did_method_provider.clone(),
                        key_algorithm_provider: self.key_algorithm_provider.clone(),
                        certificate_validator: self.certificate_validator.clone(),
                        key_role: KeyRole::AssertionMethod,
                    };
                    decomposed_token
                        .verify_signature(pub_key_source, &verification)
                        .await
                        .error_while("verifying ETSI LoTE JWT signature")?;
                    (decomposed_token.payload.custom.lote, signer_pem)
                }
                LoteContentType::Xml => {
                    let signed_xml = XAdESSignedXML::<xml::LoTEPayload>::decompose_document(
                        str::from_utf8(&response.body)?,
                    )
                    .error_while("parsing ETSI LoTE XML")?;

                    let verified = self
                        .xades_proto
                        .verify_enveloped_signature(signed_xml.envelope())
                        .await
                        .error_while("verifying ETSI LoTE XML signature")?;

                    assert_lote_signature_policy(&verified, self.leeway, crate::clock::now_utc())?;

                    (signed_xml.content.into(), verified.signer_chain_pem)
                }
            };

        if let Some(expected) = pin {
            self.pin_signer(&signer_pem, expected).await?;
        }

        let expiry = lote.list_and_scheme_information.next_update;
        if expiry + self.leeway < crate::clock::now_utc() {
            return Err(ResolverError::InvalidResponse(
                "LoTE trust list is expired".to_string(),
            ));
        }
        Ok(lote)
    }

    /// Require the recovered signer to match `expected_pem`, by fingerprint.
    async fn pin_signer(&self, signer_pem: &str, expected_pem: &str) -> Result<(), ResolverError> {
        let signer_fp = self.fingerprint_of(signer_pem).await?;
        let expected_fp = self.fingerprint_of(expected_pem).await?;
        if signer_fp != expected_fp {
            return Err(ResolverError::InvalidResponse(
                "pointed-to LoTE signer does not match the pointer's certificate".to_string(),
            ));
        }
        Ok(())
    }

    async fn fingerprint_of(&self, pem: &str) -> Result<String, ResolverError> {
        let parsed = self
            .certificate_validator
            .parse_pem_chain(pem, CertificateValidationOptions::no_validation())
            .await
            .error_while("parsing certificate for signer pinning")?;
        Ok(parsed.attributes.fingerprint)
    }
}

#[async_trait::async_trait]
impl Resolver for EtsiLoteResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let media_type = self.content_type.to_string();

        let mut root = self.fetch_and_verify(key, None).await?;
        let mut earliest_expiry = root.list_and_scheme_information.next_update;

        // Follow `PointersToOtherLoTE` breadth-first; the visited-set breaks
        // cycles, `max_pointer_depth` bounds the chain.
        let mut queue: VecDeque<(OtherLoTEPointer, usize)> = root
            .list_and_scheme_information
            .pointers_to_other_lote
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|pointer| (pointer, 1))
            .collect();

        let mut aggregate = preprocess_lote(
            root,
            self.certificate_validator.as_ref(),
            self.key_algorithm_provider.as_ref(),
        )
        .await
        .error_while("preprocessing ETSI LoTE")?;

        let mut visited = HashSet::from([key.to_string()]);

        while let Some((pointer, depth)) = queue.pop_front() {
            if self.max_pointer_depth.is_some_and(|max| depth > max) {
                tracing::warn!(url = %pointer.lote_location, "skipping LoTE pointer beyond max depth");
                continue;
            }
            if !visited.insert(pointer.lote_location.clone()) {
                continue;
            }
            let Some(expected_cert) = pointer_signer_cert_pem(&pointer) else {
                tracing::warn!(url = %pointer.lote_location, "skipping LoTE pointer with no signing identity");
                continue;
            };

            // fail-safe: drop a child that fails to fetch/verify, don't fail the aggregate
            let mut child = match self
                .fetch_and_verify(&pointer.lote_location, Some(&expected_cert))
                .await
            {
                Ok(child) => child,
                Err(error) => {
                    tracing::warn!(url = %pointer.lote_location, %error, "skipping LoTE pointer that failed to fetch/verify");
                    continue;
                }
            };
            earliest_expiry = earliest_expiry.min(child.list_and_scheme_information.next_update);
            let child_pointers = child
                .list_and_scheme_information
                .pointers_to_other_lote
                .take()
                .unwrap_or_default();
            let child_index = match preprocess_lote(
                child,
                self.certificate_validator.as_ref(),
                self.key_algorithm_provider.as_ref(),
            )
            .await
            {
                Ok(index) => index,
                Err(error) => {
                    tracing::warn!(url = %pointer.lote_location, %error, "skipping LoTE pointer that failed to preprocess");
                    continue;
                }
            };
            merge_lote(&mut aggregate, child_index);
            for child_pointer in child_pointers {
                queue.push_back((child_pointer, depth + 1));
            }
        }

        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&aggregate)?,
            media_type: Some(media_type),
            expiry_date: Some(earliest_expiry),
        })
    }
}
