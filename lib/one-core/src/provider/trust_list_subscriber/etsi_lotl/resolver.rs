use std::sync::Arc;

use standardized_types::etsi_119_612::xml::{OtherTslPointer, TrustServiceStatusList};
use standardized_types::etsi_119_612::{MIME_TSL_XML, TslType};
use standardized_types::xades::{EXC_C14N, Transform};
use time::OffsetDateTime;

use super::preprocessing::preprocess_services;
use crate::error::ContextWithErrorCode;
use crate::proto::certificate_validator::{CertificateValidationOptions, CertificateValidator};
use crate::proto::http_client::HttpClient;
use crate::proto::xades::{XAdESProto, XAdESSignedXML, XAdESVerified};
use crate::provider::caching_loader::{ResolveResult, Resolver, ResolverError};

/// XML media types a TS 119 612 TSL may be served as.
const TSL_XML_MEDIA_TYPES: &[&str] = &[MIME_TSL_XML, "application/xml", "text/xml"];

/// What a fetched list's signer is pinned against.
enum SignerPin<'a> {
    /// Root LOTL: the configured trust anchors.
    Anchors,
    /// Member list: the pointer's own certificate.
    PointerCert(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PointerKind {
    /// A member-state TSL aggregated here.
    Member,
    /// A 612 list we recognize but don't follow.
    Skip,
    /// Not a 612 list, handed to the delegate subscribers.
    Delegate,
}

fn assert_tsl_signature_policy(
    verified: &XAdESVerified,
    leeway: time::Duration,
    now: OffsetDateTime,
) -> Result<(), ResolverError> {
    if verified.signing_time > now + leeway {
        return Err(ResolverError::InvalidResponse(
            "TSL signing time is in the future".to_string(),
        ));
    }
    let doc_signed = verified.references.iter().any(|r| {
        r.transforms
            .iter()
            .any(|t| matches!(t, Transform::EnvelopedSignature))
    });
    if !doc_signed {
        return Err(ResolverError::InvalidResponse(
            "TSL signature does not cover the document".to_string(),
        ));
    }
    // TS 119 612 Annex B.1.0 mandates exclusive C14N for the trusted-list
    // signature, but the deployed EUDI lists are signed with inclusive C14N. We
    // accept the deviation (so the real lists resolve) but surface it.
    if verified.canonicalization_method != EXC_C14N {
        tracing::warn!(
            canonicalization = %verified.canonicalization_method,
            "TSL uses non-exclusive XML canonicalization; TS 119 612 Annex B.1.0 mandates \
             exclusive C14N ({EXC_C14N}). Accepting to interoperate with the deployed EUDI lists."
        );
    }
    Ok(())
}

pub struct EtsiLotlResolver {
    client: Arc<dyn HttpClient>,
    certificate_validator: Arc<dyn CertificateValidator>,
    xades_proto: Arc<dyn XAdESProto>,
    /// Root LOTL trust anchors (PEM)
    trust_anchors: Vec<String>,
    leeway: time::Duration,
}

impl EtsiLotlResolver {
    pub fn new(
        client: Arc<dyn HttpClient>,
        certificate_validator: Arc<dyn CertificateValidator>,
        xades_proto: Arc<dyn XAdESProto>,
        trust_anchors: Vec<String>,
        leeway: time::Duration,
    ) -> Self {
        Self {
            client,
            certificate_validator,
            xades_proto,
            trust_anchors,
            leeway,
        }
    }

    /// Fetch the TSL at `url`, verify its signature, pin the signer, check expiry.
    async fn fetch_and_verify(
        &self,
        url: &str,
        pin: SignerPin<'_>,
    ) -> Result<TrustServiceStatusList, ResolverError> {
        let response = async {
            self.client
                .get(url)
                .header("Accept", &TSL_XML_MEDIA_TYPES.join(", "))
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("Downloading ETSI LoTL/TSL")?;

        let body = str::from_utf8(&response.body)?;
        let signed = XAdESSignedXML::<TrustServiceStatusList>::decompose_document(body)
            .error_while("parsing TS 119 612 XML")?;

        let verified = self
            .xades_proto
            .verify_enveloped_signature(signed.envelope())
            .await
            .error_while("verifying TSL signature")?;

        assert_tsl_signature_policy(&verified, self.leeway, crate::clock::now_utc())?;
        let signer_pem = verified.signer_chain_pem;

        match pin {
            // no anchors configured: accept the LOTL's own signer (trust-on-first-use)
            SignerPin::Anchors if self.trust_anchors.is_empty() => {
                tracing::warn!(
                    "root LOTL accepted without a pinned trust anchor (trust-on-first-use); \
                     configure `trust_anchors` to authenticate the root in production"
                );
            }
            SignerPin::Anchors => {
                let anchors: Vec<&str> = self.trust_anchors.iter().map(String::as_str).collect();
                self.verify_signer_pinned(&signer_pem, &anchors).await?;
            }
            SignerPin::PointerCert(expected) => {
                self.verify_signer_pinned(&signer_pem, &[expected]).await?
            }
        }

        let tsl = signed.content;
        if let Some(next) = tsl.scheme_information.next_update.date_time
            && next + self.leeway < crate::clock::now_utc()
        {
            return Err(ResolverError::InvalidResponse(format!(
                "TSL at {url} is expired"
            )));
        }
        Ok(tsl)
    }

    /// Match the signer leaf against allowed PEMs by fingerprint.
    async fn verify_signer_pinned(
        &self,
        signer_pem: &str,
        allowed_pems: &[&str],
    ) -> Result<(), ResolverError> {
        let signer_fp = self.fingerprint_of(signer_pem).await?;
        for allowed in allowed_pems {
            if let Ok(allowed_fp) = self.fingerprint_of(allowed).await
                && allowed_fp == signer_fp
            {
                return Ok(());
            }
        }
        Err(ResolverError::InvalidResponse(
            "TSL signer does not match the pinned trust anchor / pointer identity".into(),
        ))
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

/// Whether the MIME is an XML TSL we can parse (absent counts as parseable).
fn is_parseable_tsl_xml(mime: Option<&str>) -> bool {
    match mime {
        None => true,
        Some(mime) => TSL_XML_MEDIA_TYPES.contains(&mime),
    }
}

/// Classify a LOTL pointer by its `TSLType`; non-612 types are delegated.
pub(crate) fn classify_pointer(pointer: &OtherTslPointer) -> PointerKind {
    let mime = pointer.additional_information.as_ref().and_then(|info| {
        info.other_information
            .iter()
            .find_map(|oi| oi.mime_type.as_deref())
    });
    let tsl_type = pointer.additional_information.as_ref().and_then(|info| {
        info.other_information
            .iter()
            .find_map(|oi| oi.tsl_type.as_ref())
    });

    match tsl_type {
        // member TSL: follow only a parseable XML representation (a PDF copy shares the TSLType)
        Some(TslType::Generic | TslType::CcList) if is_parseable_tsl_xml(mime) => {
            PointerKind::Member
        }
        Some(TslType::Generic | TslType::CcList) => PointerKind::Skip,
        // nested list-of-lists: not followed (the EU LOTL self-references)
        Some(TslType::ListOfLists | TslType::CcListOfLists) => PointerKind::Skip,
        Some(TslType::Other(_)) => PointerKind::Delegate,
        // no TSLType: a member only if the MIME is TSL XML, else delegate
        None => match mime {
            Some(mime) if TSL_XML_MEDIA_TYPES.contains(&mime) => PointerKind::Member,
            _ => PointerKind::Delegate,
        },
    }
}

/// PEM of the pointer's first `ServiceDigitalIdentity` X.509 cert.
pub(crate) fn pointer_signer_cert_pem(pointer: &OtherTslPointer) -> Option<String> {
    let cert_b64 = pointer
        .service_digital_identities
        .identities
        .iter()
        .flat_map(|identity| &identity.digital_ids)
        .find_map(|id| id.x509_certificate.as_ref())?;
    crate::mapper::x509::x5c_into_pem_chain(std::slice::from_ref(cert_b64)).ok()
}

fn min_opt(a: Option<OffsetDateTime>, b: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

#[async_trait::async_trait]
impl Resolver for EtsiLotlResolver {
    type Error = ResolverError;

    /// Single-level: the LOTL and its member lists, no recursion into members' pointers.
    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let lotl = self.fetch_and_verify(key, SignerPin::Anchors).await?;
        if lotl.scheme_information.tsl_type != TslType::ListOfLists {
            return Err(ResolverError::InvalidResponse(format!(
                "expected {}, got {}",
                TslType::ListOfLists,
                lotl.scheme_information.tsl_type
            )));
        }

        let mut services = Vec::new();
        let mut delegated_member_urls = Vec::new();
        let mut earliest_next_update = lotl.scheme_information.next_update.date_time;

        let pointers = lotl
            .scheme_information
            .pointers_to_other_tsl
            .map(|p| p.pointers)
            .unwrap_or_default();

        for pointer in pointers {
            match classify_pointer(&pointer) {
                PointerKind::Member => {
                    // no pointer cert → cannot authenticate the member, skip
                    let Some(expected) = pointer_signer_cert_pem(&pointer) else {
                        tracing::warn!(
                            url = %pointer.tsl_location,
                            "skipping Generic pointer with no signing identity",
                        );
                        continue;
                    };
                    // fail-safe: skip a member that fails to fetch/verify
                    let member = match self
                        .fetch_and_verify(&pointer.tsl_location, SignerPin::PointerCert(&expected))
                        .await
                    {
                        Ok(member) => member,
                        Err(e) => {
                            tracing::warn!(
                                url = %pointer.tsl_location,
                                error = %e,
                                "skipping member list that failed to fetch/verify",
                            );
                            continue;
                        }
                    };
                    if !matches!(
                        member.scheme_information.tsl_type,
                        TslType::Generic | TslType::CcList
                    ) {
                        tracing::warn!(
                            url = %pointer.tsl_location,
                            tsl_type = %member.scheme_information.tsl_type,
                            "skipping member list with unexpected TSLType",
                        );
                        continue;
                    }
                    earliest_next_update = min_opt(
                        earliest_next_update,
                        member.scheme_information.next_update.date_time,
                    );
                    if let Some(list) = member.trust_service_provider_list {
                        for provider in list.providers {
                            services.extend(provider.tsp_services.services);
                        }
                    }
                }
                PointerKind::Delegate => {
                    // recorded for a delegate subscriber to resolve at lookup time
                    delegated_member_urls.push(pointer.tsl_location);
                }
                PointerKind::Skip => {
                    tracing::debug!(url = %pointer.tsl_location, "skipping non-followed pointer");
                }
            }
        }

        let mut index = preprocess_services(services, self.certificate_validator.as_ref())
            .await
            .error_while("preprocessing TSL services")?;
        index.delegated_member_urls = delegated_member_urls;

        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&index)?,
            media_type: Some("application/json".to_string()),
            expiry_date: earliest_next_update,
        })
    }
}
