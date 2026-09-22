//! XAdES Baseline B-B enveloped signatures (ETSI EN 319 132-1, ETSI TS 119 602 Annex H.4).

mod c14n;
pub(crate) mod error;
mod signature;

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64, Decoder};
use one_crypto::{Hasher, get_hasher};
use serde::de::DeserializeOwned;
use standardized_types::iana::HashAlgorithm;
use standardized_types::xades::{
    self, EXC_C14N, INC_C14N, SHA256_DIGEST_URI, SHA512_DIGEST_URI, XMLDSIG_NS,
};
use time::OffsetDateTime;
use xades::Transform::*;
use xades::XPathFilter2Op;

use self::error::Error;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::proto::certificate_validator::{CertificateValidationOptions, CertificateValidator};
use crate::provider::credential_formatter::model::SignatureProvider;

/// Whitespace bytes to skip when decoding base64: XML-DSig `base64Binary`
/// content (X509Certificate, SignatureValue) may be line-wrapped.
const B64_IGNORE_WS: Option<&[u8]> = Some(b"\n\r\t ");

impl TryFrom<KeyAlgorithmType> for xades::SignatureSuite {
    type Error = Error;

    fn try_from(value: KeyAlgorithmType) -> Result<Self, Self::Error> {
        match value {
            KeyAlgorithmType::Ecdsa => Ok(xades::SignatureSuite::ES256),
            KeyAlgorithmType::Eddsa => Ok(xades::SignatureSuite::EdDSA),
            _ => Err(Error::UnsupportedSuite(value.to_string())),
        }
    }
}

#[async_trait]
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait XAdESProto: Send + Sync {
    async fn create_enveloped_signature(
        &self,
        unsigned_xml: &str,
        signer: &dyn SignatureProvider,
        x5c: Vec<String>,
    ) -> Result<String, Error>;

    /// Profile checks (which references must exist, signing-time freshness, ...)
    /// are left to the caller.
    async fn verify_enveloped_signature(
        &self,
        signed: &XAdESEnvelopedSignature,
    ) -> Result<XAdESVerified, Error>;
}

#[derive(Debug, Clone)]
pub struct VerifiedReference {
    /// Raw `URI` attribute (`""` for the whole document, `#id` for a fragment).
    pub uri: String,
    /// `Type` attribute (e.g. the SignedProperties type URI), if present.
    pub r#type: Option<String>,
    /// Declared transform chain.
    #[allow(dead_code)] // read by the ETSI_LOTL subscriber to locate the document reference
    pub transforms: Vec<xades::Transform>,
}

#[derive(Debug, Clone)]
pub struct XAdESVerified {
    /// Signer certificate PEM chain (leaf-first), bound via SigningCertificateV2.
    #[allow(dead_code)] // read by the ETSI_LOTL subscriber for signer pinning
    pub signer_chain_pem: String,
    /// `SigningTime` from the signed signature properties.
    pub signing_time: OffsetDateTime,
    /// `ds:CanonicalizationMethod` algorithm URI applied to `SignedInfo`.
    /// Callers enforce their own profile policy on it (e.g. TS 119 612 Annex B
    /// mandates exclusive C14N).
    #[allow(dead_code)] // read by the ETSI_LOTL subscriber's TSL signature policy
    pub canonicalization_method: String,
    /// One entry per `ds:Reference` in `SignedInfo`.
    pub references: Vec<VerifiedReference>,
}

/// Map a canonicalization algorithm URI to the C14N mode the canonicalizer implements.
fn c14n_mode_from_uri(uri: &str) -> Result<c14n::C14nMode, Error> {
    match uri {
        EXC_C14N => Ok(c14n::C14nMode::Exclusive),
        INC_C14N => Ok(c14n::C14nMode::Inclusive),
        other => Err(Error::UnsupportedSuite(format!(
            "unsupported canonicalization algorithm: {other}"
        ))),
    }
}

#[derive(Debug)]
pub struct XAdESEnvelopedSignature {
    pub(crate) signature: xades::Signature,
    pub(crate) unverified_document: String,
}

pub struct XAdES {
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl XAdES {
    pub fn new(certificate_validator: Arc<dyn CertificateValidator>) -> Self {
        Self {
            certificate_validator,
        }
    }
}

#[async_trait]
impl XAdESProto for XAdES {
    async fn create_enveloped_signature(
        &self,
        unsigned_xml: &str,
        signer: &dyn SignatureProvider,
        x5c: Vec<String>,
    ) -> Result<String, Error> {
        let parsed_document = roxmltree::Document::parse(unsigned_xml)?;

        if parsed_document.descendants().any(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(XMLDSIG_NS)
                && n.tag_name().name() == "Signature"
        }) {
            return Err(Error::InvalidDocument(
                "unexpected ds:Signature node".to_string(),
            ));
        };

        let xades_suite: xades::SignatureSuite = signer
            .get_key_algorithm()
            .error_while("getting key algorithm type")?
            .try_into()
            .error_while("generating signature")?;

        let hasher =
            resolve_hasher(xades_suite.hash_alg_uri()).error_while("generating signature")?;

        let signing_certificate = x5c
            .first()
            .ok_or(Error::EmptyCertificateChain)
            .error_while("generating signature")?;

        let signature = signature::build_signature(
            &xades_suite,
            &x5c,
            unsigned_xml,
            &*hasher,
            signer,
            signing_certificate,
        )
        .await
        .error_while("generating signature")?;

        let sig_xml = quick_xml::se::to_string(&signature)?;

        // root.range() skips any XML declaration / PIs before the root element
        let root = parsed_document.root_element();
        let root_xml = &unsigned_xml[root.range().start..root.range().end];
        let insert_pos = root_xml.rfind("</").ok_or(Error::InvalidDocument(
            "missing root closing tag".to_string(),
        ))?;

        let signed_xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}{}{}",
            &root_xml[..insert_pos],
            sig_xml,
            &root_xml[insert_pos..],
        );

        Ok(signed_xml)
    }

    async fn verify_enveloped_signature(
        &self,
        signed: &XAdESEnvelopedSignature,
    ) -> Result<XAdESVerified, Error> {
        signed.verify_signature(&*self.certificate_validator).await
    }
}

#[derive(Debug)]
pub(crate) struct XAdESSignedXML<T> {
    envelope: XAdESEnvelopedSignature,
    pub(crate) content: T,
}

// TS 119 602 §6.8 subject DN matching is a LoTE-level policy check,
// should handled by the trust-list subscriber rather than the XAdES verifier.
impl<T> XAdESSignedXML<T>
where
    T: DeserializeOwned,
{
    pub fn decompose_document(xml: &str) -> Result<XAdESSignedXML<T>, Error> {
        let parsed_document = roxmltree::Document::parse(xml)?;
        let signature_node = parsed_document
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.tag_name().namespace() == Some(XMLDSIG_NS)
                    && n.tag_name().name() == "Signature"
            })
            .ok_or(Error::MissingEnvelopedSignature)
            .error_while("decomposing signed document")?;

        let signature_node_position = signature_node.range();

        let signature = &xml[signature_node_position.start..signature_node_position.end];

        let content_xml = format!(
            "{}{}",
            &xml[..signature_node_position.start],
            &xml[signature_node_position.end..]
        );

        let signature: xades::Signature = quick_xml::de::from_str(signature)?;

        Ok(Self {
            envelope: XAdESEnvelopedSignature {
                signature,
                unverified_document: xml.to_string(),
            },
            content: quick_xml::de::from_str(&content_xml)?,
        })
    }

    pub fn envelope(&self) -> &XAdESEnvelopedSignature {
        &self.envelope
    }
}

impl XAdESEnvelopedSignature {
    pub(crate) async fn verify_signature(
        &self,
        certificate_validator: &dyn CertificateValidator,
    ) -> Result<XAdESVerified, Error> {
        let sig = &self.signature;
        let signature_id = sig.id.as_deref();
        let signed_info = &sig.signed_info;
        let qualifying_props = &sig.object.qualifying_properties;
        let signed_sig_props = &qualifying_props
            .signed_properties
            .signed_signature_properties;

        // EN 319 132-1 §4.3.1
        let expected_target = signature_id.map(|id| format!("#{id}"));
        if expected_target.as_deref() != Some(qualifying_props.target.as_str()) {
            return Err(Error::InvalidSignature(format!(
                "QualifyingProperties Target mismatch: expected {}, got {}",
                expected_target
                    .as_deref()
                    .unwrap_or("<missing ds:Signature Id>"),
                qualifying_props.target,
            )));
        }

        if xades::SignatureSuite::try_from_sig_uri(&signed_info.signature_method.algorithm)
            .is_none()
        {
            return Err(Error::UnsupportedSuite(format!(
                "unknown SignatureMethod algorithm: {}",
                signed_info.signature_method.algorithm
            )));
        }

        let signed_info_c14n = signed_info.canonicalization_method.algorithm.as_str();

        let mut references = Vec::with_capacity(signed_info.references.len());
        for reference in &signed_info.references {
            self.verify_reference_digest(reference, signature_id, signed_info_c14n)?;
            references.push(VerifiedReference {
                uri: reference.uri.clone(),
                r#type: reference.r#type.clone(),
                transforms: reference
                    .transforms
                    .as_ref()
                    .map(|t| t.transforms.clone())
                    .unwrap_or_default(),
            });
        }

        // EN 319 132-1 §5.2.2
        let signing_chain = self
            .find_signing_certificate_chain()
            .error_while("matching signing certificate")?;
        let pem_chain = x5c_into_pem_chain(signing_chain).error_while("parsing signer X509Data")?;
        let parsed = certificate_validator
            .parse_pem_chain(
                &pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
            )
            .await
            .error_while("validating signer certificate chain")?;

        let si_canonical = c14n::canonicalize_signature_subtree(
            &self.unverified_document,
            c14n_mode_from_uri(signed_info_c14n)?,
            signature_id,
            XMLDSIG_NS,
            "SignedInfo",
        )
        .map_err(Error::from)
        .error_while("canonicalizing SignedInfo")?;
        let sig_value_bytes = Base64::decode_to_vec(&sig.signature_value.value, B64_IGNORE_WS)
            .map_err(Error::from)
            .error_while("decoding signature value")?;
        parsed
            .public_key
            .verify(&si_canonical, &sig_value_bytes)
            .error_while("verifying document signature")?;

        Ok(XAdESVerified {
            signer_chain_pem: pem_chain,
            signing_time: signed_sig_props.signing_time,
            canonicalization_method: signed_info_c14n.to_string(),
            references,
        })
    }

    fn verify_reference_digest(
        &self,
        reference: &xades::Reference,
        signature_id: Option<&str>,
        signed_info_c14n: &str,
    ) -> Result<(), Error> {
        let transforms = reference
            .transforms
            .as_ref()
            .map(|t| t.transforms.as_slice())
            .unwrap_or(&[]);
        let (exclusion, c14n_mode) = interpret_ref_transforms(transforms, signed_info_c14n)?;

        // Drop the signature before digesting (the enveloped-signature transform).
        // Applies to both whole-document (`URI=""`) and root-by-id (`URI="#root"`)
        // references.
        let skip = exclusion.map(|e| c14n::SkipElement {
            namespace: XMLDSIG_NS,
            local_name: "Signature",
            id: match e {
                SignatureExclusion::ById => signature_id,
                SignatureExclusion::All => None,
            },
        });

        let canonical = if reference.uri.is_empty() {
            c14n::canonicalize(&self.unverified_document, c14n_mode, skip)?
        } else if let Some(id) = reference.uri.strip_prefix('#') {
            c14n::canonicalize_by_id(&self.unverified_document, c14n_mode, id, skip)?
        } else {
            return Err(Error::InvalidSignature(format!(
                "unsupported Reference URI: {}",
                reference.uri
            )));
        };

        let hasher = resolve_hasher(&reference.digest_method.algorithm)
            .error_while("resolving reference digest algorithm")?;
        if hasher.hash_base64(&canonical)? != reference.digest_value {
            return Err(Error::IncorrectDigest(if reference.uri.is_empty() {
                "document reference".to_string()
            } else {
                format!("reference {}", reference.uri)
            }));
        }
        Ok(())
    }

    fn find_signing_certificate_chain(&self) -> Result<&[String], Error> {
        let sig = &self.signature;
        let signed_sig_props = &sig
            .object
            .qualifying_properties
            .signed_properties
            .signed_signature_properties;

        // EN 319 132-1 §5.2.2
        let cert_ref = signed_sig_props
            .signing_certificate_v2
            .certs
            .first()
            .ok_or_else(|| {
                Error::InvalidSignature(
                    "SigningCertificateV2 contains no Cert elements".to_string(),
                )
            })?;

        let cert_hasher = resolve_hasher(&cert_ref.cert_digest.digest_method.algorithm)?;

        let expected_digest = &cert_ref.cert_digest.digest_value;

        let [x509_entry] = &sig.key_info.x509_data[..] else {
            return Err(Error::InvalidSignature(format!(
                "ds:X509Data expected to contain 1 entry, found {}",
                sig.key_info.x509_data.len()
            )));
        };

        let leaf = x509_entry.x509_certificates.first().ok_or_else(|| {
            Error::InvalidSignature("ds:X509Data entry contains no certificates".to_string())
        })?;

        if cert_hasher.hash_base64(&Base64::decode_to_vec(leaf, B64_IGNORE_WS)?)?
            != *expected_digest
        {
            return Err(Error::SigningCertificateNotFound(expected_digest.clone()));
        }

        Ok(x509_entry.x509_certificates.as_ref())
    }
}

/// How the ds:Signature element should be excluded during document digest computation.
enum SignatureExclusion {
    /// Enveloped-signature: skip the signature matching the given Id.
    ById,
    /// XPath Filter 2.0 subtract: skip all ds:Signature elements.
    All,
}

/// Map a reference's transform chain to its signature exclusion and
/// canonicalization algorithm. An empty chain uses the SignedInfo
/// `CanonicalizationMethod`.
fn interpret_ref_transforms(
    transforms: &[xades::Transform],
    signed_info_c14n: &str,
) -> Result<(Option<SignatureExclusion>, c14n::C14nMode), Error> {
    use c14n::C14nMode;
    match transforms {
        [] => Ok((None, c14n_mode_from_uri(signed_info_c14n)?)),
        [ExcC14n] => Ok((None, C14nMode::Exclusive)),
        [InclC14n] => Ok((None, C14nMode::Inclusive)),
        [EnvelopedSignature, ExcC14n] => Ok((Some(SignatureExclusion::ById), C14nMode::Exclusive)),
        [EnvelopedSignature, InclC14n] => Ok((Some(SignatureExclusion::ById), C14nMode::Inclusive)),
        [XPathFilter2(ops), ExcC14n] => {
            let subtract = ops
                .iter()
                .find_map(|op| match op {
                    XPathFilter2Op::Subtract(xpath) => Some(xpath.as_str()),
                    _ => None,
                })
                .ok_or_else(|| {
                    Error::InvalidTransformsInReference(
                        "XPath Filter 2.0 has no subtract operation".to_string(),
                    )
                })?;

            let xpath = subtract.trim();
            if xpath.ends_with("Signature") && xpath.contains("descendant") {
                Ok((Some(SignatureExclusion::All), C14nMode::Exclusive))
            } else {
                Err(Error::InvalidTransformsInReference(format!(
                    "unsupported XPath Filter 2.0 expression: {xpath}"
                )))
            }
        }
        other => Err(Error::InvalidTransformsInReference(format!(
            "unsupported transform chain: {other:?}"
        ))),
    }
}

fn resolve_hasher(digest_uri: &str) -> Result<Arc<dyn Hasher>, Error> {
    let hash_algorithm = match digest_uri {
        SHA256_DIGEST_URI => HashAlgorithm::Sha256,
        SHA512_DIGEST_URI => HashAlgorithm::Sha512,
        other => {
            return Err(Error::UnsupportedSuite(format!(
                "unsupported digest algorithm URI: {other}"
            )));
        }
    };
    Ok(get_hasher(hash_algorithm)?)
}

#[cfg(test)]
mod test;
