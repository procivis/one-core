mod mapper;

use std::sync::Arc;

use rcgen::{
    CertificateParams, CustomExtension, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    OtherNameValue, SanType,
};
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{CertificateId, Permission, RevocationMethodId};
use time::Duration;
use yasna::Tag;
use yasna::models::ObjectIdentifier;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType, RevocationType};
use crate::error::ContextWithErrorCode;
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::Signer;
use crate::provider::signer::access_certificate::mapper::{to_ia5, validated_pubkey_from_csr};
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO, Issuer};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::SignerCapabilities;
use crate::provider::signer::validity::{SignatureValidity, calculate_signature_validity};
use crate::provider::signer::x509_utils::{
    CaSigningInfo, IdentifierInfo, RevocationInfo, prepare_params_and_ca_issuer,
};
use crate::validator::permissions::RequiredPermssions;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub payload: PayloadParams,
    pub revocation_method: Option<RevocationMethodId>,
}

#[serde_as]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub max_validity_duration: Duration,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestData {
    csr: String,
    organization_identifier: String,
    country_name: String,
    rfc822_name: Option<String>,
    other_name_phone_nr: Option<String>,
    san_uri: String,
    organization_name: Option<String>,
    common_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    policy: AccessCertificatePolicy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AccessCertificatePolicy {
    NaturalPerson,
    LegalPerson,
}

impl AccessCertificatePolicy {
    fn to_certificate_policy_extension(&self) -> CustomExtension {
        const OID_CERTIFICATE_POLICY: [u64; 4] = [2, 5, 29, 32];
        const OID_CERTIFICATE_POLICY_NATURAL_PERSON: [u64; 6] = [0, 4, 0, 194112, 1, 0];
        const OID_CERTIFICATE_POLICY_LEGAL_PERSON: [u64; 6] = [0, 4, 0, 194112, 1, 1];

        let oid = match self {
            AccessCertificatePolicy::NaturalPerson => OID_CERTIFICATE_POLICY_NATURAL_PERSON,
            AccessCertificatePolicy::LegalPerson => OID_CERTIFICATE_POLICY_LEGAL_PERSON,
        };

        let certificate_policy_ext_content = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_oid(&ObjectIdentifier::from_slice(&oid));
            });
        });
        // Not critical according to ETSI EN 319 412-2
        CustomExtension::from_oid_content(&OID_CERTIFICATE_POLICY, certificate_policy_ext_content)
    }
}

pub struct AccessCertificateSigner {
    config_name: String,
    core_base_url: String,
    params: Params,
    key_provider: Arc<dyn KeyProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    session_provider: Arc<dyn SessionProvider>,
}

impl AccessCertificateSigner {
    pub fn new(
        config_name: String,
        params: Params,
        key_provider: Arc<dyn KeyProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        session_provider: Arc<dyn SessionProvider>,
        core_base_url: String,
    ) -> Self {
        Self {
            config_name,
            core_base_url,
            params,
            key_provider,
            revocation_method_provider,
            session_provider,
        }
    }
}

#[async_trait::async_trait]
impl Signer for AccessCertificateSigner {
    fn get_capabilities(&self) -> SignerCapabilities {
        SignerCapabilities {
            features: vec![],
            supported_identifiers: vec![IdentifierType::CertificateAuthority],
            sign_required_permissions: vec![Permission::AccessCertificateCreate],
            revoke_required_permissions: vec![Permission::AccessCertificateRevoke],
            signing_key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            revocation_methods: vec![RevocationType::CRL],
        }
    }

    async fn sign(
        &self,
        issuer: Issuer,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        // Check permissions in provider because internal calls for `Issuer::Key` do _not_ go through the service
        RequiredPermssions::at_least_one(self.get_capabilities().sign_required_permissions)
            .check(&*self.session_provider)
            .error_while("validating provider required permissions")?;

        let (identifier, certificate, key) = match issuer {
            Issuer::Identifier {
                identifier,
                certificate,
                key,
            } => (identifier, certificate, key),
            Issuer::Key(_) => {
                return Err(SignerError::KeyIssuerNotSupported);
            }
        };

        let SignatureValidity { start, end } =
            calculate_signature_validity(self.params.payload.max_validity_duration, &request)?;
        let request_data: RequestData = serde_json::from_value(request.data)?;
        let pub_key = validated_pubkey_from_csr(&request_data.csr)?;

        let mut cert_params = CertificateParams::default();
        cert_params.use_authority_key_identifier_extension = true;
        cert_params.not_before = start;
        cert_params.not_after = end;
        cert_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyAgreement,
        ];
        cert_params.is_ca = IsCa::ExplicitNoCa;

        cert_params
            .custom_extensions
            .push(request_data.policy.to_certificate_policy_extension());
        cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        cert_params
            .subject_alt_names
            .push(SanType::URI(to_ia5(request_data.san_uri.clone())?));
        if let Some(phone_nr) = &request_data.other_name_phone_nr {
            const OID_TELEPHONE_NR: [u64; 4] = [2, 5, 4, 20];
            cert_params.subject_alt_names.push(SanType::OtherName((
                OID_TELEPHONE_NR.to_vec(),
                OtherNameValue::Utf8String(phone_nr.clone()),
            )));
        }
        if let Some(rfc822_name) = &request_data.rfc822_name {
            cert_params
                .subject_alt_names
                .push(SanType::Rfc822Name(to_ia5(rfc822_name.clone())?));
        }

        cert_params.distinguished_name = mapper::request_to_distinguished_name(request_data)?;

        let CaSigningInfo {
            cert_issuer,
            signature_id: id,
            ca_certificate,
        } = prepare_params_and_ca_issuer(
            &mut cert_params,
            IdentifierInfo {
                identifier: &identifier,
                certificate,
                key,
            },
            RevocationInfo {
                config_name: self.config_name.clone(),
                revocation_method: self.revocation_method(),
            },
            self.key_provider.clone(),
        )
        .await?;
        cert_params
            .custom_extensions
            .push(authority_information_access_extension(
                self.core_base_url.as_str(),
                ca_certificate.id,
            ));

        let content = cert_params
            .signed_by(&pub_key, &cert_issuer)
            .map_err(SignerError::signing_error)?;
        let chain = format!("{}{}", content.pem(), ca_certificate.chain); // include CA chain

        Ok(CreateSignatureResponseDTO { id, result: chain })
    }

    fn revocation_method(&self) -> Option<Arc<dyn RevocationMethod>> {
        self.revocation_method_provider
            .get_revocation_method(self.params.revocation_method.as_ref()?)
    }
}

fn authority_information_access_extension(
    core_base_url: &str,
    certificate_id: CertificateId,
) -> CustomExtension {
    const OID_AUTHORITY_INFORMATION_ACCESS: [u64; 9] = [1, 3, 6, 1, 5, 5, 7, 1, 1];
    const OID_ID_AD_CA_ISSUERS: [u64; 9] = [1, 3, 6, 1, 5, 5, 7, 48, 2];

    let authority_info_access = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(&OID_ID_AD_CA_ISSUERS));
                writer.next().write_tagged(Tag::context(6), |writer| {
                    writer.write_ia5_string(&format!("{}/ssi/ca/{}", core_base_url, certificate_id))
                });
            });
        });
    });
    // Non-critical
    CustomExtension::from_oid_content(&OID_AUTHORITY_INFORMATION_ACCESS, authority_info_access)
}
