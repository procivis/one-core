use std::str::FromStr;
use std::sync::Arc;

use error::ErrorCode;
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, KeyUsagePurpose, SanType,
};
use standardized_types::x509::oid;
use yasna::models::ObjectIdentifier;

use crate::config::core_config::KeyAlgorithmType;
use crate::error;
use crate::error::{ContextWithErrorCode, ErrorCodeMixin, NestedError};
use crate::mapper::x509::SigningKeyAdapter;
use crate::model::key::Key;
use crate::provider::key_algorithm::model::Features;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CsrCreator: Send + Sync {
    async fn create_csr(
        &self,
        key: Key,
        request: GenerateCsrRequest,
    ) -> Result<String, CsrCreationError>;
}

#[derive(Debug, Clone)]
pub struct GenerateCsrRequest {
    pub profile: CsrRequestProfile,
    pub subject: CsrRequestSubject,
    pub subject_alternative_name: Option<CsrRequestSubjectAlternativeName>,
}

#[derive(Debug, Clone)]
pub enum CsrRequestProfile {
    Generic,
    Mdl,
    Ca,
}

#[derive(Debug, thiserror::Error)]
pub enum CsrCreationError {
    #[error("Unsupported key algorithm: `{key_algorithm}`")]
    UnsupportedKeyAlgorithm { key_algorithm: String },
    #[error("Missing provider for key storage: `{key_storage}`")]
    MissingKeyStorageProvider { key_storage: String },
    #[error("CSR signing failed: {0}")]
    SigningError(#[from] rcgen::Error),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for CsrCreationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::SigningError(_) => ErrorCode::BR_0329,
            Self::UnsupportedKeyAlgorithm { .. } => ErrorCode::BR_0128,
            Self::MissingKeyStorageProvider { .. } => ErrorCode::BR_0040,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CsrRequestSubject {
    pub country_name: Option<String>,
    pub common_name: Option<String>,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CsrRequestSubjectAlternativeName {
    pub dns_name: Vec<String>,
}

pub(crate) struct CsrCreatorImpl {
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl CsrCreatorImpl {
    pub fn new(
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            key_provider,
            key_algorithm_provider,
        }
    }

    fn validate_key_algorithm_for_csr(&self, key: &Key) -> Result<(), CsrCreationError> {
        let key_type = KeyAlgorithmType::from_str(&key.key_type).map_err(|_| {
            CsrCreationError::UnsupportedKeyAlgorithm {
                key_algorithm: key.key_type.to_owned(),
            }
        })?;
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_type(key_type)?;

        if !key_algorithm
            .get_capabilities()
            .features
            .contains(&Features::GenerateCSR)
        {
            return Err(CsrCreationError::UnsupportedKeyAlgorithm {
                key_algorithm: key.key_type.to_owned(),
            });
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl CsrCreator for CsrCreatorImpl {
    async fn create_csr(
        &self,
        key: Key,
        request: GenerateCsrRequest,
    ) -> Result<String, CsrCreationError> {
        self.validate_key_algorithm_for_csr(&key)?;

        let key_storage = self.key_provider.get_key_storage(&key.storage_type)?;
        let signing_key =
            SigningKeyAdapter::new(key, key_storage).error_while("creating signing key adapter")?;

        request_to_certificate_params(request)?
            .serialize_request(&signing_key)?
            .pem()
            .map_err(Into::into)
    }
}

fn request_to_certificate_params(
    request: GenerateCsrRequest,
) -> Result<CertificateParams, CsrCreationError> {
    let mut params = CertificateParams::default();

    params.distinguished_name = prepare_distinguished_name(request.subject);

    match request.profile {
        CsrRequestProfile::Generic => {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        }
        CsrRequestProfile::Mdl => {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.custom_extensions.extend([
                prepare_extended_key_usage_extension_iso_mdl_ds(),
                prepare_extended_key_usage_extension_iso_mdoc_ds(),
            ]);
        }
        CsrRequestProfile::Ca => {
            // Basic constraints cannot be set in CSR, so only key usages are specified here.
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        }
    }

    if let Some(subject_alternative_name) = request.subject_alternative_name {
        let dns_names = subject_alternative_name
            .dns_name
            .into_iter()
            .map(|dns_name| Ok(SanType::DnsName(dns_name.try_into()?)))
            .collect::<Result<Vec<_>, rcgen::Error>>()?;

        params.subject_alt_names.extend(dns_names);
    }

    Ok(params)
}

pub(crate) fn prepare_distinguished_name(subject: CsrRequestSubject) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    if let Some(common_name) = subject.common_name {
        dn.push(DnType::CommonName, common_name);
    }
    if let Some(country_name) = subject.country_name {
        dn.push(DnType::CountryName, country_name);
    }
    if let Some(organisation_name) = subject.organisation_name {
        dn.push(DnType::OrganizationName, organisation_name);
    }
    if let Some(state_or_province_name) = subject.state_or_province_name {
        dn.push(DnType::StateOrProvinceName, state_or_province_name);
    }
    if let Some(locality_name) = subject.locality_name {
        dn.push(DnType::LocalityName, locality_name);
    }
    if let Some(serial_number) = subject.serial_number {
        let dn_type_serial_number = vec![2, 5, 4, 5];
        dn.push(DnType::CustomDnType(dn_type_serial_number), serial_number);
    }
    dn
}

/// ISO 18013-5, B.1.4 Document signer certificate
pub(crate) const OID_EXTENDED_KEY_USAGE_ISO_MDL_DS: [u64; 6] = [1, 0, 18013, 5, 1, 2];
pub(crate) fn prepare_extended_key_usage_extension_iso_mdl_ds() -> CustomExtension {
    let mdlds_extended_key_usage = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(
                &OID_EXTENDED_KEY_USAGE_ISO_MDL_DS,
            ));
        });
    });
    let mut extended_key_usage_extension = CustomExtension::from_oid_content(
        oid::extension::EXTENDED_KEY_USAGE,
        mdlds_extended_key_usage,
    );
    extended_key_usage_extension.set_criticality(true);
    extended_key_usage_extension
}

/// ISO 7367-2, C.1.4 Document signer certificate
pub(crate) const OID_EXTENDED_KEY_USAGE_ISO_MDOC_DS: [u64; 6] = [1, 0, 23220, 4, 1, 2];
pub(crate) fn prepare_extended_key_usage_extension_iso_mdoc_ds() -> CustomExtension {
    let mdocds_extended_key_usage = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(
                &OID_EXTENDED_KEY_USAGE_ISO_MDOC_DS,
            ));
        });
    });
    let mut extended_key_usage_extension = CustomExtension::from_oid_content(
        oid::extension::EXTENDED_KEY_USAGE,
        mdocds_extended_key_usage,
    );
    extended_key_usage_extension.set_criticality(true);
    extended_key_usage_extension
}
