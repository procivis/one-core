use std::str::FromStr;
use std::sync::Arc;

use error::ErrorCode;
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, KeyUsagePurpose};
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
    #[error("Missing provider for key algorithm: `{key_type}`")]
    MissingKeyAlgorithmProvider { key_type: KeyAlgorithmType },
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
            Self::MissingKeyAlgorithmProvider { .. } => ErrorCode::BR_0063,
            Self::MissingKeyStorageProvider { .. } => ErrorCode::BR_0040,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CsrRequestSubject {
    pub country_name: Option<String>,
    pub common_name: Option<String>,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
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
            .key_algorithm_from_type(key_type)
            .ok_or(CsrCreationError::MissingKeyAlgorithmProvider { key_type })?;

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

        let key_storage = self.key_provider.get_key_storage(&key.storage_type).ok_or(
            CsrCreationError::MissingKeyStorageProvider {
                key_storage: key.storage_type.clone(),
            },
        )?;
        let signing_key =
            SigningKeyAdapter::new(key, key_storage, tokio::runtime::Handle::current())
                .error_while("creating signing key adapter")?;

        request_to_certificate_params(request)
            .serialize_request(&signing_key)?
            .pem()
            .map_err(Into::into)
    }
}

fn request_to_certificate_params(request: GenerateCsrRequest) -> CertificateParams {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    if let Some(common_name) = request.subject.common_name {
        dn.push(DnType::CommonName, common_name);
    }
    if let Some(country_name) = request.subject.country_name {
        dn.push(DnType::CountryName, country_name);
    }
    if let Some(organisation_name) = request.subject.organisation_name {
        dn.push(DnType::OrganizationName, organisation_name);
    }
    if let Some(state_or_province_name) = request.subject.state_or_province_name {
        dn.push(DnType::StateOrProvinceName, state_or_province_name);
    }
    if let Some(locality_name) = request.subject.locality_name {
        dn.push(DnType::LocalityName, locality_name);
    }
    if let Some(serial_number) = request.subject.serial_number {
        let dn_type_serial_number = vec![2, 5, 4, 5];
        dn.push(DnType::CustomDnType(dn_type_serial_number), serial_number);
    }

    params.distinguished_name = dn;

    match request.profile {
        CsrRequestProfile::Generic => {} // nothing to add
        CsrRequestProfile::Mdl => {
            params.custom_extensions.push(prepare_key_usage_extension());
            params
                .custom_extensions
                .push(prepare_extended_key_usage_extension());
        }
        CsrRequestProfile::Ca => {
            // Basic constraints cannot be set in CSR, so only key usages are specified here.
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        }
    }

    params
}

fn prepare_key_usage_extension() -> CustomExtension {
    const OID_KEY_USAGE: [u64; 4] = [2, 5, 29, 15];
    const KEY_USAGE_PURPOSE_DIGITAL_SIGNATURE: [u8; 2] = [0x80, 0];
    const BITS_TO_WRITE: usize = 15;

    let content = yasna::construct_der(|writer| {
        writer.write_bitvec_bytes(&KEY_USAGE_PURPOSE_DIGITAL_SIGNATURE, BITS_TO_WRITE);
    });

    CustomExtension::from_oid_content(&OID_KEY_USAGE, content)
}

fn prepare_extended_key_usage_extension() -> CustomExtension {
    const OID_EXTENDED_KEY_USAGE: [u64; 4] = [2, 5, 29, 37];
    const OID_EXTENDED_KEY_USAGE_MDL_DS: [u64; 6] = [1, 0, 18013, 5, 1, 2];

    let mdlds_extended_key_usage = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(
                &OID_EXTENDED_KEY_USAGE_MDL_DS,
            ));
        });
    });
    let mut extended_key_usage_extension =
        CustomExtension::from_oid_content(&OID_EXTENDED_KEY_USAGE, mdlds_extended_key_usage);
    extended_key_usage_extension.set_criticality(true);
    extended_key_usage_extension
}
