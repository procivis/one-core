use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{RevocationMethodId, SignerId};
use uuid::Uuid;

use super::decorators::{CapabilityChecked, PermissionChecked};
use super::{Signer, access_certificate, registration_certificate, x509_certificate};
use crate::config::core_config::{
    ConfigBlock, ConfigExt, CoreConfig, Fields, RevocationConfig, RevocationType, SignerType,
};
use crate::config::{ConfigValidationError, ProviderReference};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt, NestedError};
use crate::model::revocation_list::RevocationListEntityInfo;
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::service::error::ServiceError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub(crate) trait SignerProvider: Send + Sync {
    async fn get_for_signature_id(
        &self,
        id: Uuid,
    ) -> Result<(SignerId, Arc<dyn Signer>), NestedError>;

    fn get(&self, name: &SignerId) -> Result<Arc<dyn Signer>, NestedError>;
}

struct SignerProviderImpl {
    directory: ProviderDirectory<SignerId, Fields<SignerType>, dyn Signer>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
}

#[async_trait]
impl SignerProvider for SignerProviderImpl {
    async fn get_for_signature_id(
        &self,
        id: Uuid,
    ) -> Result<(SignerId, Arc<dyn Signer>), NestedError> {
        let entry = self
            .revocation_list_repository
            .get_entry_by_id(id.into())
            .await
            .error_while("getting revocation list entry")?;

        match entry.entity_info {
            RevocationListEntityInfo::Signature(name, _) => {
                let signer = self
                    .get(&name)
                    .error_while("getting signer for signature")?;
                Ok((name, signer))
            }
            _ => Err(
                ServiceError::MappingError("Invalid revocation list entry type".to_string())
                    .error_while("matching entity info"),
            ),
        }
    }

    fn get(&self, name: &SignerId) -> Result<Arc<dyn Signer>, NestedError> {
        self.directory.provider(name)
    }
}

fn initialize_provider(
    name: &SignerId,
    fields: &Fields<SignerType>,
    revocation_config: &ConfigBlock<RevocationMethodId, RevocationType>,
    core_base_url: &Option<String>,
    key_provider: &Arc<dyn KeyProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
) -> Result<Arc<dyn Signer>, InitializationError> {
    let provider: Arc<dyn Signer> = match fields.r#type {
        SignerType::RegistrationCertificate => {
            let params = registration_certificate::Params::try_from(fields.params.as_ref())
                .map_err(|e| InitializationError::InvalidParams {
                    key: name.to_string(),
                    source: e,
                })?;
            let signer = registration_certificate::RegistrationCertificate::new(
                name.to_owned(),
                params.clone(),
                revocation_method_provider.clone(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
            );

            validate_revocation_method_compatibility(
                name,
                &signer,
                revocation_config,
                &params.revocation_method,
            )?;
            Arc::new(signer)
        }
        SignerType::AccessCertificate => {
            let params: access_certificate::Params =
                fields
                    .deserialize()
                    .map_err(|e| InitializationError::InvalidParams {
                        key: name.to_string(),
                        source: e,
                    })?;
            let signer = access_certificate::AccessCertificateSigner::new(
                name.to_owned(),
                params.clone(),
                key_provider.clone(),
                revocation_method_provider.clone(),
                core_base_url
                    .clone()
                    .ok_or(InitializationError::MissingDependency(
                        "core base URL".to_string(),
                    ))?,
            );

            if let Some(revocation_method) = &params.revocation_method {
                validate_revocation_method_compatibility(
                    name,
                    &signer,
                    revocation_config,
                    revocation_method,
                )?;
            }
            Arc::new(signer)
        }
        SignerType::X509Certificate => {
            let params: x509_certificate::dto::Params =
                fields
                    .deserialize()
                    .map_err(|e| InitializationError::InvalidParams {
                        key: name.to_string(),
                        source: e,
                    })?;
            let signer = x509_certificate::X509CertificateSigner::new(
                name.to_owned(),
                params.clone(),
                key_provider.clone(),
                revocation_method_provider.clone(),
            );

            if let Some(revocation_method) = &params.revocation_method {
                validate_revocation_method_compatibility(
                    name,
                    &signer,
                    revocation_config,
                    revocation_method,
                )?;
            }
            Arc::new(signer)
        }
    };
    Ok(provider)
}

pub(crate) fn signer_provider_from_config(
    core_base_url: Option<String>,
    config: &mut CoreConfig,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    session_provider: Arc<dyn SessionProvider>,
) -> Result<Arc<dyn SignerProvider>, ConfigValidationError> {
    let revocation_config = &config.revocation;

    let directory = ProviderDirectory::initialize(
        config.signer.iter_mut(),
        |name: &SignerId, fields: &Fields<SignerType>| {
            let provider = initialize_provider(
                name,
                fields,
                revocation_config,
                &core_base_url,
                &key_provider,
                &key_algorithm_provider,
                &revocation_method_provider,
            )?;

            let provider = Arc::new(PermissionChecked {
                inner: provider,
                session_provider: session_provider.to_owned(),
            });

            let provider: Arc<dyn Signer> = Arc::new(CapabilityChecked(provider));

            Ok::<_, InitializationError>(provider)
        },
    )
    .error_while("initializing signer providers")?;

    Ok(Arc::new(SignerProviderImpl {
        directory,
        revocation_list_repository,
    }))
}

fn validate_revocation_method_compatibility(
    name: &SignerId,
    signer: &dyn Signer,
    revocation_config: &RevocationConfig,
    revocation_method: &RevocationMethodId,
) -> Result<(), InitializationError> {
    let revocation_type = revocation_config
        .get_if_enabled(revocation_method)
        .error_while("getting revocation method")?
        .r#type;
    let compatible_revocation_types = signer.get_capabilities().revocation_methods;
    if !compatible_revocation_types.contains(&revocation_type) {
        return Err(ConfigValidationError::incompatible_provider_ref(
            name.to_string(),
            ProviderReference::RevocationMethod(revocation_method.to_owned()),
            &compatible_revocation_types,
        )
        .error_while("validating signer revocation method")
        .into());
    }
    Ok(())
}
