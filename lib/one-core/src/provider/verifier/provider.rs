use std::collections::HashMap;
use std::sync::Arc;

use super::model::Verifier;
use crate::config::ConfigValidationError;
use crate::config::core_config::CoreConfig;
use crate::service::error::{MissingProviderError, ServiceError};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait VerifierProvider: Send + Sync {
    fn get_by_id(&self, id: &str) -> Result<Verifier, ServiceError>;
}

struct VerifierProviderImpl {
    verifiers: HashMap<String, Verifier>,
}

impl VerifierProvider for VerifierProviderImpl {
    fn get_by_id(&self, id: &str) -> Result<Verifier, ServiceError> {
        match self.verifiers.get(id) {
            Some(value) => Ok(value.clone()),
            None => Err(ServiceError::MissingProvider(
                MissingProviderError::Verifier(id.to_owned()),
            )),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verifier_provider_from_config(
    config: &CoreConfig,
) -> Result<Arc<dyn VerifierProvider>, ConfigValidationError> {
    let mut verifiers: HashMap<String, Verifier> = HashMap::new();
    for (name, fields) in config.verifier_provider.iter() {
        let verifier: Verifier =
            serde_json::from_value(fields.params.merge().unwrap_or(serde_json::Value::Null))
                .map_err(|e| ConfigValidationError::FieldsDeserialization {
                    key: name.clone(),
                    source: e,
                })?;
        verifiers.insert(name.clone(), verifier);
    }

    Ok(Arc::new(VerifierProviderImpl { verifiers }))
}
