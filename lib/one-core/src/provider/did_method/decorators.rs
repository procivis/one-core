use std::fmt::Display;
use std::sync::Arc;

use shared_types::{DidId, DidMethodId, DidValue};

use super::error::DidMethodError;
use super::model::{DidCapabilities, DidDocument, Operation};
use super::{DidCreated, DidKeys, DidMethod, DidUpdate, Keys};
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;

impl WithDisabledDecorator for dyn DidMethod {
    fn decorate(self: Arc<dyn DidMethod>) -> Arc<dyn DidMethod> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + DidMethod + Display + ?Sized> DidMethod for DisabledProvider<T> {
    async fn create(
        &self,
        _id: DidId,
        _params: &Option<serde_json::Value>,
        _keys: DidKeys,
    ) -> Result<DidCreated, DidMethodError> {
        self.disabled_error()
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError> {
        self.inner().resolve(did).await
    }

    async fn deactivate(
        &self,
        did_id: DidId,
        keys: DidKeys,
        log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        self.inner().deactivate(did_id, keys, log).await
    }

    async fn update(
        &self,
        did_id: DidId,
        keys: DidKeys,
        new_keys: DidKeys,
        log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        self.inner().update(did_id, keys, new_keys, log).await
    }

    fn get_capabilities(&self) -> DidCapabilities {
        let mut capabilities = self.inner().get_capabilities();
        capabilities
            .operations
            .retain(|op| op != &Operation::CREATE);
        capabilities
    }

    fn get_keys(&self) -> Option<Keys> {
        self.inner().get_keys()
    }

    fn get_reference_for_key(&self, key: &Key) -> Result<String, DidMethodError> {
        self.inner().get_reference_for_key(key)
    }

    fn config_name(&self) -> &DidMethodId {
        self.inner().config_name()
    }
}

/// Checks supported operations
pub(super) struct CapabilityChecked(pub Arc<dyn DidMethod>);

impl Provider for CapabilityChecked {
    fn capabilities(&self) -> Option<serde_json::Value> {
        self.0.capabilities()
    }
}

fn check_key_types<'a, I: Iterator<Item = &'a Key>>(
    keys: I,
    supported_algorithms: &[KeyAlgorithmType],
) -> Result<(), DidMethodError> {
    for key in keys {
        let key_type = key
            .key_algorithm_type()
            .error_while("parsing key algorithm")?;

        if !supported_algorithms.contains(&key_type) {
            return Err(DidMethodError::UnsupportedKeyType(key_type.to_string()));
        }
    }

    Ok(())
}

impl CapabilityChecked {
    fn validate_keys(
        &self,
        keys: &DidKeys,
        capabilities: &DidCapabilities,
    ) -> Result<(), DidMethodError> {
        if let Some(update_keys) = &keys.update_keys {
            check_key_types(update_keys.iter(), &capabilities.supported_update_key_types)?;
        }

        let content_keys = vec![
            &keys.authentication,
            &keys.assertion_method,
            &keys.key_agreement,
            &keys.capability_invocation,
            &keys.capability_delegation,
        ]
        .into_iter()
        .flatten();
        check_key_types(content_keys, &capabilities.key_algorithms)?;

        if let Some(limits) = self.0.get_keys()
            && !limits.validate_keys(keys)
        {
            return Err(DidMethodError::InvalidNumberOfKeys);
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl DidMethod for CapabilityChecked {
    async fn create(
        &self,
        id: DidId,
        params: &Option<serde_json::Value>,
        keys: DidKeys,
    ) -> Result<DidCreated, DidMethodError> {
        let capabilities = self.0.get_capabilities();
        if !capabilities.operations.contains(&Operation::CREATE) {
            return Err(DidMethodError::OperationNotSupported);
        }

        self.validate_keys(&keys, &capabilities)?;

        self.0.create(id, params, keys).await
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError> {
        if !self
            .0
            .get_capabilities()
            .operations
            .contains(&Operation::RESOLVE)
        {
            return Err(DidMethodError::OperationNotSupported);
        }

        self.0.resolve(did).await
    }

    async fn deactivate(
        &self,
        did_id: DidId,
        keys: DidKeys,
        log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        if !self
            .0
            .get_capabilities()
            .operations
            .contains(&Operation::DEACTIVATE)
        {
            return Err(DidMethodError::OperationNotSupported);
        }

        self.0.deactivate(did_id, keys, log).await
    }

    async fn update(
        &self,
        did_id: DidId,
        keys: DidKeys,
        new_keys: DidKeys,
        log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        let capabilities = self.0.get_capabilities();
        if !capabilities.operations.contains(&Operation::UPDATE) {
            return Err(DidMethodError::OperationNotSupported);
        }
        self.validate_keys(&new_keys, &capabilities)?;
        self.0.update(did_id, keys, new_keys, log).await
    }

    fn get_capabilities(&self) -> DidCapabilities {
        self.0.get_capabilities()
    }

    fn get_keys(&self) -> Option<Keys> {
        self.0.get_keys()
    }

    fn get_reference_for_key(&self, key: &Key) -> Result<String, DidMethodError> {
        self.0.get_reference_for_key(key)
    }

    fn config_name(&self) -> &DidMethodId {
        self.0.config_name()
    }
}
