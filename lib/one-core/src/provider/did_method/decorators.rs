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

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::provider::did_method::MockDidMethod;
    use crate::provider::did_method::keys::MinMax;
    use crate::service::test_utilities::dummy_key;

    fn capabilities(operations: Vec<Operation>) -> DidCapabilities {
        DidCapabilities {
            operations,
            key_algorithms: vec![KeyAlgorithmType::Eddsa],
            method_names: vec![],
            features: vec![],
            supported_update_key_types: vec![KeyAlgorithmType::Eddsa],
        }
    }

    fn limits(authentication_max: usize) -> Keys {
        let optional = || MinMax { min: 0, max: 5 };
        Keys {
            global: MinMax { min: 1, max: 5 },
            authentication: MinMax {
                min: 1,
                max: authentication_max,
            },
            assertion_method: optional(),
            key_agreement: optional(),
            capability_invocation: optional(),
            capability_delegation: optional(),
        }
    }

    fn authentication_keys(keys: Vec<Key>) -> DidKeys {
        DidKeys {
            authentication: keys,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_update_rejected_when_operation_not_supported() {
        let mut inner = MockDidMethod::new();
        inner
            .expect_get_capabilities()
            .returning(|| capabilities(vec![Operation::CREATE, Operation::RESOLVE]));
        let method = CapabilityChecked(Arc::new(inner));

        let result = method
            .update(
                Uuid::new_v4().into(),
                DidKeys::default(),
                authentication_keys(vec![dummy_key()]),
                None,
            )
            .await;

        assert2::assert!(let Err(DidMethodError::OperationNotSupported) = result);
    }

    #[tokio::test]
    async fn test_update_rejected_for_unsupported_key_algorithm() {
        let mut inner = MockDidMethod::new();
        inner
            .expect_get_capabilities()
            .returning(|| capabilities(vec![Operation::UPDATE]));
        inner.expect_get_keys().returning(|| Some(limits(5)));
        let method = CapabilityChecked(Arc::new(inner));

        let key = Key {
            key_type: "ECDSA".to_string(),
            ..dummy_key()
        };
        let result = method
            .update(
                Uuid::new_v4().into(),
                DidKeys::default(),
                authentication_keys(vec![key]),
                None,
            )
            .await;

        assert2::assert!(let Err(DidMethodError::UnsupportedKeyType(_)) = result);
    }

    #[tokio::test]
    async fn test_update_rejected_for_unsupported_update_key_algorithm() {
        let mut inner = MockDidMethod::new();
        inner
            .expect_get_capabilities()
            .returning(|| capabilities(vec![Operation::UPDATE]));
        let method = CapabilityChecked(Arc::new(inner));

        let update_key = Key {
            key_type: "ECDSA".to_string(),
            ..dummy_key()
        };
        let result = method
            .update(
                Uuid::new_v4().into(),
                DidKeys::default(),
                DidKeys {
                    authentication: vec![dummy_key()],
                    update_keys: Some(vec![update_key]),
                    ..Default::default()
                },
                None,
            )
            .await;

        assert2::assert!(let Err(DidMethodError::UnsupportedKeyType(_)) = result);
    }

    #[tokio::test]
    async fn test_update_rejected_for_invalid_number_of_keys() {
        let mut inner = MockDidMethod::new();
        inner
            .expect_get_capabilities()
            .returning(|| capabilities(vec![Operation::UPDATE]));
        inner.expect_get_keys().returning(|| Some(limits(1)));
        let method = CapabilityChecked(Arc::new(inner));

        let result = method
            .update(
                Uuid::new_v4().into(),
                DidKeys::default(),
                authentication_keys(vec![dummy_key(), dummy_key()]),
                None,
            )
            .await;

        assert2::assert!(let Err(DidMethodError::InvalidNumberOfKeys) = result);
    }

    #[tokio::test]
    async fn test_update_delegates_when_valid() {
        let mut inner = MockDidMethod::new();
        inner
            .expect_get_capabilities()
            .returning(|| capabilities(vec![Operation::UPDATE]));
        inner.expect_get_keys().returning(|| Some(limits(5)));
        inner.expect_update().once().returning(|_, _, _, _| {
            Ok(DidUpdate {
                deactivated: None,
                log: Some("log".to_string()),
            })
        });
        let method = CapabilityChecked(Arc::new(inner));

        let update = method
            .update(
                Uuid::new_v4().into(),
                DidKeys::default(),
                authentication_keys(vec![dummy_key()]),
                None,
            )
            .await
            .unwrap();

        assert_eq!(update.log.as_deref(), Some("log"));
        assert_eq!(update.deactivated, None);
    }
}
