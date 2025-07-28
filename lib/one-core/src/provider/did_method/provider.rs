//! DID method provider.

use std::sync::Arc;

use indexmap::IndexMap;
use shared_types::DidValue;

use super::dto::DidDocumentDTO;
use super::resolver::{DidCachingLoader, DidResolver};
use crate::model::did::Did;
use crate::model::key::Key;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::error::DidMethodProviderError;
use crate::provider::did_method::model::DidDocument;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DidMethodProvider: Send + Sync {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>>;

    fn get_did_method_id(&self, did: &DidValue) -> Option<String>;

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError>;

    async fn get_verification_method_id_from_did_and_key(
        &self,
        did: &Did,
        selected_key: &Key,
    ) -> Result<String, DidMethodProviderError>;

    fn supported_method_names(&self) -> Vec<String>;
}

pub struct DidMethodProviderImpl {
    caching_loader: DidCachingLoader,
    did_methods: IndexMap<String, Arc<dyn DidMethod>>,
    resolver: Arc<DidResolver>,
}

impl DidMethodProviderImpl {
    pub fn new(
        caching_loader: DidCachingLoader,
        did_methods: IndexMap<String, Arc<dyn DidMethod>>,
    ) -> Self {
        let resolver = DidResolver {
            did_methods: did_methods.clone(),
        };

        Self {
            caching_loader,
            did_methods,
            resolver: Arc::new(resolver),
        }
    }
}

#[async_trait::async_trait]
impl DidMethodProvider for DidMethodProviderImpl {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>> {
        self.did_methods.get(did_method_id).cloned()
    }

    fn get_did_method_id(&self, did: &DidValue) -> Option<String> {
        self.did_methods
            .iter()
            .find(|(_, method)| {
                method
                    .get_capabilities()
                    .method_names
                    .iter()
                    .any(|v| v == did.method())
            })
            .map(|(id, _)| id.clone())
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError> {
        let (content, _media_type) = self
            .caching_loader
            .get(did.as_str(), self.resolver.clone(), false)
            .await?;
        let dto: DidDocumentDTO = serde_json::from_slice(&content)?;
        Ok(dto.into())
    }

    async fn get_verification_method_id_from_did_and_key(
        &self,
        did: &Did,
        key: &Key,
    ) -> Result<String, DidMethodProviderError> {
        // Best-effort sanity check
        if let Some(ref keys) = did.keys {
            let key_related_to_did = keys.iter().map(|key| key.key.id).any(|id| id == key.id);
            if !key_related_to_did {
                return Err(DidMethodProviderError::VerificationMethodIdNotFound {
                    key_id: key.id,
                    did_id: did.id,
                });
            }
        }

        let did_document = self.resolve(&did.did).await?;
        let verification_methods = did_document.verification_method;
        let verification_method = match verification_methods
            .iter()
            .find(|method| method.id.contains(&key.id.to_string()))
            .cloned()
        {
            // Our did:web implementation puts the id as the identifier in the did document
            // -> this resolution works for did:web dids with multiple verification methods.
            Some(id) => id,
            // For did methods with exactly one verification method,the only verification method is
            // the matching one.
            // This branch is taken for did:key and did:jwk.
            None if verification_methods.len() == 1 => verification_methods[0].to_owned(),
            _ => {
                // Return an error if the result would be ambiguous
                // TODO: more elaborate logic to find the key based on the public key bytes maybe?
                return Err(DidMethodProviderError::VerificationMethodIdNotFound {
                    key_id: key.id,
                    did_id: did.id,
                });
            }
        };
        Ok(verification_method.id)
    }

    fn supported_method_names(&self) -> Vec<String> {
        self.did_methods
            .values()
            .flat_map(|did_method| did_method.get_capabilities().method_names)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use indexmap::indexmap;
    use maplit::hashmap;
    use serde_json::json;
    use similar_asserts::assert_eq;
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::*;
    use crate::model::did::{DidType, KeyRole, RelatedKey};
    use crate::model::key::{PublicKeyJwk, PublicKeyJwkOctData};
    use crate::provider::caching_loader::CachingLoader;
    use crate::provider::did_method::MockDidMethod;
    use crate::provider::did_method::model::{DidCapabilities, DidVerificationMethod};
    use crate::provider::remote_entity_storage::RemoteEntityType;
    use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;

    #[tokio::test]
    async fn test_resolve_only_one_verification_method() {
        let verification_method_id = "did:test:123#0";
        let did_document = test_document(vec![test_verification_method(
            verification_method_id.to_string(),
        )]);
        let provider = setup_provider(did_document);

        let result = provider
            .get_verification_method_id_from_did_and_key(&test_did(None), &test_key())
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), verification_method_id);
    }

    #[tokio::test]
    async fn test_matching_resolve_with_many_verification_methods() {
        let key = test_key();
        let verification_method_id = format!("did:test:123#{}", key.id);
        let did_document = test_document(vec![
            test_verification_method("did:test:123#0".to_string()),
            test_verification_method(verification_method_id.clone()),
        ]);
        let provider = setup_provider(did_document);

        let result = provider
            .get_verification_method_id_from_did_and_key(&test_did(None), &key)
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), verification_method_id);
    }

    #[tokio::test]
    async fn test_not_matching_resolve_with_many_verification_methods() {
        let did_document = test_document(vec![
            test_verification_method("did:test:123#0".to_string()),
            test_verification_method("did:test:123#1".to_string()),
        ]);
        let provider = setup_provider(did_document);

        let result = provider
            .get_verification_method_id_from_did_and_key(&test_did(None), &test_key())
            .await;

        assert!(matches!(
            result,
            Err(DidMethodProviderError::VerificationMethodIdNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn test_relations_sanity_check_success() {
        let verification_method_id = "did:test:123#0";
        let did_document = test_document(vec![test_verification_method(
            verification_method_id.to_string(),
        )]);
        let provider = setup_provider(did_document);
        let key = test_key();
        let did = test_did(Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: key.clone(),
        }]));

        let result = provider
            .get_verification_method_id_from_did_and_key(&did, &key)
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), verification_method_id);
    }

    #[tokio::test]
    async fn test_relations_sanity_check_failure() {
        let provider = setup_provider(test_document(vec![]));

        let result = provider
            .get_verification_method_id_from_did_and_key(&test_did(Some(vec![])), &test_key())
            .await;

        assert!(matches!(
            result,
            Err(DidMethodProviderError::VerificationMethodIdNotFound { .. })
        ));
    }

    fn setup_provider(did_document: DidDocument) -> DidMethodProviderImpl {
        let mut did_method = MockDidMethod::new();
        did_method
            .expect_resolve()
            .return_once(|_| Ok(did_document));
        did_method
            .expect_get_capabilities()
            .returning(|| DidCapabilities {
                operations: vec![],
                key_algorithms: vec![],
                method_names: vec!["test".to_string()],
                features: vec![],
                supported_update_key_types: vec![],
            });
        let did_method_arc: Arc<dyn DidMethod> = Arc::new(did_method);
        let caching_loader = CachingLoader::new(
            RemoteEntityType::DidDocument,
            Arc::new(InMemoryStorage::new(hashmap! {})),
            100,
            Duration::seconds(100),
            Duration::seconds(100),
        );
        DidMethodProviderImpl::new(
            caching_loader,
            indexmap! {"TEST".to_string() => did_method_arc},
        )
    }

    fn test_verification_method(id: String) -> DidVerificationMethod {
        DidVerificationMethod {
            id,
            r#type: "did:test:123".to_string(),
            controller: "did:test:123-controller".to_string(),
            public_key_jwk: PublicKeyJwk::Oct(PublicKeyJwkOctData {
                alg: None,
                r#use: None,
                kid: None,
                k: "dummy key".to_string(),
            }),
        }
    }

    fn test_document(verification_methods: Vec<DidVerificationMethod>) -> DidDocument {
        DidDocument {
            context: json!({}),
            id: DidValue::from_str("did:test:123").unwrap(),
            verification_method: verification_methods,
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            also_known_as: None,
            service: None,
        }
    }

    fn test_did(keys: Option<Vec<RelatedKey>>) -> Did {
        Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "".to_string(),
            did: DidValue::from_str("did:test:123").unwrap(),
            did_type: DidType::Local,
            did_method: "TEST".to_string(),
            deactivated: false,
            keys,
            organisation: None,
            log: None,
        }
    }

    fn test_key() -> Key {
        Key {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key: vec![],
            name: "test key".to_string(),
            key_reference: None,
            storage_type: "".to_string(),
            key_type: "".to_string(),
            organisation: None,
        }
    }
}
