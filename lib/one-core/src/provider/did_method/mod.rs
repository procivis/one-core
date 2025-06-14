//! Tools for DID method operations and metadata.
//!
//! Decentralized identifiers (DIDs) are a type of globally unique identifier
//! for a resource. The DID is similar to a URL and can be resolved to a DID
//! document which offers metadata about the identified resource.
//!
//! Use this module to perform all operations associated with the relevant
//! DID method.

use async_trait::async_trait;
use error::DidMethodError;
use keys::Keys;
use model::{AmountOfKeys, DidCapabilities, DidDocument};
use shared_types::{DidId, DidValue};

use crate::model::key::Key;

pub mod common;
pub mod did_document;
pub mod dto;
pub mod error;
pub mod jwk;
pub mod key;
pub mod key_helpers;
pub mod keys;
pub mod mdl;
pub mod model;
pub mod provider;
pub mod resolver;
pub mod sd_jwt_vc_issuer_metadata;
pub mod universal;
pub mod web;
pub mod webvh;
pub mod x509;

/// Performs operations on DIDs and provides DID utilities.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait DidMethod: Send + Sync {
    /// Creates a DID.
    async fn create(
        &self,
        id: Option<DidId>,
        params: &Option<serde_json::Value>,
        keys: Option<DidKeys>,
    ) -> Result<DidCreated, DidMethodError>;

    /// Resolve a DID to its DID document.
    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError>;

    /// Deactivates a DID. Note that DID deactivation is permanent.
    async fn deactivate(
        &self,
        did_id: DidId,
        keys: DidKeys,
        log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError>;

    /// Informs whether a DID can be deactivated or not.
    ///
    /// DID deactivation is useful if, for instance, a private key is leaked.
    fn can_be_deactivated(&self) -> bool;

    /// See the [API docs][dmc] for a complete list of credential format capabilities.
    ///
    /// [dmc]: https://docs.procivis.ch/api/resources/dids#did-method-capabilities
    fn get_capabilities(&self) -> DidCapabilities;

    /// Validates whether the number of keys assigned is supported by the DID method.
    ///
    /// Different DID methods support different numbers of keys for verification relationships.
    /// This method validates whether the method of the DID supports the keys associated with it.
    fn validate_keys(&self, keys: AmountOfKeys) -> bool;
    /// Returns the keys associated with a DID.
    fn get_keys(&self) -> Option<Keys>;
}

#[derive(Debug, Clone)]
pub struct DidCreated {
    pub did: DidValue,
    pub log: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DidUpdate {
    pub deactivated: Option<bool>,
    pub log: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DidKeys {
    pub authentication: Vec<Key>,
    pub assertion_method: Vec<Key>,
    pub key_agreement: Vec<Key>,
    pub capability_invocation: Vec<Key>,
    pub capability_delegation: Vec<Key>,
    /// used for signing did-log entries for did:webvh
    pub update_keys: Option<Vec<Key>>,
}
