use std::collections::HashMap;

use one_core::service::config::dto::ConfigDTO;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(example = json!({"format": {}, "identifier": {}, "issuanceProtocol": {}, "verificationProtocol": {}, "transport": {}, "revocation": {}, "did": {}, "datatype": {}, "keyAlgorithm": {}, "keyStorage": {}, "trustManagement": {}, "cacheEntities": {}, "frontend": {}}))]
pub(crate) struct ConfigRestDTO {
    /// Credential formats for issuing, holding and verifying.
    pub format: HashMap<String, Value>,
    /// Identifier types to associate entities to schemas, credentials, trust lists and proofs.
    pub identifier: HashMap<String, Value>,
    /// Protocols for the issuance of credentials.
    pub issuance_protocol: HashMap<String, Value>,
    /// Protocols for the verification of credentials.
    pub verification_protocol: HashMap<String, Value>,
    /// Transport protocols over which to communicate.
    pub transport: HashMap<String, Value>,
    /// Revocation methods for credential status.
    pub revocation: HashMap<String, Value>,
    /// DID methods used for identifying agents.
    pub did: HashMap<String, Value>,
    /// Datatypes for claim validation.
    pub datatype: HashMap<String, Value>,
    /// Key algorithms used for signatures.
    pub key_algorithm: HashMap<String, Value>,
    /// Holder binding key storage types.
    pub holder_key_storage: HashMap<String, Value>,
    /// How keys are stored.
    pub key_storage: HashMap<String, Value>,
    /// Trust management solutions.
    pub trust_management: HashMap<String, Value>,
    /// Entities held in temporary storage.
    pub cache_entities: HashMap<String, Value>,
    /// Maintenance tasks
    pub task: HashMap<String, Value>,
    /// Blob storage
    pub blob_storage: HashMap<String, Value>,
    /// Frontend configuration
    pub frontend: HashMap<String, Value>,
    /// OpenID4VCI authorization code flow
    pub credential_issuer: HashMap<String, Value>,
}

impl From<ConfigDTO> for ConfigRestDTO {
    fn from(config: ConfigDTO) -> Self {
        ConfigRestDTO {
            format: config.format,
            identifier: config.identifier,
            issuance_protocol: config.issuance_protocol,
            verification_protocol: config.verification_protocol,
            transport: config.transport,
            revocation: config.revocation,
            did: config.did,
            datatype: config.datatype,
            key_algorithm: config.key_algorithm,
            holder_key_storage: config.holder_key_storage,
            key_storage: config.key_storage,
            trust_management: config.trust_management,
            cache_entities: config.cache_entities,
            task: config.task,
            blob_storage: config.blob_storage,
            frontend: HashMap::new(),
            credential_issuer: config.credential_issuer,
        }
    }
}
