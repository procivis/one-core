use std::collections::HashMap;

use one_core::service::config::dto::ConfigDTO;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigRestDTO {
    /// Credential formats for issuing, holding and verifying.
    #[schema(example = json!({}))]
    pub format: HashMap<String, Value>,
    /// Identifier types to associate entities to schemas, credentials, trust lists and proofs.
    #[schema(example = json!({}))]
    pub identifier: HashMap<String, Value>,
    /// Protocols for the issuance of credentials.
    #[schema(example = json!({}))]
    pub issuance_protocol: HashMap<String, Value>,
    /// Protocols for the verification of credentials.
    #[schema(example = json!({}))]
    pub verification_protocol: HashMap<String, Value>,
    /// Transport protocols over which to communicate.
    #[schema(example = json!({}))]
    pub transport: HashMap<String, Value>,
    /// Revocation methods for credential status.
    #[schema(example = json!({}))]
    pub revocation: HashMap<String, Value>,
    /// DID methods used for identifying agents.
    #[schema(example = json!({}))]
    pub did: HashMap<String, Value>,
    /// Datatypes for claim validation.
    #[schema(example = json!({}))]
    pub datatype: HashMap<String, Value>,
    /// Key algorithms used for signatures.
    #[schema(example = json!({}))]
    pub key_algorithm: HashMap<String, Value>,
    /// Supported key storage security levels.
    #[schema(example = json!({}))]
    pub key_security_level: HashMap<String, Value>,
    /// How keys are stored.
    #[schema(example = json!({}))]
    pub key_storage: HashMap<String, Value>,
    /// Trust management solutions.
    #[schema(example = json!({}))]
    pub trust_management: HashMap<String, Value>,
    /// Entities held in temporary storage.
    #[schema(example = json!({}))]
    pub cache_entities: HashMap<String, Value>,
    /// Maintenance tasks
    #[schema(example = json!({}))]
    pub task: HashMap<String, Value>,
    /// Blob storage
    #[schema(example = json!({}))]
    pub blob_storage: HashMap<String, Value>,
    /// Frontend configuration
    #[schema(example = json!({}))]
    pub frontend: HashMap<String, Value>,
    /// OpenID4VCI authorization code flow
    #[schema(example = json!({}))]
    pub credential_issuer: HashMap<String, Value>,
    #[schema(example = json!({}))]
    pub verification_engagement: HashMap<String, Value>,
    #[schema(example = json!({}))]
    pub wallet_provider: HashMap<String, Value>,
    #[schema(example = json!({}))]
    pub signer: HashMap<String, Value>,
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
            key_storage: config.key_storage,
            key_security_level: config.key_security_level,
            trust_management: config.trust_management,
            cache_entities: config.cache_entities,
            task: config.task,
            blob_storage: config.blob_storage,
            frontend: HashMap::new(),
            credential_issuer: config.credential_issuer,
            verification_engagement: config.verification_engagement,
            wallet_provider: config.wallet_provider,
            signer: config.signer,
        }
    }
}
