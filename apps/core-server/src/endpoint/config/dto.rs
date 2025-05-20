use std::collections::HashMap;

use one_core::service::config::dto::ConfigDTO;
use one_dto_mapper::From;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[schema(example = json!({"format": {}, "identifier": {}, "issuanceProtocol": {}, "verificationProtocol": {}, "transport": {}, "revocation": {}, "did": {}, "datatype": {}, "keyAlgorithm": {}, "keyStorage": {}, "trustManagement": {}, "cacheEntities": {}}))]
#[from(ConfigDTO)]
pub struct ConfigRestDTO {
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
    /// How keys are stored.
    pub key_storage: HashMap<String, Value>,
    /// Trust management solutions.
    pub trust_management: HashMap<String, Value>,
    /// Entities held in temporary storage.
    pub cache_entities: HashMap<String, Value>,
}
