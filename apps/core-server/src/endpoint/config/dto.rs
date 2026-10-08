use std::collections::HashMap;

use one_core::service::config::dto::{
    ConfigDTO, CredentialSchemaGlobalSettingsDTO, GlobalSettingsDTO,
};
use one_dto_mapper::From;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigRestDTO {
    /// Credential formats for issuing, holding and verifying.
    #[schema(example = json!({}))]
    pub format: HashMap<String, Value>,
    /// Available identifier types. Identifiers represent entities and are used
    /// across credential operations and certificate workflows
    #[schema(example = json!({}))]
    pub identifier: HashMap<String, Value>,
    /// Protocols for credential issuance.
    #[schema(example = json!({}))]
    pub issuance_protocol: HashMap<String, Value>,
    /// Protocols for credential presentation and verification.
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
    /// Security levels for key storage. When creating a credential
    /// schema, the required level sets the minimum key storage standard
    /// a wallet must meet to receive issuance. On the holder side, the
    /// level also determines the key storage used when keys are
    /// auto-generated during issuance.
    #[schema(example = json!({}))]
    pub key_security_level: HashMap<String, Value>,
    /// Implementations for how keys are stored.
    #[schema(example = json!({}))]
    pub key_storage: HashMap<String, Value>,
    /// Entities held in temporary storage.
    #[schema(example = json!({}))]
    pub cache_entities: HashMap<String, Value>,
    /// Scheduled maintenance tasks, such as credential status check,
    /// trust collection syncing, and webhooks
    #[schema(example = json!({}))]
    pub task: HashMap<String, Value>,
    /// Storage configuration for large data objects (credentials,
    /// proofs, wallet unit attestations, registration certificates)
    /// kept outside the main primary database table for query
    /// performance.
    #[schema(example = json!({}))]
    pub blob_storage: HashMap<String, Value>,
    /// Configuration values consumed by the Desk frontend, such as
    /// feature flags and UI defaults.
    #[schema(example = json!({}))]
    pub frontend: HashMap<String, Value>,
    /// Issuer-initiated OpenID4VCI authorization code flow
    #[schema(example = json!({}))]
    pub credential_issuer: HashMap<String, Value>,
    /// Type of engagement to use when proposing a proof (wallet),
    /// or when creating a proof request (verifier).
    #[schema(example = json!({}))]
    pub verification_engagement: HashMap<String, Value>,
    /// Wallet provider implementations that manage wallet app instances,
    /// including unit attestation issuance and version constraints.
    #[schema(example = json!({}))]
    pub wallet_provider: HashMap<String, Value>,
    /// Signing implementations referenced when creating different
    /// certificate types, including X.509 certificates, and EUDI
    /// Access and Registration Certificates.
    #[schema(example = json!({}))]
    pub signer: HashMap<String, Value>,
    /// Implementations for publishing trust lists, such as ETSI LoTE.
    #[schema(example = json!({}))]
    pub trust_list_publisher: HashMap<String, Value>,
    /// Implementations for subscribing to and consuming trust lists.
    #[schema(example = json!({}))]
    pub trust_list_subscriber: HashMap<String, Value>,
    /// Verifier provider implementations that manage mobile verifier
    /// deployments and their configuration.
    #[schema(example = json!({}))]
    pub verifier_provider: HashMap<String, Value>,
    /// Implementations for processing OpenID4VP transaction data during
    /// credential presentation.
    #[schema(example = json!({}))]
    pub transaction_data_provider: HashMap<String, Value>,
    #[schema(example = json!({}))]
    pub ecosystem: HashMap<String, Value>,
    /// Deployment-wide settings that are not tied to a specific config entity.
    pub global_settings: GlobalSettingsRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(GlobalSettingsDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GlobalSettingsRestDTO {
    /// Default language tag for the deployment, used where no lanugage
    /// is otherwise specified, for example, in credential schema creation.
    pub default_language: String,
    /// Settings specific for credential schemas
    pub credential_schema: CredentialSchemaGlobalSettingsRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialSchemaGlobalSettingsDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaGlobalSettingsRestDTO {
    /// maximum allowed expiration when creating credential schema
    pub max_expiration_seconds: i64,
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
            cache_entities: config.cache_entities,
            task: config.task,
            blob_storage: config.blob_storage,
            frontend: HashMap::new(),
            credential_issuer: config.credential_issuer,
            verification_engagement: config.verification_engagement,
            wallet_provider: config.wallet_provider,
            signer: config.signer,
            trust_list_publisher: config.trust_list_publisher,
            trust_list_subscriber: config.trust_list_subscriber,
            verifier_provider: config.verifier_provider,
            transaction_data_provider: config.transaction_data_provider,
            ecosystem: config.ecosystem,
            global_settings: config.global_settings.into(),
        }
    }
}
