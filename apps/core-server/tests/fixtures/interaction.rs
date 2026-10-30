use std::collections::HashMap;

use one_core::model::credential_schema::CredentialSchema;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use shared_types::{CredentialId, CredentialSchemaFormatId};
use standardized_types::openid4vci::SecurityLevel;
use time::Duration;
use time::macros::format_description;

use crate::fixtures::encrypted_token;
use crate::utils::context::TestContext;

#[derive(Default)]
pub struct InteractionDataParams {
    pub require_instance_attestation: bool,
    /// issuer supports DPoP combined mode, requires `require_instance_attestation`
    pub dpop_combined_mode: bool,
    pub require_tx_code: bool,
    pub access_token_expired: bool,
    pub refresh_token_expired: bool,
    /// no refresh token was issued
    pub without_refresh_token: bool,
    /// overrides the credential endpoint of the issuer
    pub credential_endpoint: Option<String>,
    /// id of the default configuration
    pub credential_configuration_id: Option<String>,
    pub format: Option<String>,
    /// binding methods of the default configuration, `jwk` and `cose_key` if unset
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub disclosure_policy: Option<serde_json::Value>,
    pub notification_id: Option<String>,
    /// top-level credential issued for the default configuration
    pub credential_id: Option<CredentialId>,
    /// format of the credential issued for the default configuration
    pub credential_schema_format_id: Option<CredentialSchemaFormatId>,
    pub notification_endpoint: Option<String>,
    pub batch_size: Option<u32>,
    pub issuer_display: Option<serde_json::Value>,
    /// credential configurations offered next to the default one
    pub additional_configurations: Vec<ConfigurationParams>,
}

#[derive(Default)]
pub struct ConfigurationParams {
    pub credential_configuration_id: String,
    pub format: String,
    /// `jwk` and `cose_key` if unset
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub disclosure_policy: Option<serde_json::Value>,
    pub notification_id: Option<String>,
    pub credential_id: Option<CredentialId>,
    pub credential_schema_format_id: Option<CredentialSchemaFormatId>,
}

impl InteractionDataParams {
    pub fn with_format(format: String) -> Self {
        Self {
            format: Some(format),
            ..Default::default()
        }
    }
}

/// Credential issuer metadata of the issuer of `credential_schema`, located at
/// `context.server_mock`. Tests accepting an offer serve it with
/// `context.server_mock.issuer_metadata`.
pub fn dummy_issuer_metadata(
    context: &TestContext,
    credential_schema: &CredentialSchema,
    params: &InteractionDataParams,
) -> serde_json::Value {
    let issuer_url = issuer_url(context, credential_schema);
    let mut default_configuration = configuration_metadata(&default_configuration(params));
    default_configuration["proof_types_supported"] = json!({
        "jwt": {
            "proof_signing_alg_values_supported": [
                "EdDSA",
                "ES256",
            ]
        }
    });
    default_configuration["credential_metadata"] = json!({
        "display": [
            {
                "lang": "en",
                "name": "test"
            }
        ]
    });
    if let Some(key_security_level) = credential_schema
        .wallet_attestation
        .key_storage_security_level
    {
        default_configuration["proof_types_supported"]["jwt"]["key_attestations_required"] = json!({
            "key_storage": [SecurityLevel::from(key_security_level)]
        });
    }
    let mut configurations = serde_json::Map::new();
    configurations.insert(default_configuration_id(params), default_configuration);
    for configuration in &params.additional_configurations {
        configurations.insert(
            configuration.credential_configuration_id.clone(),
            configuration_metadata(configuration),
        );
    }

    let mut metadata = json!({
        "credential_issuer": issuer_url,
        "credential_endpoint": params
            .credential_endpoint
            .clone()
            .unwrap_or(format!("{issuer_url}/credential")),
        "nonce_endpoint": format!(
            "{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/nonce",
            context.server_mock.uri()
        ),
        "credential_configurations_supported": configurations,
    });
    if let Some(notification_endpoint) = &params.notification_endpoint {
        metadata["notification_endpoint"] = json!(notification_endpoint);
    }
    if let Some(batch_size) = params.batch_size {
        metadata["batch_credential_issuance"] = json!({ "batch_size": batch_size });
    }
    if let Some(issuer_display) = &params.issuer_display {
        metadata["display"] = issuer_display.clone();
    }
    metadata
}

/// Interaction data the holder stores for an offer of the issuer of `credential_schema`, whose
/// metadata is [`dummy_issuer_metadata`]
pub fn dummy_holder_issuance_interaction_data(
    context: &TestContext,
    credential_schema: &CredentialSchema,
    params: InteractionDataParams,
) -> Vec<u8> {
    let issuer_metadata = dummy_issuer_metadata(context, credential_schema, &params);
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let now = one_core::clock::now_utc();
    let at_expiry = match params.access_token_expired {
        true => now - Duration::seconds(20),
        false => now + Duration::seconds(20),
    };
    let rt_expiry = match params.refresh_token_expired {
        true => now - Duration::seconds(20),
        false => now + Duration::seconds(20),
    };

    let issuer_url = issuer_url(context, credential_schema);
    let configurations: Vec<_> = std::iter::once(default_configuration(&params))
        .chain(params.additional_configurations)
        .map(|configuration| {
            let mut stored = issuer_metadata["credential_configurations_supported"]
                [&configuration.credential_configuration_id]
                .clone();
            // the display data is taken from the current issuer metadata when accepting
            stored
                .as_object_mut()
                .unwrap()
                .remove("credential_metadata");
            for (key, value) in configuration_state(&configuration).as_object().unwrap() {
                stored[key] = value.clone();
            }
            stored
        })
        .collect();

    let mut value = json!({
    "issuer_url": issuer_url,
    "credential_endpoint": issuer_metadata["credential_endpoint"],
    "token_endpoint": format!("{}/token", issuer_url),
    "nonce_endpoint": issuer_metadata["nonce_endpoint"],
    "grants":{
        "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
            "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
        }
    },
    "access_token": encrypted_token("123"),
    "access_token_expires_at": at_expiry.format(&format).unwrap(),
    "refresh_token": encrypted_token("123"),
    "refresh_token_expires_at": rt_expiry.format(&format).unwrap(),
    "token_endpoint_auth_methods_supported": [
        "none"
    ],
    "protocol": "OPENID4VCI_FINAL1",
    "credential_configurations": configurations,
    });
    if params.without_refresh_token {
        value.as_object_mut().unwrap().remove("refresh_token");
        value
            .as_object_mut()
            .unwrap()
            .remove("refresh_token_expires_at");
    }
    if params.require_instance_attestation {
        value["token_endpoint_auth_methods_supported"] = json!(["attest_jwt_client_auth"]);
        value["client_attestation_pop_signing_alg_values_supported"] = json!(["ES256"]);
    }
    if params.dpop_combined_mode {
        value["token_endpoint_auth_methods_supported"] =
            json!(["attest_jwt_client_auth", "attest_jwt_client_auth_dpop"]);
        value["dpop_signing_alg_values_supported"] = json!(["ES256"]);
    }
    if params.require_tx_code {
        value["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["tx_code"] =
            json!({"input_mode":"numeric","length":5,"description":"code"});
    }
    if let Some(notification_endpoint) = issuer_metadata.get("notification_endpoint") {
        value["notification_endpoint"] = notification_endpoint.clone();
    }
    if let Some(batch_size) = params.batch_size {
        value["batch_size"] = json!(batch_size);
    }
    serde_json::to_vec(&value).unwrap()
}

fn issuer_url(context: &TestContext, credential_schema: &CredentialSchema) -> String {
    format!(
        "{}/ssi/openid4vci/final-1.0/{}",
        context.server_mock.uri(),
        credential_schema.id,
    )
}

fn default_configuration_id(params: &InteractionDataParams) -> String {
    params
        .credential_configuration_id
        .clone()
        .unwrap_or("01ee2044-2e75-4a3b-a575-b48669bd8254".to_string())
}

fn default_configuration(params: &InteractionDataParams) -> ConfigurationParams {
    ConfigurationParams {
        credential_configuration_id: default_configuration_id(params),
        format: params.format.clone().unwrap_or("jwt_vc_json".to_string()),
        cryptographic_binding_methods_supported: params
            .cryptographic_binding_methods_supported
            .clone(),
        disclosure_policy: params.disclosure_policy.clone(),
        notification_id: params.notification_id.clone(),
        credential_id: params.credential_id,
        credential_schema_format_id: params.credential_schema_format_id,
    }
}

/// Issuer metadata of a credential configuration
fn configuration_metadata(params: &ConfigurationParams) -> serde_json::Value {
    let mut metadata = json!({
        "format": params.format,
        "cryptographic_binding_methods_supported": params
            .cryptographic_binding_methods_supported
            .clone()
            .unwrap_or(vec!["jwk".to_string(), "cose_key".to_string()]),
    });
    if let Some(disclosure_policy) = &params.disclosure_policy {
        metadata["disclosure_policy"] = disclosure_policy.clone();
    }
    metadata
}

/// Issuance state of a credential configuration
fn configuration_state(params: &ConfigurationParams) -> serde_json::Value {
    let mut state = json!({
        "credential_configuration_id": params.credential_configuration_id,
    });
    if let Some(notification_id) = &params.notification_id {
        state["notification_ids"] = json!([notification_id]);
    }
    if let Some(credential_id) = params.credential_id {
        state["credential_id"] = json!(credential_id);
    }
    if let Some(credential_schema_format_id) = params.credential_schema_format_id {
        state["credential_schema_format_id"] = json!(credential_schema_format_id);
    }
    state
}

#[derive(Default)]
pub struct IssuerInteractionDataParams {
    pub access_token_expired: bool,
    pub offered_formats: Vec<CredentialSchemaFormatId>,
    pub notification_ids: HashMap<CredentialSchemaFormatId, String>,
}

/// Returns interaction_data_bytes.
pub fn dummy_issuer_interaction_data(
    access_token: &str,
    params: IssuerInteractionDataParams,
) -> Vec<u8> {
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let now = one_core::clock::now_utc();
    let at_expiry = if params.access_token_expired {
        now - Duration::seconds(20)
    } else {
        now + Duration::seconds(20)
    };
    let data = json!({
        "pre_authorized_code_used": true,
        "access_token_hash": SHA256.hash(access_token.as_bytes()).unwrap(),
        "access_token_expires_at": at_expiry.format(&format).unwrap(),
        "formats": (!params.offered_formats.is_empty()).then_some(&params.offered_formats),
        "notification_ids": params
            .notification_ids
            .iter()
            .map(|(format, notification_id)| {
                json!({ "notification_id": notification_id, "format": format })
            })
            .collect::<Vec<_>>(),
    });
    serde_json::to_vec(&data).unwrap()
}
