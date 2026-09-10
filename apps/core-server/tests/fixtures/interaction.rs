use std::collections::HashMap;

use one_core::model::credential_schema::CredentialSchema;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use shared_types::{CredentialId, CredentialSchemaFormatId};
use standardized_types::openid4vci::KeyStorageSecurityLevel;
use time::Duration;
use time::macros::format_description;

use crate::fixtures::encrypted_token;
use crate::utils::context::TestContext;

#[derive(Default)]
pub struct InteractionDataParams {
    pub require_instance_attestation: bool,
    pub require_tx_code: bool,
    pub access_token_expired: bool,
    pub refresh_token_expired: bool,
    pub format: Option<String>,
    pub notification_id: Option<String>,
    pub notification_endpoint: Option<String>,
    pub batch_size: Option<u32>,
    pub issuer_display: Option<serde_json::Value>,
    /// credential configurations offered next to the default one
    pub additional_configurations: Vec<ConfigurationParams>,
}

pub struct ConfigurationParams {
    pub credential_configuration_id: String,
    pub format: String,
    pub notification_id: Option<String>,
    pub credential_id: Option<CredentialId>,
}

impl InteractionDataParams {
    pub fn with_format(format: String) -> Self {
        Self {
            format: Some(format),
            ..Default::default()
        }
    }
}

pub fn dummy_interaction_data(
    context: &TestContext,
    credential_schema: &CredentialSchema,
    params: InteractionDataParams,
) -> Vec<u8> {
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

    let issuer_url = format!(
        "{}/ssi/openid4vci/final-1.0/{}",
        context.server_mock.uri(),
        credential_schema.id,
    );
    let mut configuration = json!({
        "credential_configuration_id": "01ee2044-2e75-4a3b-a575-b48669bd8254",
        "format": params.format.unwrap_or("jwt_vc_json".to_string()),
        "cryptographic_binding_methods_supported": [
            "jwk",
            "cose_key"
        ],
        "proof_types_supported": {
            "jwt": {
                "proof_signing_alg_values_supported": [
                    "EdDSA",
                    "ES256",
                ]
            }
        },
        "credential_metadata": {
            "display": [
                {
                    "lang": "en",
                    "name": "test"
                }
            ]
        },
    });
    if let Some(key_security_level) = credential_schema.key_storage_security {
        configuration["proof_types_supported"]["jwt"]["key_attestations_required"] = json!({
            "key_storage": [KeyStorageSecurityLevel::from(key_security_level)]
        });
    }
    if let Some(notification_id) = params.notification_id {
        configuration["notification_id"] = json!(notification_id);
    }
    let mut configurations = vec![configuration];
    for configuration in params.additional_configurations {
        configurations.push(json!({
            "credential_configuration_id": configuration.credential_configuration_id,
            "format": configuration.format,
            "cryptographic_binding_methods_supported": ["jwk", "cose_key"],
            "notification_id": configuration.notification_id,
            "credential_id": configuration.credential_id,
        }));
    }

    let mut value = json!({
    "issuer_url": issuer_url,
    "credential_endpoint": format!("{}/credential", issuer_url),
    "token_endpoint": format!("{}/token", issuer_url),
    "nonce_endpoint": format!("{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/nonce", context.server_mock.uri()),
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
    "trust_resolution": "UNTRUSTED",
    "trust_mode": "TRUST_OPTIONAL"
    });
    if params.require_instance_attestation {
        value["token_endpoint_auth_methods_supported"] = json!(["attest_jwt_client_auth"]);
        value["client_attestation_pop_signing_alg_values_supported"] = json!(["ES256"]);
    }
    if params.require_tx_code {
        value["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["tx_code"] =
            json!({"input_mode":"numeric","length":5,"description":"code"});
    }
    if let Some(notification_endpoint) = params.notification_endpoint {
        value["notification_endpoint"] = json!(notification_endpoint);
    }
    if let Some(batch_size) = params.batch_size {
        value["batch_size"] = json!(batch_size);
    }
    if let Some(issuer_display) = params.issuer_display {
        value["issuer_display"] = issuer_display;
    }
    serde_json::to_vec(&value).unwrap()
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
