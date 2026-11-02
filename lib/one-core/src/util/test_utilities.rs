use std::collections::HashMap;
use std::sync::Arc;

#[cfg(test)]
pub(crate) use holder_interaction_data::{
    TestHolderCredentialConfiguration, TestHolderInteractionData,
};
use mockall::predicate::{always, eq};
use time::Duration;

use crate::proto::http_client::{Method, MockHttpClient, RequestBuilder, Response};
use crate::provider::caching_loader::json_ld_context::JsonLdCachingLoader;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntity, RemoteEntityType};

pub fn mock_http_get_request(http_client: &mut MockHttpClient, url: String, response: Response) {
    let mut new_client = MockHttpClient::new();
    new_client
        .expect_send()
        .with(
            eq(url.clone()),
            always(),
            always(),
            eq(Method::Get),
            always(),
        )
        .return_once(move |_, _, _, _, _| Ok(response));

    http_client
        .expect_get()
        .with(eq(url))
        .return_once(move |url| RequestBuilder::new(Arc::new(new_client), Method::Get, url));
}

pub fn prepare_caching_loader(additional: Option<(&str, &str)>) -> JsonLdCachingLoader {
    let now = crate::clock::now_utc();
    let context = include_str!("context_vc2_0.jsonld");
    let mut contexts = vec![
        (
            "https://www.w3.org/ns/credentials/v2".to_string(),
            RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                key: "https://www.w3.org/ns/credentials/v2".to_string(),
                value: context.to_string().into_bytes(),
                last_used: now,
                media_type: None,
                expiration_date: Some(now + Duration::days(1)),
            },
        ),
        (
            "https://www.w3.org/ns/credentials/examples/v2".to_string(),
            RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                key: "https://www.w3.org/ns/credentials/examples/v2".to_string(),
                value: W3_ORG_NS_CREDENTIALS_EXAMPLES_V2.to_string().into_bytes(),
                last_used: now,
                media_type: None,
                expiration_date: Some(now + Duration::days(1)),
            },
        ),
    ];

    if let Some((id, content)) = additional {
        contexts.push((
            id.to_string(),
            RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                key: id.to_string(),
                value: content.to_string().into_bytes(),
                last_used: now,
                media_type: None,
                expiration_date: Some(now + Duration::days(1)),
            },
        ))
    }

    JsonLdCachingLoader::new(
        RemoteEntityType::JsonLdContext,
        Arc::new(InMemoryStorage::new(HashMap::from_iter(contexts))),
        10000,
        Duration::seconds(999999),
        Duration::seconds(300),
    )
}

#[cfg(test)]
pub(crate) fn assert_time_diff_less_than(
    time1: &time::OffsetDateTime,
    time2: &time::OffsetDateTime,
    max_diff: &Duration,
) {
    let diff = Duration::nanoseconds(
        (time1.unix_timestamp_nanos() - time2.unix_timestamp_nanos()).abs() as i64,
    );
    assert!(diff <= *max_diff)
}

const W3_ORG_NS_CREDENTIALS_EXAMPLES_V2: &str = r#"{
  "@context": {
    "@vocab": "https://www.w3.org/ns/credentials/examples#"
  }
}"#;

/// Builder of holder interaction data for the tests of this crate
#[cfg(test)]
mod holder_interaction_data {
    use indexmap::IndexMap;
    use serde::Deserialize;
    use shared_types::{CredentialId, CredentialSchemaFormatId};
    use standardized_types::etsi_119_472::disclosure_policy::DisclosurePolicy;
    use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
    use standardized_types::oauth2::dynamic_client_registration::TokenEndpointAuthMethod;
    use standardized_types::openid4vci::{
        BatchCredentialIssuance, CredentialConfiguration, CredentialIssuerMetadata,
        CredentialMetadata, CredentialRequestEncryption, CredentialResponseEncryption, Grants,
        IssuerDisplay, PreAuthorizedCodeGrant, ProofTypeSupported, SigningAlgValue,
    };
    use time::OffsetDateTime;

    use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
    use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
        DpopState, HolderCredentialConfiguration, HolderCredentialConfigurationState,
        HolderInteractionData, HolderIssuanceState, MetadataSource, TokenGrant, TokenState,
    };

    /// Flat test input of a [`HolderInteractionData`]
    pub(crate) struct TestHolderInteractionData {
        pub issuer_url: String,
        pub credential_endpoint: String,
        pub token_endpoint: Option<String>,
        pub notification_endpoint: Option<String>,
        pub nonce_endpoint: Option<String>,
        pub challenge_endpoint: Option<String>,
        pub grants: Option<Grants>,
        pub continue_issuance: Option<ContinueIssuanceDTO>,
        pub batch_size: Option<u32>,
        pub access_token: Option<Vec<u8>>,
        pub access_token_expires_at: Option<OffsetDateTime>,
        pub refresh_token: Option<Vec<u8>>,
        pub refresh_token_expires_at: Option<OffsetDateTime>,
        pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
        pub client_attestation_pop_signing_alg_values_supported: Option<Vec<String>>,
        pub issuer_display: Option<Vec<IssuerDisplay>>,
        pub credential_request_encryption: Option<CredentialRequestEncryption>,
        pub credential_response_encryption: Option<CredentialResponseEncryption>,
        pub dpop_signing_alg_values_supported: Option<Vec<String>>,
        pub dpop_nonce: Option<String>,
        pub protocol: String,
        pub credential_configurations: Vec<TestHolderCredentialConfiguration>,
    }

    impl Default for TestHolderInteractionData {
        fn default() -> Self {
            Self {
                issuer_url: "https://issuer.example.com".to_string(),
                credential_endpoint: "https://issuer.example.com/credential".to_string(),
                token_endpoint: None,
                notification_endpoint: None,
                nonce_endpoint: None,
                challenge_endpoint: None,
                grants: None,
                continue_issuance: None,
                batch_size: None,
                access_token: None,
                access_token_expires_at: None,
                refresh_token: None,
                refresh_token_expires_at: None,
                token_endpoint_auth_methods_supported: vec![],
                client_attestation_pop_signing_alg_values_supported: None,
                issuer_display: None,
                credential_request_encryption: None,
                credential_response_encryption: None,
                dpop_signing_alg_values_supported: None,
                dpop_nonce: None,
                protocol: "OPENID4VCI_FINAL1".to_string(),
                credential_configurations: vec![],
            }
        }
    }

    impl TestHolderInteractionData {
        /// Offer of an issuer at `issuer_url`, with a pre-authorized code grant
        pub(crate) fn mock_issuer(issuer_url: &str) -> Self {
            Self {
                issuer_url: issuer_url.to_string(),
                credential_endpoint: format!("{issuer_url}/credential"),
                token_endpoint: Some(format!("{issuer_url}/token")),
                nonce_endpoint: Some(format!("{issuer_url}/nonce")),
                grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
                    pre_authorized_code: "code".to_string(),
                    tx_code: None,
                    authorization_server: None,
                })),
                ..Default::default()
            }
        }
    }

    /// Flat test input of a [`HolderCredentialConfiguration`]
    #[derive(Clone, Default, Deserialize)]
    #[serde(default)]
    pub(crate) struct TestHolderCredentialConfiguration {
        pub credential_configuration_id: String,
        pub format: String,
        pub cryptographic_binding_methods_supported: Option<Vec<String>>,
        pub credential_signing_alg_values_supported: Option<Vec<SigningAlgValue>>,
        pub proof_types_supported: Option<IndexMap<String, ProofTypeSupported>>,
        pub credential_metadata: Option<CredentialMetadata>,
        pub disclosure_policy: Option<DisclosurePolicy>,
        pub notification_ids: Vec<String>,
        pub credential_id: Option<CredentialId>,
        pub credential_schema_format_id: Option<CredentialSchemaFormatId>,
    }

    impl From<TestHolderCredentialConfiguration> for HolderCredentialConfiguration {
        fn from(value: TestHolderCredentialConfiguration) -> Self {
            Self {
                metadata: CredentialConfiguration {
                    format: value.format,
                    cryptographic_binding_methods_supported: value
                        .cryptographic_binding_methods_supported,
                    credential_signing_alg_values_supported: value
                        .credential_signing_alg_values_supported,
                    proof_types_supported: value.proof_types_supported,
                    credential_metadata: value.credential_metadata,
                    disclosure_policy: value.disclosure_policy,
                    ..Default::default()
                },
                state: HolderCredentialConfigurationState {
                    credential_configuration_id: value.credential_configuration_id,
                    notification_ids: value.notification_ids,
                    credential_id: value.credential_id,
                    credential_schema_format_id: value.credential_schema_format_id,
                },
            }
        }
    }

    impl From<TestHolderInteractionData> for HolderInteractionData {
        fn from(value: TestHolderInteractionData) -> Self {
            let parse_url = |url: String| url.parse().expect("valid test URL");
            let (credential_configurations_supported, credential_configurations) = value
                .credential_configurations
                .into_iter()
                .map(|configuration| {
                    let HolderCredentialConfiguration { metadata, state } = configuration.into();
                    ((state.credential_configuration_id.clone(), metadata), state)
                })
                .unzip();
            let authorization_server = value
                .grants
                .as_ref()
                .and_then(Grants::authorization_server)
                .cloned();
            let (grant, client_id) = match value.grants {
                Some(Grants::PreAuthorizedCode(grant)) => (
                    Some(TokenGrant::PreAuthorizedCode {
                        pre_authorized_code: grant.pre_authorized_code,
                    }),
                    None,
                ),
                Some(Grants::AuthorizationCode(_)) => match value.continue_issuance {
                    Some(continue_issuance) => (
                        Some(TokenGrant::AuthorizationCode {
                            authorization_code: continue_issuance.authorization_code,
                            redirect_uri: continue_issuance.redirect_uri,
                            code_verifier: continue_issuance.code_verifier,
                        }),
                        Some(continue_issuance.client_id),
                    ),
                    None => (None, None),
                },
                None => (None, None),
            };

            Self {
                protocol: value.protocol,
                issuer_metadata: CredentialIssuerMetadata {
                    credential_issuer: value.issuer_url.clone(),
                    authorization_servers: authorization_server.map(|server| vec![server]),
                    credential_endpoint: value.credential_endpoint,
                    nonce_endpoint: value.nonce_endpoint,
                    notification_endpoint: value.notification_endpoint,
                    credential_configurations_supported,
                    display: value.issuer_display,
                    issuer_info: vec![],
                    batch_credential_issuance: value
                        .batch_size
                        .map(|batch_size| BatchCredentialIssuance { batch_size }),
                    credential_request_encryption: value.credential_request_encryption,
                    credential_response_encryption: value.credential_response_encryption,
                    preferred_client_status_period: None,
                    profile_version: None,
                },
                authorization_server_metadata: AuthorizationServerMetadata {
                    token_endpoint: value.token_endpoint.map(parse_url),
                    challenge_endpoint: value.challenge_endpoint.map(parse_url),
                    token_endpoint_auth_methods_supported: value
                        .token_endpoint_auth_methods_supported,
                    client_attestation_pop_signing_alg_values_supported: value
                        .client_attestation_pop_signing_alg_values_supported,
                    dpop_signing_alg_values_supported: value.dpop_signing_alg_values_supported,
                    ..authorization_server_metadata(&value.issuer_url)
                },
                metadata_source: MetadataSource::Fetched,
                state: HolderIssuanceState {
                    grant,
                    client_id,
                    tokens: TokenState {
                        access_token: value.access_token,
                        access_token_expires_at: value.access_token_expires_at,
                        refresh_token: value.refresh_token,
                        refresh_token_expires_at: value.refresh_token_expires_at,
                    },
                    dpop: DpopState {
                        nonce: value.dpop_nonce,
                        disabled: false,
                    },
                    credential_configurations,
                },
            }
        }
    }

    fn authorization_server_metadata(issuer: &str) -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: issuer.to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            pushed_authorization_request_endpoint: None,
            jwks_uri: None,
            code_challenge_methods_supported: vec![],
            scopes_supported: vec![],
            response_types_supported: vec![],
            grant_types_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
            challenge_endpoint: None,
            client_attestation_signing_alg_values_supported: None,
            client_attestation_pop_signing_alg_values_supported: None,
            client_attestation_pop_methods_supported: None,
            dpop_signing_alg_values_supported: None,
            signed_metadata: None,
        }
    }
}
