use dcql::DcqlQuery;
use futures::FutureExt;
use mockall::predicate::eq;
use serde_json::json;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::mapper::RemoteIdentifierRelation;
use crate::config::core_config::{Fields, KeyAlgorithmType, TransportType};
use crate::model::did::{Did, DidType};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::credential_formatter::model::{MockSignatureProvider, MockTokenVerifier};
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::proto::mqtt_client::{MockMqttClient, MockMqttTopic, MqttClient};
use crate::provider::verification_protocol::openid4vp::final1_0::model::AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::async_verifier_flow::request_as_signed_jwt;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::mappers::parse_identity_request;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::IdentityRequest;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::holder_flow::{
    handle_invitation_with_transport, ProximityHolderTransport,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::mqtt::model::{
    MQTTOpenID4VPInteractionDataHolder, MQTTSessionKeys,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::mqtt::oidc_mqtt_verifier::MqttVerifier;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::mqtt::{
    generate_session_keys, ConfigParams, MqttHolderTransport,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::peer_encryption::PeerEncryption;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::KeyAgreementKey;
use crate::service::storage_proxy::MockStorageProxy;
use crate::service::test_utilities::{dummy_organisation, generic_config};

#[derive(Default)]
struct TestInputs<'a> {
    pub broker_url: Option<&'a str>,
    pub mqtt_client: MockMqttClient,
}

fn setup_protocol(inputs: TestInputs) -> MqttVerifier {
    let mut config = generic_config().core;
    config.transport.insert(
        "MQTT".into(),
        Fields {
            r#type: TransportType::Mqtt,
            display: "".into(),
            order: None,
            enabled: Some(true),
            capabilities: None,
            params: None,
        },
    );

    MqttVerifier::new(
        Arc::new(inputs.mqtt_client),
        ConfigParams {
            broker_url: inputs
                .broker_url
                .unwrap_or("mqtt://127.0.0.1:2137")
                .to_string()
                .parse()
                .unwrap(),
        },
    )
}

fn setup_holder_transport(
    custom_scheme: Option<String>,
    mqtt_client: Option<Arc<dyn MqttClient>>,
) -> MqttHolderTransport {
    MqttHolderTransport {
        url_scheme: custom_scheme.unwrap_or("openid4vp".to_string()),
        mqtt_client: mqtt_client.unwrap_or(Arc::new(MockMqttClient::default())),
    }
}

#[test]
fn test_can_handle() {
    let transport = setup_holder_transport(None, None);

    let wrong_protocol_url = "http://127.0.0.1".parse().unwrap();
    assert!(!transport.can_handle(&wrong_protocol_url));

    let missing_parameters = "openid4vp://proof".parse().unwrap();
    assert!(!transport.can_handle(&missing_parameters));

    let valid = "openid4vp://proof?brokerUrl=mqtt%3A%2F%2Fsomewhere.com%3A1234&key=abcdef&topicId=F25591B1-DB46-4606-8068-ADF986C3A2BD"
        .parse()
        .unwrap();
    assert!(transport.can_handle(&valid));
}

#[test]
fn test_can_handle_custom_scheme() {
    let url_scheme = "test-scheme";
    let protocol = setup_holder_transport(Some(url_scheme.to_string()), None);

    let url = format!("{url_scheme}://proof?brokerUrl=mqtt%3A%2F%2Fsomewhere.com%3A1234&key=abcdef&topicId=F25591B1-DB46-4606-8068-ADF986C3A2BD")
        .parse()
        .unwrap();
    assert!(protocol.can_handle(&url));
}

#[test]
fn test_encryption_verifier_to_holder() {
    let (verifier_key, _verifier_public_key) = generate_verifier_key();

    let holder_session_keys = generate_session_keys(verifier_key.public_key_bytes()).unwrap();
    let holder_encryption = PeerEncryption::new(
        holder_session_keys.sender_key,
        holder_session_keys.receiver_key,
        holder_session_keys.nonce,
    );

    let verifier_encryption = generate_verifier_encryption(
        verifier_key,
        IdentityRequest {
            key: holder_session_keys.public_key,
            nonce: holder_session_keys.nonce,
        },
    );

    let message = json!({ "message": "hello world" });
    let encrypted = verifier_encryption.encrypt(&message).unwrap();

    let decrypted: serde_json::Value = holder_encryption.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, message);
}

#[tokio::test]
async fn test_handle_invitation_success() {
    let verifier_did =
        DidValue::from_str("did:key:z6Mkw7WbDmMJ5X8w1V7D4eFFJoVqMdkaGZQuFkp5ZZ4r1W3y").unwrap();
    let mut mock_storage_access = MockStorageProxy::default();
    mock_storage_access
        .expect_get_or_create_identifier()
        .once()
        .returning(|_, did, _| {
            Ok((
                Identifier {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "verifier".to_string(),
                    organisation: None,
                    did: None,
                    key: None,
                    certificates: None,
                    r#type: IdentifierType::Did,
                    is_remote: true,
                    state: IdentifierState::Active,
                    deleted_at: None,
                },
                RemoteIdentifierRelation::Did(Did {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "did".to_string(),
                    did: did.did_value().unwrap().to_owned(),
                    did_type: DidType::Remote,
                    did_method: "KEY".to_string(),
                    deactivated: false,
                    keys: None,
                    organisation: None,
                    log: None,
                }),
            ))
        });
    let interaction_id = Uuid::new_v4();
    mock_storage_access
        .expect_create_interaction()
        .once()
        .returning(move |_| Ok(interaction_id));
    mock_storage_access
        .expect_update_interaction()
        .once()
        .returning(|_, _| Ok(()));

    let mut auth_fn = MockSignatureProvider::new();
    auth_fn
        .expect_get_key_id()
        .return_const(Some("did-vm-id".to_string()));
    auth_fn.expect_jose_alg().return_const("ES256".to_string());
    auth_fn.expect_sign().returning(move |_| Ok(vec![1, 2, 3]));

    let mut did_method_provider: MockDidMethodProvider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .withf({
            let verifier_did = verifier_did.clone();
            move |did| did == &verifier_did
        })
        .returning(|did| {
            Ok(DidDocument {
                context: Default::default(),
                id: did.clone(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: did.to_string(),
                    public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "P-256".to_string(),
                        x: "x".to_string(),
                        y: None,
                    }),
                }],
                authentication: None,
                assertion_method: Some(vec!["did-vm-id".to_string()]),
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

    let (verifier_key, verifier_public_key) = generate_verifier_key();
    let holder_identity_request = Arc::new(Mutex::new(None));
    let handle = holder_identity_request.clone();
    let request = AuthorizationRequest {
        client_id: format!("decentralized_identifier:{verifier_did}"),
        nonce: Some("nonce".to_string()),
        dcql_query: Some(DcqlQuery {
            credentials: vec![],
            credential_sets: None,
        }),
        response_type: None,
        response_mode: None,
        client_metadata: None,
        response_uri: None,
        state: None,
        redirect_uri: None,
    };
    let signed = request_as_signed_jwt(request, &verifier_did, Box::new(auth_fn))
        .await
        .unwrap();
    let mut identify_topic = MockMqttTopic::default();
    identify_topic
        .expect_send()
        .return_once(move |identity_request| {
            let request = parse_identity_request(identity_request).unwrap();

            let mut lock = handle.lock().unwrap();
            *lock = Some(request);

            Ok(())
        });

    let handle = holder_identity_request.clone();
    let mut presentation_definition_topic = MockMqttTopic::default();
    presentation_definition_topic
        .expect_recv()
        .return_once(move || {
            let lock = handle.lock().unwrap();

            let holder_identity_request = lock.clone().unwrap();

            let encryption = generate_verifier_encryption(verifier_key, holder_identity_request);

            Ok(encryption.encrypt(&signed).unwrap())
        });

    let mut mqtt_client = MockMqttClient::default();

    mqtt_client
        .expect_subscribe()
        .withf(|_, _, url| url.ends_with("/identify"))
        .return_once(move |_, _, _| Ok(Box::new(identify_topic)));
    mqtt_client
        .expect_subscribe()
        .withf(|_, _, url| url.ends_with("/presentation-definition"))
        .return_once(move |_, _, _| Ok(Box::new(presentation_definition_topic)));

    let valid =
        format!("openid4vp://proof?brokerUrl=mqtt%3A%2F%2Fsomewhere.com%3A1234&key={verifier_public_key}&topicId={}", Uuid::new_v4())
            .parse()
            .unwrap();

    let mut verifier = MockTokenVerifier::new();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("ES256"))
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Ecdsa);

            Some((KeyAlgorithmType::Ecdsa, Arc::new(key_algorithm)))
        });
    verifier
        .expect_key_algorithm_provider()
        .once()
        .return_const(Box::new(key_algorithm_provider));
    verifier.expect_verify().once().return_const(Ok(()));
    let response = handle_invitation_with_transport(
        valid,
        dummy_organisation(None),
        &mock_storage_access,
        &setup_holder_transport(None, Some(Arc::new(mqtt_client))),
        Box::new(verifier),
    )
    .await
    .expect("handle invitation failed");

    assert_eq!(response.interaction_id, interaction_id);
}

#[tokio::test]
async fn test_presentation_reject_success() {
    let (verifier_key, _verifier_public_key) = generate_verifier_key();

    let holder_session_keys = generate_session_keys(verifier_key.public_key_bytes()).unwrap();

    let mut reject_topic = MockMqttTopic::default();
    reject_topic.expect_send().return_once(move |data| {
        let verifier_encryption = generate_verifier_encryption(
            verifier_key,
            IdentityRequest {
                key: holder_session_keys.public_key,
                nonce: holder_session_keys.nonce,
            },
        );

        let timestamp: i64 = verifier_encryption.decrypt(&data).unwrap();
        let now = OffsetDateTime::now_utc();
        let timestamp_date = OffsetDateTime::from_unix_timestamp(timestamp).unwrap();
        let diff = now - timestamp_date;
        assert!(diff < Duration::minutes(5));

        Ok(())
    });

    let mut mqtt_client = MockMqttClient::default();

    let topic_id = Uuid::new_v4();
    let expected_url = format!("/proof/{topic_id}/presentation-submission/reject");
    let broker_url = "test_url".to_string();
    let broker_port = 1234;

    mqtt_client
        .expect_subscribe()
        .with(eq(broker_url.clone()), eq(broker_port), eq(expected_url))
        .return_once(move |_, _, _| Ok(Box::new(reject_topic)));

    let interaction_data = MQTTOpenID4VPInteractionDataHolder {
        broker_url,
        broker_port,
        client_id: "client_id".to_string(),
        nonce: "nonce".to_string(),
        session_keys: MQTTSessionKeys {
            public_key: [0; 32],
            receiver_key: holder_session_keys.receiver_key,
            sender_key: holder_session_keys.sender_key,
            nonce: holder_session_keys.nonce,
        },
        dcql_query: None,
        identity_request_nonce: "identity_request_nonce".to_string(),
        topic_id,
    };

    let transport = setup_holder_transport(None, Some(Arc::new(mqtt_client)));
    transport
        .reject_proof(serde_json::to_value(&interaction_data).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_share_proof_for_mqtt_returns_url() {
    let broker_url = "tcp://share-proof-test:1234";
    let mut mqtt_client = MockMqttClient::default();
    mqtt_client
        .expect_subscribe()
        .times(4)
        .returning(move |_, _, _| {
            // this is called in a spawned task so we don't care whether it fails for this test
            let mut topic = MockMqttTopic::default();
            topic.expect_recv().returning(|| Ok(vec![]));

            Ok(Box::new(topic))
        });

    let custom_url_scheme = "my-url-scheme";
    let protocol = setup_protocol(TestInputs {
        mqtt_client,
        broker_url: Some(broker_url),
    });

    let key_agreement = KeyAgreementKey::new_random();
    let interaction_id = Uuid::new_v4();

    let url = protocol
        .schedule_verifier_flow(
            &key_agreement,
            custom_url_scheme,
            interaction_id,
            Uuid::new_v4().into(),
            |_| async {}.boxed(),
        )
        .await
        .unwrap();

    let proof_id_query_value = url
        .query_pairs()
        .find_map(|(key, value)| (key == "topicId").then_some(value))
        .unwrap();
    let broker_url_query_value = url
        .query_pairs()
        .find_map(|(key, value)| (key == "brokerUrl").then_some(value))
        .unwrap();
    url.query_pairs()
        .find_map(|(key, value)| (key == "key").then_some(value))
        .unwrap();

    assert_eq!(proof_id_query_value, interaction_id.to_string());
    assert_eq!(custom_url_scheme, url.scheme());
    assert_eq!(broker_url, broker_url_query_value);
}

fn generate_verifier_key() -> (KeyAgreementKey, String) {
    let key_agreement_key = KeyAgreementKey::new_random();
    let public_key = key_agreement_key.public_key_bytes();

    (key_agreement_key, hex::encode(public_key))
}

fn generate_verifier_encryption(
    key: KeyAgreementKey,
    holder_identity_request: IdentityRequest,
) -> PeerEncryption {
    let (sender_key, receiver_key) = key
        .derive_session_secrets(holder_identity_request.key, holder_identity_request.nonce)
        .unwrap();

    PeerEncryption::new(sender_key, receiver_key, holder_identity_request.nonce)
}
