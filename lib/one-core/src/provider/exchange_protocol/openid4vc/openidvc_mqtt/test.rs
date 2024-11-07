use std::sync::{Arc, Mutex};

use mockall::predicate::eq;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::core_config::{Fields, TransportType};
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::exchange_protocol::openid4vc::key_agreement_key::KeyAgreementKey;
use crate::provider::exchange_protocol::openid4vc::mapper::{
    create_format_map, parse_identity_request,
};
use crate::provider::exchange_protocol::openid4vc::model::{
    InvitationResponseDTO, MQTTOpenID4VPInteractionData, MQTTSessionKeys, MqttOpenId4VpRequest,
    OpenID4VPPresentationDefinition,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::IdentityRequest;
use crate::provider::exchange_protocol::openid4vc::openidvc_mqtt::{
    generate_session_keys, ConfigParams, OpenId4VcMqtt,
};
use crate::provider::exchange_protocol::openid4vc::peer_encryption::PeerEncryption;
use crate::provider::exchange_protocol::{FormatMapper, TypeToDescriptorMapper};
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::mqtt_client::{MockMqttClient, MockMqttTopic};
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::service::test_utilities::generic_config;

#[derive(Default)]
struct TestInputs<'a> {
    pub broker_url: Option<&'a str>,
    pub mqtt_client: MockMqttClient,
    pub interaction_repository: MockInteractionRepository,
    pub proof_repository: MockProofRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub key_provider: MockKeyProvider,
}

fn setup_protocol(inputs: TestInputs) -> OpenId4VcMqtt {
    let mut config = generic_config().core;
    config.transport.insert(
        "MQTT".into(),
        Fields {
            r#type: TransportType::Mqtt,
            display: "".into(),
            order: None,
            disabled: Some(false),
            capabilities: None,
            params: None,
        },
    );

    OpenId4VcMqtt::new(
        Arc::new(inputs.mqtt_client),
        Arc::new(config),
        ConfigParams {
            broker_url: inputs
                .broker_url
                .unwrap_or("mqtt://127.0.0.1:2137")
                .to_string()
                .parse()
                .unwrap(),
        },
        Arc::new(inputs.interaction_repository),
        Arc::new(inputs.proof_repository),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.key_provider),
    )
}

#[test]
fn test_can_handle() {
    let protocol = setup_protocol(TestInputs::default());

    let wrong_protocol_url = "http://127.0.0.1".parse().unwrap();
    assert!(!protocol.can_handle(&wrong_protocol_url));

    let missing_parameters = "openid4vp://proof".parse().unwrap();
    assert!(!protocol.can_handle(&missing_parameters));

    let valid = "openid4vp://proof?brokerUrl=mqtt%3A%2F%2Fsomewhere.com%3A1234&key=abcdef&topicId=F25591B1-DB46-4606-8068-ADF986C3A2BD"
        .parse()
        .unwrap();
    assert!(protocol.can_handle(&valid));
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
    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_create_interaction()
        .once()
        .returning(|_| Ok(Uuid::new_v4()));

    let (verifier_key, verifier_public_key) = generate_verifier_key();
    let holder_identity_request = Arc::new(Mutex::new(None));

    let handle = holder_identity_request.clone();
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

            let presentation_definition = OpenID4VPPresentationDefinition {
                id: Default::default(),
                input_descriptors: vec![],
            };

            Ok(encryption
                .encrypt(&MqttOpenId4VpRequest {
                    client_id: "client-id".to_string(),
                    nonce: "nonce".to_string(),
                    presentation_definition,
                })
                .unwrap())
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

    let protocol = setup_protocol(TestInputs {
        mqtt_client,
        interaction_repository,
        ..Default::default()
    });
    let result = protocol
        .handle_invitation(valid, dummy_organization())
        .await
        .unwrap();
    assert!(matches!(result, InvitationResponseDTO::ProofRequest { .. }));
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

    let interaction_data = MQTTOpenID4VPInteractionData {
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
        presentation_definition: None,
        identity_request_nonce: "identity_request_nonce".to_string(),
        topic_id,
    };

    let now = OffsetDateTime::now_utc();
    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        issuance_date: now,
        exchange: "OPENID4VC".to_string(),
        transport: "MQTT".to_string(),
        redirect_uri: None,
        state: None,
        schema: None,
        claims: None,
        verifier_did: None,
        holder_did: None,
        verifier_key: None,
        interaction: Some(Interaction {
            id: Default::default(),
            created_date: now,
            last_modified: now,
            host: None,
            data: Some(serde_json::to_vec(&interaction_data).unwrap()),
            organisation: None,
        }),
    };

    let protocol = setup_protocol(TestInputs {
        mqtt_client,
        ..Default::default()
    });
    protocol.reject_proof(&proof).await.unwrap();
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

    let protocol = setup_protocol(TestInputs {
        mqtt_client,
        broker_url: Some(broker_url),
        ..Default::default()
    });

    let proof_id = Uuid::new_v4();
    let proof = Proof {
        id: proof_id.into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "OPENID4VC".to_string(),
        transport: "MQTT".to_string(),
        redirect_uri: None,
        state: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "test-mqtt-share-proof".into(),
            expire_duration: 123,
            imported_source_url: None,
            organisation: None,
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: None,
                credential_schema: None,
            }]),
        }),
        claims: None,
        verifier_did: None,
        holder_did: None,
        verifier_key: None,
        interaction: None,
    };

    let format_type_mapper: FormatMapper = Arc::new(move |input| Ok(input.to_owned()));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(create_format_map);

    let key_agreement = KeyAgreementKey::new_random();
    let interaction_id = Uuid::new_v4();

    let url = protocol
        .share_proof(
            &proof,
            format_type_mapper,
            type_to_descriptor_mapper,
            interaction_id,
            key_agreement,
            CancellationToken::new(),
            None,
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

    assert_eq!("openid4vp", url.scheme());
    assert_eq!(interaction_id.to_string(), proof_id_query_value);
    assert_eq!(broker_url, broker_url_query_value);
}

fn dummy_organization() -> Organisation {
    Organisation {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    }
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
