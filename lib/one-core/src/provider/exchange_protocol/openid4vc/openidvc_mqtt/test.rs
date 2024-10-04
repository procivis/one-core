use std::sync::{Arc, Mutex};

use serde_json::json;
use uuid::Uuid;

use crate::provider::exchange_protocol::openid4vc::key_agreement_key::KeyAgreementKey;
use crate::provider::exchange_protocol::openid4vc::mapper::parse_identity_request;
use crate::provider::exchange_protocol::openid4vc::model::{
    InvitationResponseDTO, OpenID4VPPresentationDefinition,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::IdentityRequest;
use crate::provider::exchange_protocol::openid4vc::openidvc_mqtt::{
    generate_session_keys, ConfigParams, OpenId4VcMqtt,
};
use crate::provider::exchange_protocol::openid4vc::peer_encryption::PeerEncryption;
use crate::provider::exchange_protocol::{
    ExchangeProtocolImpl, MockHandleInvitationOperations, MockStorageProxy,
};
use crate::provider::mqtt_client::{MockMqttClient, MockMqttTopic};
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::service::test_utilities::{dummy_organisation, dummy_proof, generic_config};

#[derive(Default)]
struct TestInputs<'a> {
    pub broker_addr: Option<&'a str>,
    pub broker_url: Option<&'a str>,
    pub broker_port: Option<u16>,
    pub mqtt_client: MockMqttClient,
    pub interaction_repository: MockInteractionRepository,
    pub proof_repository: MockProofRepository,
}

fn setup_protocol(inputs: TestInputs) -> OpenId4VcMqtt {
    OpenId4VcMqtt::new(
        Arc::new(inputs.mqtt_client),
        Arc::new(generic_config().core),
        ConfigParams {
            broker_url: inputs
                .broker_url
                .unwrap_or("mqtt://127.0.0.1:2137")
                .to_string()
                .parse()
                .unwrap(),
            broker_addr: inputs.broker_addr.unwrap_or("mqtt://127.0.0.1").to_string(),
            broker_port: inputs.broker_port.unwrap_or(2137),
        },
        Arc::new(inputs.interaction_repository),
        Arc::new(inputs.proof_repository),
    )
}

#[test]
fn test_can_handle() {
    let protocol = setup_protocol(TestInputs::default());

    let wrong_protocol_url = "http://127.0.0.1".parse().unwrap();
    assert!(!protocol.can_handle(&wrong_protocol_url));

    let missing_parameters = "openid4vp://proof".parse().unwrap();
    assert!(!protocol.can_handle(&missing_parameters));

    let valid = "openid4vp://proof?brokerUrl=mqtt://somewhere.com:1234&key=abcdef"
        .parse()
        .unwrap();
    assert!(protocol.can_handle(&valid));
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
    let encrypted = verifier_encryption.encrypt(message.clone()).unwrap();

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
    interaction_repository
        .expect_update_interaction()
        .times(2)
        .returning(|_| Ok(()));

    let proof_id = Uuid::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_create_proof()
        .once()
        .returning(move |_| Ok(proof_id.to_owned().into()));
    proof_repository
        .expect_update_proof()
        .once()
        .returning(|_| Ok(()));
    proof_repository
        .expect_get_proof()
        .once()
        .returning(|_, _| Ok(Some(dummy_proof())));

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

            let presentation = OpenID4VPPresentationDefinition {
                id: Default::default(),
                input_descriptors: vec![],
            };

            Ok(encryption.encrypt(presentation).unwrap())
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

    let storage_proxy = Arc::new(MockStorageProxy::default());
    let handle_invitation_operations_proxy = Arc::new(MockHandleInvitationOperations::default());

    let valid =
        format!("openid4vp://proof?brokerUrl=mqtt://somewhere.com:1234&key={verifier_public_key}")
            .parse()
            .unwrap();

    let protocol = setup_protocol(TestInputs {
        mqtt_client,
        interaction_repository,
        proof_repository,
        ..Default::default()
    });
    let result = protocol
        .handle_invitation(
            valid,
            dummy_organisation(),
            &*storage_proxy,
            &*handle_invitation_operations_proxy,
            vec![],
        )
        .await
        .unwrap();
    assert!(matches!(result, InvitationResponseDTO::ProofRequest { .. }));
}
