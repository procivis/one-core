use std::str::FromStr;
use std::sync::{Arc, Mutex};

use mockall::predicate::eq;
use one_crypto::MockSigner;
use serde_json::json;
use shared_types::{DidValue, KeyId};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::core_config::{Fields, TransportType};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::interaction::Interaction;
use crate::model::key::{Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::provider::credential_formatter::model::MockSignatureProvider;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::exchange_protocol::openid4vc::key_agreement_key::KeyAgreementKey;
use crate::provider::exchange_protocol::openid4vc::mapper::create_format_map;
use crate::provider::exchange_protocol::openid4vc::model::{
    ClientIdSchemaType, InvitationResponseDTO, OpenID4VCIssuanceParams, OpenID4VCParams,
    OpenID4VCPresentationHolderParams, OpenID4VCPresentationParams,
    OpenID4VCPresentationVerifierParams, OpenID4VCRedirectUriParams,
    OpenID4VPAuthorizationRequestParams, OpenID4VPPresentationDefinition,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::mappers::parse_identity_request;
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::IdentityRequest;
use crate::provider::exchange_protocol::openid4vc::openidvc_mqtt::model::{
    MQTTOpenID4VPInteractionDataHolder, MQTTSessionKeys,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_mqtt::{
    generate_session_keys, ConfigParams, OpenId4VcMqtt,
};
use crate::provider::exchange_protocol::openid4vc::peer_encryption::PeerEncryption;
use crate::provider::exchange_protocol::{FormatMapper, TypeToDescriptorMapper};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::mqtt_client::{MockMqttClient, MockMqttTopic};
use crate::repository::did_repository::MockDidRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::service::test_utilities::generic_config;

#[derive(Default)]
struct TestInputs<'a> {
    pub broker_url: Option<&'a str>,
    pub mqtt_client: MockMqttClient,
    pub interaction_repository: MockInteractionRepository,
    pub proof_repository: MockProofRepository,
    pub did_repository: MockDidRepository,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub key_provider: MockKeyProvider,
    pub issuance_url_scheme: Option<&'a str>,
    pub presentation_url_scheme: Option<&'a str>,
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
        OpenID4VCParams {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: false,
            client_metadata_by_value: false,
            presentation_definition_by_value: false,
            allow_insecure_http_transport: true,
            refresh_expires_in: 1000,
            use_request_uri: false,
            issuance: OpenID4VCIssuanceParams {
                disabled: false,
                url_scheme: inputs
                    .issuance_url_scheme
                    .unwrap_or("openid-credential-offer")
                    .to_string(),
                redirect_uri: OpenID4VCRedirectUriParams {
                    disabled: false,
                    allowed_schemes: vec!["https".to_string()],
                },
            },
            presentation: generic_presentation_params(inputs.presentation_url_scheme),
        },
        Arc::new(inputs.interaction_repository),
        Arc::new(inputs.proof_repository),
        Arc::new(inputs.did_repository),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_provider),
    )
}
fn generic_presentation_params(url_scheme: Option<&str>) -> OpenID4VCPresentationParams {
    OpenID4VCPresentationParams {
        disabled: false,
        url_scheme: url_scheme.unwrap_or("openid4vp").to_string(),
        x509_ca_certificate: None,
        holder: OpenID4VCPresentationHolderParams {
            supported_client_id_schemes: vec![
                ClientIdSchemaType::RedirectUri,
                ClientIdSchemaType::VerifierAttestation,
            ],
        },
        verifier: OpenID4VCPresentationVerifierParams {
            default_client_id_schema: ClientIdSchemaType::RedirectUri,
            supported_client_id_schemes: vec![
                ClientIdSchemaType::RedirectUri,
                ClientIdSchemaType::VerifierAttestation,
            ],
        },
        redirect_uri: OpenID4VCRedirectUriParams {
            disabled: false,
            allowed_schemes: vec!["https".to_string()],
        },
    }
}

#[test]
fn test_can_handle() {
    let protocol = setup_protocol(TestInputs::default());

    let wrong_protocol_url = "http://127.0.0.1".parse().unwrap();
    assert!(!protocol.holder_can_handle(&wrong_protocol_url));

    let missing_parameters = "openid4vp://proof".parse().unwrap();
    assert!(!protocol.holder_can_handle(&missing_parameters));

    let valid = "openid4vp://proof?brokerUrl=mqtt%3A%2F%2Fsomewhere.com%3A1234&key=abcdef&topicId=F25591B1-DB46-4606-8068-ADF986C3A2BD"
        .parse()
        .unwrap();
    assert!(protocol.holder_can_handle(&valid));
}

#[test]
fn test_can_handle_custom_scheme() {
    let url_scheme = "test-scheme";
    let protocol = setup_protocol(TestInputs {
        presentation_url_scheme: Some(url_scheme),
        ..Default::default()
    });

    let url = format!("{url_scheme}://proof?brokerUrl=mqtt%3A%2F%2Fsomewhere.com%3A1234&key=abcdef&topicId=F25591B1-DB46-4606-8068-ADF986C3A2BD")
        .parse()
        .unwrap();
    assert!(protocol.holder_can_handle(&url));
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
    let client_id =
        DidValue::from_str("did:key:z6Mkw7WbDmMJ5X8w1V7D4eFFJoVqMdkaGZQuFkp5ZZ4r1W3y").unwrap();

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_create_interaction()
        .once()
        .returning(|_| Ok(Uuid::new_v4()));

    let mut did_repository = MockDidRepository::default();

    did_repository
        .expect_get_did_by_value()
        .withf({
            let client_id = client_id.clone();
            move |did, _| did == &client_id
        })
        .once()
        .returning(|did, _| {
            Ok(Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: did.clone(),
                did_type: DidType::Remote,
                did_method: "KEY".to_string(),
                deactivated: false,
                keys: None,
                organisation: None,
            }))
        });

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
            let verifier_did = client_id.clone();
            move |did, _| did == &verifier_did
        })
        .returning(|did, _| {
            Ok(DidDocument {
                context: Default::default(),
                id: did.clone(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: did.to_string(),
                    public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
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
                rest: Default::default(),
            })
        });

    let mut mock_key_algorithm = MockKeyAlgorithm::default();
    mock_key_algorithm
        .expect_jwk_to_bytes()
        .returning(|_| Ok(vec![]));
    let mock_key_algorithm = Arc::new(mock_key_algorithm);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let mock_key_algorithm_clone = mock_key_algorithm.clone();
    mock_key_algorithm_provider
        .expect_get_key_algorithm_from_jose_alg()
        .returning(move |_| Some((mock_key_algorithm_clone.clone(), "ES256".to_string())));
    mock_key_algorithm_provider
        .expect_get_key_algorithm()
        .returning(move |_| Some(mock_key_algorithm.clone()));

    let mut mock_signer = MockSigner::default();
    mock_signer.expect_verify().returning(|_, _, _| Ok(()));
    let mock_signer = Arc::new(mock_signer);

    mock_key_algorithm_provider
        .expect_get_signer()
        .returning(move |_| Ok(mock_signer.clone()));

    let (verifier_key, verifier_public_key) = generate_verifier_key();
    let holder_identity_request = Arc::new(Mutex::new(None));
    let handle = holder_identity_request.clone();
    let request = OpenID4VPAuthorizationRequestParams {
        client_id: client_id.to_string(),
        nonce: Some("nonce".to_string()),
        presentation_definition: Some(OpenID4VPPresentationDefinition {
            id: Default::default(),
            input_descriptors: vec![],
        }),
        response_type: None,
        response_mode: None,
        client_id_scheme: Some(ClientIdSchemaType::Did),
        client_metadata: None,
        response_uri: None,
        state: None,
        client_metadata_uri: None,
        presentation_definition_uri: None,
        redirect_uri: None,
    };
    let signed = request
        .as_signed_jwt(&client_id, Box::new(auth_fn))
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

    let protocol = setup_protocol(TestInputs {
        mqtt_client,
        interaction_repository,
        did_method_provider,
        did_repository,
        key_algorithm_provider: mock_key_algorithm_provider,
        ..Default::default()
    });
    let result = protocol
        .holder_handle_invitation(valid, dummy_organization())
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
        state: ProofStateEnum::Pending,
        requested_date: Some(now),
        completed_date: None,
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
    protocol.holder_reject_proof(&proof).await.unwrap();
}

#[tokio::test]
async fn test_share_proof_for_mqtt_returns_url() {
    let broker_url = "tcp://share-proof-test:1234";
    let mut mqtt_client = MockMqttClient::default();
    let mut did_provider = MockDidMethodProvider::default();
    let mut key_provider = MockKeyProvider::default();

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| Ok(Box::new(MockSignatureProvider::default())));

    let key_id: KeyId = Uuid::new_v4().into();
    let did_value: DidValue = "did:key:z6Mkw7WbDmMJ5X8w1V7D4eFFJoVqMdkaGZQuFkp5ZZ4r1W3y"
        .parse()
        .unwrap();

    did_provider
        .expect_get_verification_method_id_from_did_and_key()
        .withf({
            let expected_did_value = did_value.clone();
            let expected_key_id = key_id;
            move |did, key| did.did == expected_did_value && key.id == expected_key_id
        })
        .returning(move |_, _| Ok(key_id.clone().to_string()));

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
        did_method_provider: did_provider,
        key_provider,
        presentation_url_scheme: Some(custom_url_scheme),
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
        state: ProofStateEnum::Pending,
        requested_date: Some(OffsetDateTime::now_utc()),
        completed_date: None,
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
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: did_value,
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: Key {
                    id: key_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    public_key: vec![],
                    name: "key".to_string(),
                    key_reference: vec![],
                    storage_type: "INTERNAL".to_string(),
                    key_type: "EDDSA".to_string(),
                    organisation: None,
                },
            }]),
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
    };

    let format_type_mapper: FormatMapper = Arc::new(move |input| Ok(input.to_owned()));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(create_format_map);

    let key_agreement = KeyAgreementKey::new_random();
    let interaction_id = Uuid::new_v4();

    let url = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            key_id,
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

    assert_eq!(custom_url_scheme, url.scheme());
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
