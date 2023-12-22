use std::collections::HashMap;
use std::{str::FromStr, sync::Arc};

use mockall::{predicate, Sequence};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    crypto::MockCryptoProvider,
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::{Credential, CredentialState, CredentialStateEnum},
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::{Did, DidType},
        interaction::Interaction,
        organisation::Organisation,
        proof::{Proof, ProofState, ProofStateEnum},
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    provider::{
        credential_formatter::provider::MockCredentialFormatterProvider,
        key_storage::provider::MockKeyProvider,
        revocation::provider::MockRevocationMethodProvider,
        transport_protocol::{
            openid4vc::dto::{
                OpenID4VPClientMetadata, OpenID4VPFormat, OpenID4VPInteractionData,
                OpenID4VPPresentationDefinition,
            },
            TransportProtocol, TransportProtocolError,
        },
    },
    repository::{
        credential_repository::MockCredentialRepository,
        credential_schema_repository::MockCredentialSchemaRepository,
        did_repository::MockDidRepository, interaction_repository::MockInteractionRepository,
        mock::proof_repository::MockProofRepository,
    },
    service::ssi_holder::dto::InvitationResponseDTO,
};

use super::{OpenID4VC, OpenID4VCParams};

#[derive(Default)]
struct Repositories {
    pub credential_repository: MockCredentialRepository,
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub did_repository: MockDidRepository,
    pub proof_repository: MockProofRepository,
    pub interaction_repository: MockInteractionRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_provider: MockRevocationMethodProvider,
    pub key_provider: MockKeyProvider,
    pub crypto: MockCryptoProvider,
}

fn setup_protocol(repositories: Repositories) -> OpenID4VC {
    OpenID4VC::new(
        Some("http://base_url".to_string()),
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.credential_schema_repository),
        Arc::new(repositories.did_repository),
        Arc::new(repositories.proof_repository),
        Arc::new(repositories.interaction_repository),
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.revocation_provider),
        Arc::new(repositories.key_provider),
        Arc::new(repositories.crypto),
        OpenID4VCParams {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
        },
    )
}

fn construct_proof_with_state() -> Proof {
    Proof {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "OPENID4VC".to_string(),
        redirect_uri: None,
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Pending,
        }]),
        schema: Some(ProofSchema {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "schema".to_string(),
            expire_duration: 10,
            claim_schemas: Some(vec![ProofSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4(),
                    key: "first_name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                },
                required: true,
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4(),
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "credential schema".to_string(),
                    format: "JWT".to_string(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: None,
                    organisation: None,
                }),
            }]),
            organisation: None,
        }),
        claims: None,
        verifier_did: None,
        holder_did: None,
        interaction: None,
    }
}

fn generic_credential() -> Credential {
    let now = OffsetDateTime::now_utc();

    let claim_schema = ClaimSchema {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
    };
    let organisation = Organisation {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
        created_date: now,
        last_modified: now,
    };

    Credential {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        transport: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: None,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
        }]),
        claims: Some(vec![Claim {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: now,
            last_modified: now,
            value: "123".to_string(),
            schema: Some(claim_schema.clone()),
        }]),
        issuer_did: Some(Did {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            created_date: now,
            last_modified: now,
            name: "did1".to_string(),
            organisation: Some(organisation.clone()),
            did: "did1".parse().unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: claim_schema,
                required: true,
            }]),
            organisation: Some(organisation),
        }),
        interaction: Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: now,
            last_modified: now,
            host: Some("http://host.co".parse().unwrap()),
            data: Some(vec![1, 2, 3]),
        }),
        revocation_list: None,
        key: None,
    }
}

#[tokio::test]
async fn test_generate_offer() {
    let base_url = "BASE_URL".to_string();
    let interaction_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();
    let credential = generic_credential();

    let offer = super::mapper::create_credential_offer_encoded(
        Some(base_url),
        &interaction_id,
        &credential,
    )
    .unwrap();

    assert_eq!(
        offer,
        r#"credential_offer=%7B%22credential_issuer%22%3A%22BASE_URL%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22credential_definition%22%3A%7B%22type%22%3A%5B%22VerifiableCredential%22%5D%2C%22credentialSubject%22%3A%7B%22NUMBER%22%3A%7B%22value%22%3A%22123%22%2C%22value_type%22%3A%22NUMBER%22%7D%7D%7D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22c322aa7f-9803-410d-b891-939b279fb965%22%7D%7D%7D"#
    )
}

#[tokio::test]
async fn test_generate_share_credentials() {
    let credential = generic_credential();

    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let mut seq = Sequence::new();

    let credential_moved = credential.clone();
    credential_repository
        .expect_get_credential()
        .once()
        .in_sequence(&mut seq)
        .returning(move |_, _| Ok(Some(credential_moved.clone())));

    interaction_repository
        .expect_create_interaction()
        .once()
        .in_sequence(&mut seq)
        .returning(move |req| Ok(req.id));

    credential_repository
        .expect_update_credential()
        .once()
        .in_sequence(&mut seq)
        .withf(move |req| req.id == credential.id)
        .returning(|_| Ok(()));

    interaction_repository
        .expect_delete_interaction()
        .once()
        .in_sequence(&mut seq)
        .with(predicate::eq(credential.interaction.as_ref().unwrap().id))
        .returning(move |_| Ok(()));

    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_generate_alphanumeric()
        .once()
        .returning(|_| String::from("ABC123"));

    let protocol = setup_protocol(Repositories {
        credential_repository,
        interaction_repository,
        crypto,
        ..Default::default()
    });

    let result = protocol.share_credential(&credential).await.unwrap();

    // Everything except for interaction id is here.
    // Generating token with predictable interaction id it tested somewhere else.
    assert!(
        result.starts_with(r#"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22credential_definition%22%3A%7B%22type%22%3A%5B%22VerifiableCredential%22%5D%2C%22credentialSubject%22%3A%7B%22NUMBER%22%3A%7B%22value%22%3A%22123%22%2C%22value_type%22%3A%22NUMBER%22%7D%7D%7D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%"#)
    )
}

#[tokio::test]
async fn test_generate_share_proof_open_id_flow_success() {
    let proof = construct_proof_with_state();
    let interaction_id: Uuid = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();

    let mut proof_repository = MockProofRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let mut seq = Sequence::new();

    let proof_moved = proof.clone();
    proof_repository
        .expect_get_proof()
        .once()
        .in_sequence(&mut seq)
        .returning(move |_, _| Ok(proof_moved.clone()));

    interaction_repository
        .expect_create_interaction()
        .once()
        .in_sequence(&mut seq)
        .returning(move |_| Ok(interaction_id));

    proof_repository
        .expect_update_proof()
        .once()
        .in_sequence(&mut seq)
        .returning(move |update| {
            assert_eq!(update.id, proof.id);
            Ok(())
        });

    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_generate_alphanumeric()
        .once()
        .returning(|_| String::from("ABC123"));

    let protocol = setup_protocol(Repositories {
        proof_repository,
        interaction_repository,
        crypto,
        ..Default::default()
    });

    let result = protocol.share_proof(&proof).await.unwrap();

    assert!(result.starts_with(r#"openid4vp://?response_type=vp_token"#))
}

fn generic_holder_did() -> Did {
    let now = OffsetDateTime::now_utc();
    Did {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "holder".to_string(),
        did: "did:key:holder".parse().unwrap(),
        did_type: DidType::Remote,
        did_method: "KEY".to_string(),
        keys: None,
        organisation: None,
        deactivated: false,
    }
}

#[tokio::test]
async fn test_handle_invitation_proof_success() {
    let mut proof_repository = MockProofRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let mut seq = Sequence::new();

    interaction_repository
        .expect_create_interaction()
        .once()
        .in_sequence(&mut seq)
        .returning(move |request| Ok(request.id));

    proof_repository
        .expect_create_proof()
        .once()
        .in_sequence(&mut seq)
        .returning(move |request| Ok(request.id));

    let protocol = setup_protocol(Repositories {
        proof_repository,
        interaction_repository,
        ..Default::default()
    });

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let url = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
        , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();

    let result = protocol
        .handle_invitation(url, generic_holder_did())
        .await
        .unwrap();
    assert!(matches!(result, InvitationResponseDTO::ProofRequest { .. }));
}

#[tokio::test]
async fn test_handle_invitation_proof_failed() {
    let protocol = setup_protocol(Repositories {
        ..Default::default()
    });

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let incorrect_response_type = Url::parse(&format!("openid4vp://?response_type=some_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                      , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(incorrect_response_type, generic_holder_did())
        .await
        .unwrap_err();
    assert!(matches!(result, TransportProtocolError::InvalidRequest(_)));

    let missing_nonce = Url::parse(&format!("openid4vp://?response_type=vp_token&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                            , callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(missing_nonce, generic_holder_did())
        .await
        .unwrap_err();
    assert!(matches!(result, TransportProtocolError::InvalidRequest(_)));

    let incorrect_client_id_scheme = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=some_scheme&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                         , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(incorrect_client_id_scheme, generic_holder_did())
        .await
        .unwrap_err();
    assert!(matches!(result, TransportProtocolError::InvalidRequest(_)));

    let incorrect_response_mode = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=some_mode&response_uri={}&presentation_definition={}"
                                                      , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(incorrect_response_mode, generic_holder_did())
        .await
        .unwrap_err();
    assert!(matches!(result, TransportProtocolError::InvalidRequest(_)));

    let incorrect_client_id_scheme = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=some_scheme&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                         , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(incorrect_client_id_scheme, generic_holder_did())
        .await
        .unwrap_err();
    assert!(matches!(result, TransportProtocolError::InvalidRequest(_)));

    let metadata_missing_jwt_vp_json = serde_json::to_string(&OpenID4VPClientMetadata {
        vp_formats: Default::default(),
        client_id_scheme: "redirect_uri".to_string(),
    })
    .unwrap();
    let missing_metadata_field = Url::parse(&format!("openid4vp://?response_type=some_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}", nonce, callback_url, metadata_missing_jwt_vp_json, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(missing_metadata_field, generic_holder_did())
        .await
        .unwrap_err();
    assert!(matches!(result, TransportProtocolError::InvalidRequest(_)));
}

#[test]
fn test_serialize_and_deserialize_interaction_data() {
    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let query = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                    , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap().query().unwrap().to_string();
    let data: OpenID4VPInteractionData = serde_qs::from_str(&query).unwrap();
    let json = serde_json::to_string(&data).unwrap();
    let _data_from_json: OpenID4VPInteractionData = serde_json::from_str(&json).unwrap();
}
