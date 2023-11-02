use std::{str::FromStr, sync::Arc};

use time::OffsetDateTime;
use uuid::Uuid;

use mockall::{predicate, Sequence};

use crate::{
    config::data_structure::{ExchangeOPENID4VCParams, ExchangeParams, ParamsEnum},
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::{Credential, CredentialState, CredentialStateEnum},
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::{Did, DidType},
        interaction::Interaction,
        organisation::Organisation,
    },
    provider::transport_protocol::TransportProtocol,
    repository::mock::{
        credential_repository::MockCredentialRepository,
        interaction_repository::MockInteractionRepository, proof_repository::MockProofRepository,
    },
};

use super::OpenID4VC;

#[derive(Default)]
struct Repositories {
    pub _client: reqwest::Client,
    pub credential_repository: MockCredentialRepository,
    pub proof_repository: MockProofRepository,
    pub interaction_repository: MockInteractionRepository,
    pub _base_url: Option<String>,
    pub _params: ExchangeOPENID4VCParams,
}

fn setup_protocol(repositories: Repositories) -> OpenID4VC {
    OpenID4VC::new(
        Some("BASE_URL".to_string()),
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.proof_repository),
        Arc::new(repositories.interaction_repository),
        Some(ParamsEnum::Parsed(ExchangeParams::OPENID4VC(
            ExchangeOPENID4VCParams::default(),
        ))),
    )
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
        credential: vec![],
        transport: "PROCIVIS_TEMPORARY".to_string(),
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
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: now,
            last_modified: now,
            name: "did1".to_string(),
            organisation: Some(organisation.clone()),
            did: "did1".to_string(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: None,
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
            host: Some("host".to_string()),
            data: Some(vec![1, 2, 3]),
        }),
        revocation_list: None,
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
    let interaction_id: Uuid = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();

    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let mut seq = Sequence::new();

    let credential_moved = credential.clone();
    credential_repository
        .expect_get_credential()
        .once()
        .in_sequence(&mut seq)
        .returning(move |_, _| Ok(credential_moved.clone()));

    interaction_repository
        .expect_delete_interaction()
        .once()
        .in_sequence(&mut seq)
        .with(predicate::eq(credential.id))
        .returning(move |_| Ok(()));

    interaction_repository
        .expect_create_interaction()
        .once()
        .in_sequence(&mut seq)
        .returning(move |_| Ok(interaction_id));

    credential_repository
        .expect_update_credential()
        .once()
        .in_sequence(&mut seq)
        .returning(move |update| {
            assert_eq!(update.id, interaction_id);
            Ok(())
        });

    let protocol = setup_protocol(Repositories {
        credential_repository,
        interaction_repository,
        ..Default::default()
    });

    let result = protocol.share_credential(&credential).await.unwrap();

    // Everything except for interaction id is here.
    // Genrating token with predictible interaction id it tested somewhere else.
    assert!(
        result.starts_with(r#"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22BASE_URL%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22credential_definition%22%3A%7B%22type%22%3A%5B%22VerifiableCredential%22%5D%2C%22credentialSubject%22%3A%7B%22NUMBER%22%3A%7B%22value%22%3A%22123%22%2C%22value_type%22%3A%22NUMBER%22%7D%7D%7D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%"#)
    )
}
