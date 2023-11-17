use crate::config::data_structure::CoreConfig;
use crate::crypto::MockCryptoProvider;
use crate::model::credential::{Credential, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::interaction::Interaction;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::transport_protocol::dto::SubmitIssuerResponse;
use crate::provider::transport_protocol::provider::MockTransportProtocolProvider;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::mock::claim_repository::MockClaimRepository;
use crate::repository::mock::credential_repository::MockCredentialRepository;
use crate::repository::mock::proof_repository::MockProofRepository;
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{
    OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialRequestDTO, OpenID4VCIError,
    OpenID4VCIProofRequestDTO, OpenID4VCITokenRequestDTO,
};
use crate::service::oidc::mapper::vec_last_position_from_token_path;
use crate::service::oidc::OIDCService;
use crate::service::test_utilities::generic_config;
use mockall::predicate::{always, eq};
use shared_types::DidId;

use crate::model::did::{Did, DidType};
use crate::repository::did_repository::MockDidRepository;
use serde_json::json;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
struct Mocks {
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub credential_repository: MockCredentialRepository,
    pub proof_repository: MockProofRepository,
    pub interaction_repository: MockInteractionRepository,
    pub claim_repository: MockClaimRepository,
    pub config: CoreConfig,
    pub transport_provider: MockTransportProtocolProvider,
    pub did_repository: MockDidRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub crypto: MockCryptoProvider,
    pub revocation_method_provider: MockRevocationMethodProvider,
}

#[allow(clippy::too_many_arguments)]
fn setup_service(mocks: Mocks) -> OIDCService {
    OIDCService::new(
        Some("http://127.0.0.1:3000".to_string()),
        Arc::new(mocks.credential_schema_repository),
        Arc::new(mocks.credential_repository),
        Arc::new(mocks.proof_repository),
        Arc::new(mocks.interaction_repository),
        Arc::new(mocks.claim_repository),
        Arc::new(mocks.config),
        Arc::new(mocks.transport_provider),
        Arc::new(mocks.did_repository),
        Arc::new(mocks.formatter_provider),
        Arc::new(mocks.did_method_provider),
        Arc::new(mocks.crypto),
        Arc::new(mocks.revocation_method_provider),
    )
}

fn generic_credential_schema() -> CredentialSchema {
    let now = OffsetDateTime::now_utc();
    CredentialSchema {
        id: Uuid::new_v4(),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        format: "JWT".to_string(),
        revocation_method: "".to_string(),
        claim_schemas: None,
        organisation: None,
    }
}

fn dummy_interaction(
    pre_authorized_code: bool,
    access_token_expires_at: Option<&str>,
) -> Interaction {
    Interaction {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        host: Some("http://host-base-url".parse().unwrap()),
        data: Some(
            json!({
            "pre_authorized_code_used": pre_authorized_code,
            "access_token": "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            "access_token_expires_at": access_token_expires_at.unwrap_or("2099-10-28T07:03:38.4404734Z"),
            })
            .to_string()
            .into_bytes(),
        ),
    }
}

fn dummy_credential(state: CredentialStateEnum, pre_authroized_code: bool) -> Credential {
    Credential {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        credential: b"credential".to_vec(),
        transport: "protocol".to_string(),
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state,
        }]),
        claims: None,
        issuer_did: None,
        holder_did: None,
        schema: None,
        interaction: Some(dummy_interaction(pre_authroized_code, None)),
        revocation_list: None,
        key: None,
    }
}

#[tokio::test]
async fn test_get_issuer_metadata_jwt() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let schema = generic_credential_schema();
    let relations = CredentialSchemaRelations::default();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(clone.clone()));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        config: generic_config(),
        ..Default::default()
    });
    let result = service.oidc_get_issuer_metadata(&schema.id).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    let credential = result.credentials_supported.get(0).unwrap().to_owned();
    assert_eq!("jwt_vc_json".to_string(), credential.format);
    assert_eq!(
        schema.name,
        credential.display.unwrap().get(0).unwrap().name
    );
}

#[tokio::test]
async fn test_get_issuer_metadata_sd_jwt() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();

    let mut schema = generic_credential_schema();
    schema.format = "SDJWT".to_string();
    let relations = CredentialSchemaRelations::default();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(clone.clone()));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        config: generic_config(),
        ..Default::default()
    });
    let result = service.oidc_get_issuer_metadata(&schema.id).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    let credential = result.credentials_supported.get(0).unwrap().to_owned();
    assert_eq!("vc+sd-jwt".to_string(), credential.format);
    assert_eq!(
        schema.name,
        credential.display.unwrap().get(0).unwrap().name
    );
}

#[tokio::test]
async fn test_service_discovery() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(
                eq(schema.id.to_owned()),
                eq(CredentialSchemaRelations::default()),
            )
            .returning(move |_, _| Ok(clone.clone()));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        config: generic_config(),
        ..Default::default()
    });
    let result = service.oidc_service_discovery(&schema.id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_oidc_create_token() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(
                eq(schema.id.to_owned()),
                eq(CredentialSchemaRelations::default()),
            )
            .returning(move |_, _| Ok(clone.clone()));

        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(CredentialStateEnum::Pending, false)])
            });

        credential_repository
            .expect_update_credential()
            .once()
            .return_once(|_| Ok(()));

        interaction_repository
            .expect_update_interaction()
            .once()
            .return_once(|_| Ok(()));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config(),
        ..Default::default()
    });
    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            },
        )
        .await;

    assert!(result.is_ok());

    let result_content = result.unwrap();
    assert_eq!("bearer", result_content.token_type);
    assert_eq!(
        "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
        result_content.access_token
    );
}

#[tokio::test]
async fn test_oidc_create_token_invalid_grant_type() {
    let schema = generic_credential_schema();
    let service = setup_service(Mocks::default());
    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                grant_type: "something else".to_string(),
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedGrantType
        ))
    ));
}

#[tokio::test]
async fn test_oidc_create_token_pre_authorized_code_used() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let interaction_repository = MockInteractionRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(
                eq(schema.id.to_owned()),
                eq(CredentialSchemaRelations::default()),
            )
            .returning(move |_, _| Ok(clone.clone()));

        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(CredentialStateEnum::Pending, true)])
            });
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config(),
        ..Default::default()
    });
    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidGrant))
    ));
}

#[tokio::test]
async fn test_oidc_create_token_wrong_credential_state() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let interaction_repository = MockInteractionRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(
                eq(schema.id.to_owned()),
                eq(CredentialSchemaRelations::default()),
            )
            .returning(move |_, _| Ok(clone.clone()));

        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(CredentialStateEnum::Offered, false)])
            });
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config(),
        ..Default::default()
    });
    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result, Err(ServiceError::AlreadyExists)));
}

#[tokio::test]
async fn test_oidc_create_credential_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut transport_provider = MockTransportProtocolProvider::default();
    let mut did_repository = MockDidRepository::default();
    let now = OffsetDateTime::now_utc();

    let schema = generic_credential_schema();
    let credential = dummy_credential(CredentialStateEnum::Pending, true);
    let holder_did_id: DidId = Uuid::new_v4().into();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(clone.clone()));

        let clone = credential.clone();
        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| Ok(vec![clone]));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| Ok(dummy_interaction(true, None)));

        transport_provider
            .expect_issue_credential()
            .once()
            .return_once(|_| {
                Ok(SubmitIssuerResponse {
                    credential: "xyz".to_string(),
                    format: "jwt_vc_json".to_string(),
                })
            });

        let holder_did_id_clone = holder_did_id.clone();
        did_repository
            .expect_get_did_by_value()
            .times(1)
            .returning(move |did_value, _| {
                Ok(Did {
                    id: holder_did_id_clone.clone(),
                    created_date: now,
                    last_modified: now,
                    name: "verifier".to_string(),
                    did: did_value.clone(),
                    did_type: DidType::Remote,
                    did_method: "KEY".to_string(),
                    organisation: None,
                    keys: None,
                })
            });

        credential_repository
            .expect_update_credential()
            .once()
            .withf(move |request| {
                request.id == credential.id && request.holder_did_id == Some(holder_did_id.clone())
            })
            .returning(move |_| Ok(()));
    }

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config(),
        transport_provider,
        did_repository,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                },
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "jwt".to_string(),
                    jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6MTIzNCJ9.eyJhdWQiOiIxMjM0NTY3ODkwIn0.y9vUcoVsVgIt96oO28qpyCqCpc2Mr2Qztligw2PBaYI".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!("jwt_vc_json", result.format);
    assert_eq!("xyz", result.credential);
}

#[tokio::test]
async fn test_oidc_create_credential_format_invalid() {
    let mut repository = MockCredentialSchemaRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(clone.clone()));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "some_string".to_string(),
                credential_definition: OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                },
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "".to_string(),
                    jwt: "".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialFormat
        ))
    ));
}

#[tokio::test]
async fn test_oidc_create_credential_format_invalid_for_credential_schema() {
    let mut repository = MockCredentialSchemaRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(clone.clone()));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "vc+sd-jwt".to_string(),
                credential_definition: OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                },
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "".to_string(),
                    jwt: "".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialFormat
        ))
    ));
}

#[tokio::test]
async fn test_oidc_create_credential_format_invalid_credential_definition() {
    let mut repository = MockCredentialSchemaRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(clone.clone()));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        config: generic_config(),
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["some string".to_string()],
                },
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "".to_string(),
                    jwt: "".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialType
        ))
    ));
}

#[tokio::test]
async fn test_oidc_create_credential_format_invalid_bearer_token() {
    let mut repository = MockCredentialSchemaRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(clone.clone()));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        config: generic_config(),
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                },
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "".to_string(),
                    jwt: "".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken))
    ));
}

#[tokio::test]
async fn test_oidc_create_credential_pre_authorized_code_not_used() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let transport_provider = MockTransportProtocolProvider::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(clone.clone()));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| Ok(dummy_interaction(false, None)));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config(),
        transport_provider,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                },
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "".to_string(),
                    jwt: "".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken))
    ));
}

#[tokio::test]
async fn test_oidc_create_credential_interaction_data_invalid() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let transport_provider = MockTransportProtocolProvider::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(clone.clone()));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| Ok(dummy_interaction(true, None)));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config(),
        transport_provider,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.123",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                },
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "".to_string(),
                    jwt: "".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken))
    ));
}

#[tokio::test]
async fn test_oidc_create_credential_access_token_expired() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let transport_provider = MockTransportProtocolProvider::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(clone.clone()));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| {
                Ok(dummy_interaction(
                    true,
                    Some("2022-10-28T07:03:38.4404734Z"),
                ))
            });
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config(),
        transport_provider,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                },
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "".to_string(),
                    jwt: "".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken))
    ));
}

#[test]
fn test_vec_last_position_from_token_path() {
    assert_eq!(
        vec_last_position_from_token_path("$[0].verifiableCredential[0]").unwrap(),
        0
    );
    assert_eq!(
        vec_last_position_from_token_path("$[0].verifiableCredential[1]").unwrap(),
        1
    );
    assert_eq!(
        vec_last_position_from_token_path("$[1].verifiableCredential[2]").unwrap(),
        2
    );
    assert_eq!(
        vec_last_position_from_token_path("$.verifiableCredential[3]").unwrap(),
        3
    );
    assert_eq!(vec_last_position_from_token_path("$[4]").unwrap(), 4);
    assert_eq!(
        vec_last_position_from_token_path("$[152046]").unwrap(),
        152046
    );
    assert_eq!(vec_last_position_from_token_path("$").unwrap(), 0);
    assert!(vec_last_position_from_token_path("$[ABC]").is_err());
}
