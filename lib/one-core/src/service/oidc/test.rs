use crate::config::data_structure::CoreConfig;
use crate::model::credential::{Credential, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::interaction::Interaction;
use crate::repository::mock::credential_repository::MockCredentialRepository;
use crate::repository::mock::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::mock::interaction_repository::MockInteractionRepository;
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{OpenID4VCIError, OpenID4VCITokenRequestDTO};
use crate::service::oidc::OIDCService;
use crate::service::test_utilities::generic_config;
use mockall::predicate::eq;
use serde_json::json;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

fn setup_service(
    repository: MockCredentialSchemaRepository,
    credential_repository: MockCredentialRepository,
    interaction_repository: MockInteractionRepository,
    config: CoreConfig,
) -> OIDCService {
    OIDCService::new(
        Some("http://127.0.0.1:3000".to_string()),
        Arc::new(repository),
        Arc::new(credential_repository),
        Arc::new(interaction_repository),
        Arc::new(config),
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
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            host: Some("host".to_string()),
            data: Some(
                json!({
                "pre_authorized_code_used": pre_authroized_code,
                "access_token": "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
                "access_token_expires_at": "2023-10-28T07:03:38.4404734Z"
                })
                .to_string()
                .into_bytes(),
            ),
        }),
        revocation_list: None,
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
    let service = setup_service(
        repository,
        credential_repository,
        MockInteractionRepository::default(),
        generic_config(),
    );
    let result = service.oidc_get_issuer_metadata(&schema.id).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(
        "jwt_vc_json".to_string(),
        result.credentials_supported.get(0).unwrap().format
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
    let service = setup_service(
        repository,
        credential_repository,
        MockInteractionRepository::default(),
        generic_config(),
    );
    let result = service.oidc_get_issuer_metadata(&schema.id).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(
        "vc+sd-jwt".to_string(),
        result.credentials_supported.get(0).unwrap().format
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
    let service = setup_service(
        repository,
        credential_repository,
        MockInteractionRepository::default(),
        generic_config(),
    );
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
    let service = setup_service(
        repository,
        credential_repository,
        interaction_repository,
        generic_config(),
    );
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
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockCredentialRepository::default(),
        MockInteractionRepository::default(),
        generic_config(),
    );
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
    let service = setup_service(
        repository,
        credential_repository,
        interaction_repository,
        generic_config(),
    );
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
    let service = setup_service(
        repository,
        credential_repository,
        interaction_repository,
        generic_config(),
    );
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
