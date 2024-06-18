use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use mockall::predicate::{self, always, eq};
use serde_json::json;
use shared_types::{DidId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::config::ConfigValidationError;
use crate::crypto::MockCryptoProvider;
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, CredentialSchemaType,
    LayoutType, WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::history::HistoryAction;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofState, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, Presentation,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::credential_formatter::test_utilities::get_dummy_date;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::did_method::dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::exchange_protocol::dto::SubmitIssuerResponse;
use crate::provider::exchange_protocol::openid4vc::dto::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, OpenID4VPClientMetadata,
    OpenID4VPClientMetadataJwkDTO, OpenID4VPFormat,
};
use crate::provider::exchange_protocol::provider::MockExchangeProtocolProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::revocation::{CredentialRevocationState, MockRevocationMethod};
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::oidc::dto::{
    NestedPresentationSubmissionDescriptorDTO, OpenID4VCICredentialDefinitionRequestDTO,
    OpenID4VCICredentialRequestDTO, OpenID4VCIError, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO,
    OpenID4VCIProofRequestDTO, OpenID4VCITokenRequestDTO, OpenID4VPDirectPostRequestDTO,
    PresentationSubmissionDescriptorDTO, PresentationSubmissionMappingDTO,
};
use crate::service::oidc::mapper::vec_last_position_from_token_path;
use crate::service::oidc::model::{
    OpenID4VPInteractionContent, OpenID4VPPresentationDefinition,
    OpenID4VPPresentationDefinitionConstraint, OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor,
    OpenID4VPPresentationDefinitionInputDescriptorFormat,
};
use crate::service::oidc::validator::validate_claims;
use crate::service::oidc::OIDCService;
use crate::service::test_utilities::*;

#[derive(Default)]
struct Mocks {
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub credential_repository: MockCredentialRepository,
    pub history_repository: MockHistoryRepository,
    pub proof_repository: MockProofRepository,
    pub interaction_repository: MockInteractionRepository,
    pub key_repository: MockKeyRepository,
    pub key_provider: MockKeyProvider,
    pub config: CoreConfig,
    pub exchange_provider: MockExchangeProtocolProvider,
    pub did_repository: MockDidRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub crypto_provider: MockCryptoProvider,
}

#[allow(clippy::too_many_arguments)]
fn setup_service(mocks: Mocks) -> OIDCService {
    OIDCService::new(
        Some("http://127.0.0.1:3000".to_string()),
        Arc::new(mocks.credential_schema_repository),
        Arc::new(mocks.credential_repository),
        Arc::new(mocks.history_repository),
        Arc::new(mocks.proof_repository),
        Arc::new(mocks.key_repository),
        Arc::new(mocks.key_provider),
        Arc::new(mocks.interaction_repository),
        Arc::new(mocks.config),
        Arc::new(mocks.exchange_provider),
        Arc::new(mocks.did_repository),
        Arc::new(mocks.formatter_provider),
        Arc::new(mocks.did_method_provider),
        Arc::new(mocks.key_algorithm_provider),
        Arc::new(mocks.revocation_method_provider),
        Arc::new(mocks.crypto_provider),
    )
}

fn generic_credential_schema() -> CredentialSchema {
    let now = OffsetDateTime::now_utc();
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        format: "JWT".to_string(),
        revocation_method: "".to_string(),
        claim_schemas: None,
        organisation: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    }
}

fn dummy_interaction(
    pre_authorized_code: bool,
    access_token_expires_at: Option<&str>,
    refresh_token: Option<&str>,
    refresh_token_expires_at: Option<&str>,
) -> Interaction {
    let mut data = json!({
        "pre_authorized_code_used": pre_authorized_code,
        "access_token": "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
        "access_token_expires_at": access_token_expires_at.unwrap_or("2099-10-28T07:03:38.4404734Z"),
    });

    if let Some(refresh_token) = refresh_token {
        data.as_object_mut()
            .unwrap()
            .insert("refresh_token".to_string(), json!(refresh_token));
    }

    if let Some(refresh_token_expires_at) = refresh_token_expires_at {
        data.as_object_mut().unwrap().insert(
            "refresh_token_expires_at".to_string(),
            json!(refresh_token_expires_at),
        );
    }

    Interaction {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        host: Some("http://host-base-url".parse().unwrap()),
        data: Some(data.to_string().into_bytes()),
    }
}

fn dummy_credential(
    protocol: &str,
    state: CredentialStateEnum,
    pre_authroized_code: bool,
) -> Credential {
    Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: b"credential".to_vec(),
        exchange: protocol.to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state,
            suspend_end_date: None,
        }]),
        claims: None,
        issuer_did: None,
        holder_did: None,
        schema: None,
        interaction: Some(dummy_interaction(pre_authroized_code, None, None, None)),
        revocation_list: None,
        key: None,
    }
}

#[tokio::test]
async fn test_get_issuer_metadata_jwt() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let schema = generic_credential_schema();
    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        ..Default::default()
    };
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(Some(clone.clone())));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service.oidc_get_issuer_metadata(&schema.id).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    let credential = result.credentials_supported[0].to_owned();
    assert_eq!("jwt_vc_json".to_string(), credential.format);
    assert_eq!(schema.name, credential.display.unwrap()[0].name);
}

#[tokio::test]
async fn test_get_issuer_metadata_sd_jwt() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();

    let mut schema = generic_credential_schema();
    schema.format = "SDJWT".to_string();
    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        ..Default::default()
    };
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(Some(clone.clone())));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service.oidc_get_issuer_metadata(&schema.id).await.unwrap();
    let credential = result.credentials_supported[0].to_owned();
    assert_eq!("vc+sd-jwt".to_string(), credential.format);
    assert_eq!(schema.name, credential.display.unwrap()[0].name);
}

#[tokio::test]
async fn test_get_issuer_metadata_mdoc() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();

    let mut schema = generic_credential_schema();
    schema.format = "MDOC".to_string();
    let now = OffsetDateTime::now_utc();
    schema.claim_schemas = Some(vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: now,
                last_modified: now,
                array: false,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location/X".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
                array: false,
            },
            required: true,
        },
    ]);

    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        ..Default::default()
    };
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(Some(clone.clone())));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service.oidc_get_issuer_metadata(&schema.id).await.unwrap();
    let credential = result.credentials_supported[0].to_owned();
    assert_eq!("mso_mdoc".to_string(), credential.format);
    assert_eq!(schema.name, credential.display.unwrap()[0].name);
    let claims = credential.claims.unwrap();
    assert_eq!(
        HashMap::from([(
            "location".to_string(),
            HashMap::from([(
                "X".to_string(),
                OpenID4VCIIssuerMetadataMdocClaimsValuesDTO {
                    value: Default::default(),
                    value_type: "STRING".to_string(),
                    mandatory: Some(true),
                    order: None
                }
            )])
        )]),
        claims
    );
}

#[tokio::test]
async fn test_service_discovery() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();

    let schema = generic_credential_schema();
    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        ..Default::default()
    };
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(Some(clone.clone())));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        config: generic_config().core,
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
            .returning(move |_, _| Ok(Some(clone.clone())));

        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(
                    "OPENID4VC",
                    CredentialStateEnum::Pending,
                    false,
                )])
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
        config: generic_config().core,
        ..Default::default()
    });
    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
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
    assert!(result_content.refresh_token.is_none());
    assert!(result_content.refresh_token_expires_in.is_none());
}

#[tokio::test]
async fn test_oidc_create_token_incorrect_protocol() {
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
            .returning(move |_, _| Ok(Some(clone.clone())));

        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(
                    "PROCIVIS_TEMPORARY",
                    CredentialStateEnum::Pending,
                    false,
                )])
            });
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
            },
        )
        .await;

    assert!(result.is_err_and(|x| matches!(
        x,
        ServiceError::ConfigValidationError(ConfigValidationError::InvalidType(_, _))
    )));
}

#[tokio::test]
async fn test_oidc_create_token_empty_pre_authorized_code() {
    let schema = generic_credential_schema();

    let service = setup_service(Mocks {
        config: generic_config().core,
        ..Default::default()
    });
    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "".to_string(),
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::InvalidRequest
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
            .returning(move |_, _| Ok(Some(clone.clone())));

        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(
                    "OPENID4VC",
                    CredentialStateEnum::Pending,
                    true,
                )])
            });
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
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
            .returning(move |_, _| Ok(Some(clone.clone())));

        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(
                    "OPENID4VC",
                    CredentialStateEnum::Offered,
                    false,
                )])
            });
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::InvalidCredentialState { .. }
        ))
    ));
}

#[tokio::test]
async fn test_oidc_create_credential_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut exchange_provider = MockExchangeProtocolProvider::default();
    let mut did_repository = MockDidRepository::default();
    let now = OffsetDateTime::now_utc();

    let schema = generic_credential_schema();
    let credential = dummy_credential("OPENID4VC", CredentialStateEnum::Pending, true);
    let holder_did_id: DidId = Uuid::new_v4().into();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(Some(clone.clone())));

        let clone = credential.clone();
        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| Ok(vec![clone]));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| Ok(Some(dummy_interaction(true, None, None, None))));

        exchange_provider
            .expect_issue_credential()
            .once()
            .return_once(|_, _| {
                Ok(SubmitIssuerResponse {
                    credential: "xyz".to_string(),
                    format: "jwt_vc_json".to_string(),
                    redirect_uri: None,
                })
            });

        did_repository
            .expect_get_did_by_value()
            .times(1)
            .returning(move |did_value, _| {
                Ok(Some(Did {
                    id: holder_did_id,
                    created_date: now,
                    last_modified: now,
                    name: "verifier".to_string(),
                    did: did_value.clone(),
                    did_type: DidType::Remote,
                    did_method: "KEY".to_string(),
                    organisation: None,
                    keys: None,
                    deactivated: false,
                }))
            });

        credential_repository
            .expect_update_credential()
            .once()
            .withf(move |request| {
                request.id == credential.id && request.holder_did_id == Some(holder_did_id)
            })
            .returning(move |_| Ok(()));
    }

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        exchange_provider,
        did_repository,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                }),
                doctype: None,
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
async fn test_oidc_create_credential_incorrect_protocol() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let schema = generic_credential_schema();
    let credential = dummy_credential("PROCIVIS_TEMPORARY", CredentialStateEnum::Pending, true);
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(Some(clone.clone())));

        let clone = credential.clone();
        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| Ok(vec![clone]));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| Ok(Some(dummy_interaction(true, None, None, None))));
    }

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                }),
                doctype: None,
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "jwt".to_string(),
                    jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6MTIzNCJ9.eyJhdWQiOiIxMjM0NTY3ODkwIn0.y9vUcoVsVgIt96oO28qpyCqCpc2Mr2Qztligw2PBaYI".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_err_and(|x| matches!(
        x,
        ServiceError::ConfigValidationError(ConfigValidationError::InvalidType(_, _))
    )));
}

#[tokio::test]
async fn test_oidc_create_credential_success_mdoc() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut exchange_provider = MockExchangeProtocolProvider::default();
    let mut did_repository = MockDidRepository::default();
    let now = OffsetDateTime::now_utc();

    let schema = CredentialSchema {
        format: "MDOC".to_string(),
        schema_id: "test.doctype".to_owned(),
        ..generic_credential_schema()
    };
    let credential = dummy_credential("OPENID4VC", CredentialStateEnum::Pending, true);
    let holder_did_id: DidId = Uuid::new_v4().into();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(Some(clone.clone())));

        let clone = credential.clone();
        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| Ok(vec![clone]));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| Ok(Some(dummy_interaction(true, None, None, None))));

        exchange_provider
            .expect_issue_credential()
            .once()
            .return_once(|_, _| {
                Ok(SubmitIssuerResponse {
                    credential: "xyz".to_string(),
                    format: "mso_mdoc".to_string(),
                    redirect_uri: None,
                })
            });

        did_repository
            .expect_get_did_by_value()
            .times(1)
            .returning(move |did_value, _| {
                Ok(Some(Did {
                    id: holder_did_id,
                    created_date: now,
                    last_modified: now,
                    name: "verifier".to_string(),
                    did: did_value.clone(),
                    did_type: DidType::Remote,
                    did_method: "KEY".to_string(),
                    organisation: None,
                    keys: None,
                    deactivated: false,
                }))
            });

        credential_repository
            .expect_update_credential()
            .once()
            .withf(move |request| {
                request.id == credential.id && request.holder_did_id == Some(holder_did_id)
            })
            .returning(move |_| Ok(()));
    }

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        exchange_provider,
        did_repository,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "mso_mdoc".to_string(),
                credential_definition: None,
                doctype: Some(schema.schema_id),
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "jwt".to_string(),
                    jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6MTIzNCJ9.eyJhdWQiOiIxMjM0NTY3ODkwIn0.y9vUcoVsVgIt96oO28qpyCqCpc2Mr2Qztligw2PBaYI".to_string(),
                },
            },
        )
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!("mso_mdoc", result.format);
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
            .returning(move |_, _| Ok(Some(clone.clone())));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "some_string".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                }),
                doctype: None,
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
            .returning(move |_, _| Ok(Some(clone.clone())));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "vc+sd-jwt".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                }),
                doctype: None,
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
            .returning(move |_, _| Ok(Some(clone.clone())));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["some string".to_string()],
                }),
                doctype: None,
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
            .returning(move |_, _| Ok(Some(clone.clone())));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                }),
                doctype: None,
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
    let exchange_provider = MockExchangeProtocolProvider::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(Some(clone.clone())));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| Ok(Some(dummy_interaction(false, None, None, None))));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        exchange_provider,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                }),
                doctype: None,
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
    let exchange_provider = MockExchangeProtocolProvider::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(Some(clone.clone())));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| Ok(Some(dummy_interaction(true, None, None, None))));
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        exchange_provider,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.123",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                }),
                doctype: None,
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
    let exchange_provider = MockExchangeProtocolProvider::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), always())
            .returning(move |_, _| Ok(Some(clone.clone())));

        interaction_repository
            .expect_get_interaction()
            .once()
            .return_once(|_, _| {
                Ok(Some(dummy_interaction(
                    true,
                    Some("2022-10-28T07:03:38.4404734Z"),
                    None,
                    None,
                )))
            });
    }
    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        exchange_provider,
        ..Default::default()
    });

    let result = service
        .oidc_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                }),
                doctype: None,
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

fn jwt_format_map() -> HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat> {
    HashMap::from([(
        "jwt_vc_json".to_string(),
        OpenID4VPPresentationDefinitionInputDescriptorFormat {
            alg: vec!["EdDSA".to_string(), "ES256".to_string()],
            proof_type: vec![],
        },
    )])
}

#[tokio::test]
async fn test_oidc_verifier_presentation_definition_success() {
    let mut proof_repository = MockProofRepository::default();

    let proof_id = Uuid::new_v4();

    let interaction_data = serde_json::to_vec(&OpenID4VPInteractionContent {
        nonce: "nonce".to_string(),
        presentation_definition: OpenID4VPPresentationDefinition {
            id: Uuid::new_v4(),
            input_descriptors: vec![OpenID4VPPresentationDefinitionInputDescriptor {
                id: "123".to_string(),
                name: None,
                purpose: None,
                format: jwt_format_map(),
                constraints: OpenID4VPPresentationDefinitionConstraint {
                    validity_credential_nbf: None,
                    fields: vec![OpenID4VPPresentationDefinitionConstraintField {
                        id: Some(Uuid::new_v4().into()),
                        name: None,
                        purpose: None,
                        path: vec!["123".to_string()],
                        optional: Some(false),
                        filter: None,
                        intent_to_retain: None,
                    }],
                },
            }],
        },
    })
    .unwrap();

    {
        let now = OffsetDateTime::now_utc();
        proof_repository
            .expect_get_proof()
            .once()
            .return_once(move |_, _| {
                Ok(Some(Proof {
                    id: proof_id.to_owned(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    issuance_date: get_dummy_date(),
                    exchange: "OPENID4VC".to_string(),
                    redirect_uri: None,
                    state: Some(vec![ProofState {
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        state: ProofStateEnum::Pending,
                    }]),
                    schema: Some(ProofSchema {
                        id: Uuid::default().into(),
                        created_date: now,
                        last_modified: now,
                        deleted_at: None,
                        name: "test".to_string(),
                        expire_duration: 0,
                        organisation: None,
                        input_schemas: Some(vec![ProofInputSchema {
                            validity_constraint: Some(100),
                            claim_schemas: Some(vec![ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    id: Uuid::from_str("2fa85f64-5717-4562-b3fc-2c963f66afa6")
                                        .unwrap()
                                        .into(),
                                    key: "Key".to_owned(),
                                    data_type: "STRING".to_owned(),
                                    created_date: get_dummy_date(),
                                    last_modified: get_dummy_date(),
                                    array: false,
                                },
                                required: true,
                                order: 0,
                            }]),
                            credential_schema: Some(CredentialSchema {
                                id: Uuid::from_str("3fa85f64-5717-4562-b3fc-2c963f66afa6")
                                    .unwrap()
                                    .into(),
                                deleted_at: None,
                                created_date: get_dummy_date(),
                                last_modified: get_dummy_date(),
                                name: "Credential1".to_owned(),
                                format: "JWT".to_owned(),
                                revocation_method: "NONE".to_owned(),
                                wallet_storage_type: None,
                                claim_schemas: None,
                                organisation: None,
                                layout_type: LayoutType::Card,
                                layout_properties: None,
                                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                                schema_id: "CredentialSchemaId".to_owned(),
                            }),
                        }]),
                    }),
                    claims: None,
                    verifier_did: None,
                    holder_did: None,
                    verifier_key: None,
                    interaction: Some(Interaction {
                        id: Uuid::new_v4(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        host: None,
                        data: Some(interaction_data),
                    }),
                }))
            });
    }

    let service = setup_service(Mocks {
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_verifier_presentation_definition(proof_id)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_oidc_verifier_presentation_definition_incorrect_protocol() {
    let mut proof_repository = MockProofRepository::default();

    let proof_id = Uuid::new_v4();

    proof_repository
        .expect_get_proof()
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                id: proof_id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                issuance_date: get_dummy_date(),
                exchange: "PROCIVIS_TEMPORARY".to_string(),
                redirect_uri: None,
                state: None,
                schema: None,
                claims: None,
                verifier_did: None,
                holder_did: None,
                verifier_key: None,
                interaction: Some(Interaction {
                    id: Uuid::new_v4(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    host: None,
                    data: None,
                }),
            }))
        });

    let service = setup_service(Mocks {
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_verifier_presentation_definition(proof_id)
        .await;

    assert!(result.is_err_and(|x| matches!(
        x,
        ServiceError::ConfigValidationError(ConfigValidationError::InvalidType(_, _))
    )));
}

#[tokio::test]
async fn test_submit_proof_failed_credential_suspended() {
    let proof_id = Uuid::new_v4();
    let verifier_did = "verifier did".parse().unwrap();
    let holder_did: DidValue = "did:holder".parse().unwrap();
    let issuer_did: DidValue = "did:issuer".parse().unwrap();

    let mut proof_repository = MockProofRepository::new();
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .withf(move |history| {
            assert_eq!(history.entity_id, Some(proof_id.into()));
            assert_eq!(history.action, HistoryAction::Errored);
            true
        })
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let interaction_id = Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36").unwrap();

    let nonce = "7QqBfOcEcydceH6ZrXtu9fhDCvXjtLBv".to_string();

    let claim_id = Uuid::new_v4().into();
    let credential_schema = dummy_credential_schema();
    let interaction_data = OpenID4VPInteractionContent {
        nonce: nonce.to_owned(),
        presentation_definition: OpenID4VPPresentationDefinition {
            id: interaction_id.to_owned(),
            input_descriptors: vec![OpenID4VPPresentationDefinitionInputDescriptor {
                id: "input_0".to_string(),
                name: None,
                purpose: None,
                format: jwt_format_map(),
                constraints: OpenID4VPPresentationDefinitionConstraint {
                    fields: vec![
                        OpenID4VPPresentationDefinitionConstraintField {
                            id: None,
                            name: None,
                            purpose: None,
                            path: vec!["$.credentialSchema.id".to_string()],
                            optional: None,
                            filter: Some(OpenID4VPPresentationDefinitionConstraintFieldFilter {
                                r#type: "string".to_string(),
                                r#const: credential_schema.schema_id.to_owned(),
                            }),
                            intent_to_retain: None,
                        },
                        OpenID4VPPresentationDefinitionConstraintField {
                            id: Some(claim_id),
                            name: None,
                            purpose: None,
                            path: vec!["$.vc.credentialSubject.string".to_string()],
                            optional: Some(false),
                            filter: None,
                            intent_to_retain: None,
                        },
                    ],
                    validity_credential_nbf: None,
                },
            }],
        },
    };
    let interaction_data_serialized = serde_json::to_vec(&interaction_data).unwrap();
    let now = OffsetDateTime::now_utc();
    let interaction = Interaction {
        id: interaction_id.to_owned(),
        created_date: now,
        last_modified: now,
        host: None,
        data: Some(interaction_data_serialized),
    };

    let interaction_id_copy = interaction_id.to_owned();
    let holder_did_clone = holder_did.clone();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .withf(move |_interaction_id, _| {
            assert_eq!(*_interaction_id, interaction_id_copy);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                verifier_did: Some(Did {
                    did: verifier_did,
                    ..dummy_did()
                }),
                holder_did: Some(Did {
                    did: holder_did_clone,
                    ..dummy_did()
                }),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Pending,
                }]),
                schema: Some(ProofSchema {
                    input_schemas: Some(vec![ProofInputSchema {
                        validity_constraint: None,
                        claim_schemas: Some(vec![
                            ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    id: claim_id,
                                    key: "required_key".to_string(),
                                    ..dummy_claim_schema()
                                },
                                required: true,
                                order: 0,
                            },
                            ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    key: "optional_key".to_string(),
                                    ..dummy_claim_schema()
                                },
                                required: false,
                                order: 1,
                            },
                        ]),
                        credential_schema: Some(credential_schema),
                    }]),
                    ..dummy_proof_schema()
                }),
                interaction: Some(interaction),
                ..dummy_proof_with_protocol("OPENID4VC")
            }))
        });

    proof_repository
        .expect_set_proof_state()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let mut formatter = MockCredentialFormatter::new();

    let holder_did_clone = holder_did.clone();
    let issuer_did_clone = issuer_did.clone();
    formatter
        .expect_extract_credentials_unverified()
        .once()
        .returning(move |_| {
            Ok(DetailCredential {
                id: None,
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did_clone.to_owned()),
                claims: CredentialSubject {
                    values: HashMap::from([
                        ("unknown_key".to_string(), json!("unknown_key_value")),
                        ("required_key".to_string(), json!("required_key_value")),
                    ]),
                },
                status: vec![],
                credential_schema: None,
            })
        });

    let holder_did_clone = holder_did.clone();
    let nonce_clone = nonce.clone();
    formatter
        .expect_extract_presentation_unverified()
        .once()
        .returning(move |_, _| {
            Ok(Presentation {
                id: Some("presentation id".to_string()),
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                issuer_did: Some(holder_did_clone.to_owned()),
                nonce: Some(nonce_clone.to_owned()),
                credentials: vec!["credential".to_string()],
            })
        });

    let holder_did_clone = holder_did.clone();
    let nonce_clone = nonce.clone();
    formatter
        .expect_extract_presentation()
        .once()
        .returning(move |_, _, _| {
            Ok(Presentation {
                id: Some("presentation id".to_string()),
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                issuer_did: Some(holder_did_clone.to_owned()),
                nonce: Some(nonce_clone.to_owned()),
                credentials: vec!["credential".to_string()],
            })
        });
    formatter.expect_get_leeway().returning(|| 10);
    let issuer_did_clone = issuer_did.clone();
    formatter
        .expect_extract_credentials()
        .once()
        .returning(move |_, _| {
            Ok(DetailCredential {
                id: None,
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did.to_owned()),
                claims: CredentialSubject {
                    values: HashMap::from([
                        ("unknown_key".to_string(), json!("unknown_key_value")),
                        ("required_key".to_string(), json!("required_key_value")),
                    ]),
                },
                status: vec![CredentialStatus {
                    id: "".to_string(),
                    r#type: "".to_string(),
                    status_purpose: None,
                    additional_fields: Default::default(),
                }],
                credential_schema: None,
            })
        });

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .times(4)
        .returning(move |_| Some(formatter.clone()));

    let mut revocation_method = MockRevocationMethod::new();
    revocation_method
        .expect_check_credential_revocation_status()
        .once()
        .return_once(|_, _, _| {
            Ok(CredentialRevocationState::Suspended {
                suspend_end_date: None,
            })
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method_by_status_type()
        .once()
        .return_once(|_| Some((Arc::new(revocation_method), "".to_string())));

    let service = setup_service(Mocks {
        proof_repository,
        history_repository,
        formatter_provider,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let vp_token = "vp_token";

    let err = service
        .oidc_verifier_direct_post(OpenID4VPDirectPostRequestDTO {
            presentation_submission: Some(PresentationSubmissionMappingDTO {
                id: "25f5a42c-6850-49a0-b842-c7b2411021a5".to_string(),
                definition_id: interaction_id.to_string(),
                descriptor_map: vec![PresentationSubmissionDescriptorDTO {
                    id: "input_0".to_string(),
                    format: "jwt_vp_json".to_string(),
                    path: "$".to_string(),
                    path_nested: Some(NestedPresentationSubmissionDescriptorDTO {
                        format: "jwt_vc_json".to_string(),
                        path: "$.vp.verifiableCredential[0]".to_string(),
                    }),
                }],
            }),
            vp_token: Some(vp_token.to_string()),
            state: Some("a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap()),
            response: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ServiceError::BusinessLogic(BusinessLogicError::CredentialIsRevokedOrSuspended)
    ));
}

#[tokio::test]
async fn test_submit_proof_incorrect_protocol() {
    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(Some(dummy_proof_with_protocol("PROCIVIS_TEMPORARY"))));

    let service = setup_service(Mocks {
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_verifier_direct_post(OpenID4VPDirectPostRequestDTO {
            presentation_submission: Some(PresentationSubmissionMappingDTO {
                id: "25f5a42c-6850-49a0-b842-c7b2411021a5".to_string(),
                definition_id: "25f5a42c-6850-49a0-b842-c7b2411021a5".to_string(),
                descriptor_map: vec![PresentationSubmissionDescriptorDTO {
                    id: "input_0".to_string(),
                    format: "jwt_vp_json".to_string(),
                    path: "$".to_string(),
                    path_nested: Some(NestedPresentationSubmissionDescriptorDTO {
                        format: "jwt_vc_json".to_string(),
                        path: "$.vp.verifiableCredential[0]".to_string(),
                    }),
                }],
            }),
            vp_token: Some("vp_token".to_string()),
            state: Some("a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap()),
            response: None,
        })
        .await;

    assert!(result.is_err_and(|x| matches!(
        x,
        ServiceError::ConfigValidationError(ConfigValidationError::InvalidType(_, _))
    )));
}

fn generic_detail_credential() -> DetailCredential {
    let holder_did: DidValue = "did:holder".parse().unwrap();
    let issuer_did: DidValue = "did:issuer".parse().unwrap();

    DetailCredential {
        id: None,
        issued_at: Some(OffsetDateTime::now_utc()),
        expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
        update_at: None,
        invalid_before: Some(OffsetDateTime::now_utc()),
        issuer_did: Some(issuer_did),
        subject: Some(holder_did),
        claims: CredentialSubject {
            values: HashMap::new(),
        },
        status: vec![],
        credential_schema: None,
    }
}

fn generic_proof_input_schema() -> ProofInputSchema {
    let now = OffsetDateTime::now_utc();

    ProofInputSchema {
        validity_constraint: Some(100),
        claim_schemas: None,
        credential_schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "None".to_string(),
            wallet_storage_type: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "".to_string(),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            claim_schemas: None,
            organisation: None,
        }),
    }
}

#[test]
fn test_validate_claims_success_nested_claims() {
    let mut detail_credential = generic_detail_credential();
    detail_credential.claims.values = HashMap::from([(
        "location".to_string(),
        json!({
            "X": "123",
            "Y": "456"
        }),
    )]);

    let mut proof_input_schema = generic_proof_input_schema();
    proof_input_schema.claim_schemas = Some(vec![
        ProofInputClaimSchema {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location/X".to_owned(),
                data_type: "STRING".to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            },
            required: true,
            order: 0,
        },
        ProofInputClaimSchema {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location/Y".to_owned(),
                data_type: "STRING".to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            },
            required: true,
            order: 0,
        },
    ]);

    validate_claims(detail_credential, &proof_input_schema).unwrap();
}

#[test]
fn test_validate_claims_failed_malformed_claim() {
    let mut detail_credential = generic_detail_credential();
    detail_credential.claims.values = HashMap::from([(
        "location/".to_string(),
        json!({
            "X": "123",
            "Y": "456"
        }),
    )]);

    let mut proof_input_schema = generic_proof_input_schema();
    proof_input_schema.claim_schemas = Some(vec![
        ProofInputClaimSchema {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location/X".to_owned(),
                data_type: "STRING".to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            },
            required: true,
            order: 0,
        },
        ProofInputClaimSchema {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location/Y".to_owned(),
                data_type: "STRING".to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            },
            required: true,
            order: 0,
        },
    ]);

    matches!(
        validate_claims(detail_credential, &proof_input_schema,).unwrap_err(),
        ServiceError::OpenID4VCError(OpenID4VCIError::InvalidRequest)
    );
}

#[tokio::test]
async fn test_get_client_metadata_success() {
    let mut proof_repository = MockProofRepository::default();
    let mut key_algorithm = MockKeyAlgorithm::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let now = OffsetDateTime::now_utc();
    let proof_id = Uuid::new_v4();
    let proof = Proof {
        id: proof_id,
        created_date: now,
        last_modified: now,
        issuance_date: now,
        exchange: "OPENID4VC".to_string(),
        redirect_uri: None,
        state: Some(vec![ProofState {
            created_date: now,
            last_modified: now,
            state: ProofStateEnum::Pending,
        }]),
        schema: None,
        claims: None,
        verifier_did: Some(Did {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb966")
                .unwrap()
                .into(),
            created_date: now,
            last_modified: now,
            name: "did1".to_string(),
            organisation: Some(Organisation {
                id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                    .unwrap()
                    .into(),
                created_date: now,
                last_modified: now,
            }),
            did: "did1".parse().unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: Some(vec![RelatedKey {
                role: KeyRole::KeyAgreement,
                key: Key {
                    id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                        .unwrap()
                        .into(),
                    created_date: now,
                    last_modified: now,
                    public_key: vec![],
                    name: "verifier_key1".to_string(),
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
    {
        proof_repository
            .expect_get_proof()
            .times(1)
            .return_once(move |_, _| Ok(Some(proof)));

        key_algorithm.expect_bytes_to_jwk().return_once(|_, _| {
            Ok(PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
                r#use: Some("enc".to_string()),
                crv: "123".to_string(),
                x: "456".to_string(),
                y: None,
            }))
        });
        key_algorithm_provider
            .expect_get_key_algorithm()
            .return_once(|_| Some(Arc::new(key_algorithm)));
    }
    let service = setup_service(Mocks {
        key_algorithm_provider,
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service.oidc_get_client_metadata(proof_id).await.unwrap();
    assert_eq!(
        OpenID4VPClientMetadata {
            jwks: vec![OpenID4VPClientMetadataJwkDTO {
                key_id: "c322aa7f-9803-410d-b891-939b279fb965".parse().unwrap(),
                jwk: PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
                    r#use: Some("enc".to_string()),
                    crv: "123".to_string(),
                    x: "456".to_string(),
                    y: None,
                }),
            }],
            vp_formats: HashMap::from([
                (
                    "jwt_vp_json".to_string(),
                    OpenID4VPFormat {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    }
                ),
                (
                    "ldp_vc".to_string(),
                    OpenID4VPFormat {
                        alg: vec![
                            "EdDSA".to_string(),
                            "ES256".to_string(),
                            "BLS12-381G1-SHA256".to_string()
                        ]
                    }
                ),
                (
                    "vc+sd-jwt".to_string(),
                    OpenID4VPFormat {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    }
                ),
                (
                    "jwt_vc_json".to_string(),
                    OpenID4VPFormat {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    }
                ),
                (
                    "mso_mdoc".to_string(),
                    OpenID4VPFormat {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    }
                ),
                (
                    "ldp_vp".to_string(),
                    OpenID4VPFormat {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    }
                ),
            ]),
            client_id_scheme: "redirect_uri".to_string(),
            authorization_encrypted_response_alg: Some(
                AuthorizationEncryptedResponseAlgorithm::EcdhEs
            ),
            authorization_encrypted_response_enc: Some(
                AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM
            ),
        },
        result
    );
}

#[tokio::test]
async fn test_for_mdoc_schema_pre_authorized_grant_type_creates_refresh_token() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut crypto_provider = MockCryptoProvider::new();

    let mut schema = generic_credential_schema();
    schema.format = "MDOC".to_string();

    credential_schema_repository
        .expect_get_credential_schema()
        .once()
        .with(
            eq(schema.id.to_owned()),
            eq(CredentialSchemaRelations::default()),
        )
        .return_once({
            let schema = schema.clone();
            move |_, _| Ok(Some(schema))
        });

    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| {
            Ok(vec![dummy_credential(
                "OPENID4VC",
                CredentialStateEnum::Pending,
                false,
            )])
        });

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_| Ok(()));

    interaction_repository
        .expect_update_interaction()
        .once()
        .return_once(|_| Ok(()));

    crypto_provider
        .expect_generate_alphanumeric()
        .once()
        .with(predicate::eq(32))
        .return_once(|_| "abcdefghijklmnopqrstuvwxyzABCDEF".to_string());

    let service = setup_service(Mocks {
        credential_schema_repository,
        credential_repository,
        interaction_repository,
        crypto_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
            },
        )
        .await;

    let result = result.unwrap();
    assert_eq!("bearer", result.token_type);
    assert_eq!(
        "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
        result.access_token
    );

    assert_eq!(
        Some("c62f4237-3c74-42f2-a5ff-c72489e025f7.abcdefghijklmnopqrstuvwxyzABCDEF"),
        result.refresh_token.as_deref()
    );
    assert!(result.refresh_token_expires_in.is_some());
}

#[tokio::test]
async fn test_valid_refresh_token_grant_type_creates_refresh_and_tokens() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut crypto_provider = MockCryptoProvider::new();

    let schema = generic_credential_schema();

    credential_schema_repository
        .expect_get_credential_schema()
        .once()
        .with(
            eq(schema.id.to_owned()),
            eq(CredentialSchemaRelations::default()),
        )
        .return_once({
            let schema = schema.clone();
            move |_, _| Ok(Some(schema))
        });

    let interaction_id: Uuid = "c62f4237-3c74-42f2-a5ff-c72489e025f7".parse().unwrap();
    let refresh_token = "c62f4237-3c74-42f2-a5ff-c72489e025f7.AAAAA";
    let refresh_token_expires_at = "2077-10-28T07:03:38.4404734Z";
    let credential = Credential {
        interaction: Some(dummy_interaction(
            false,
            None,
            Some(refresh_token),
            Some(refresh_token_expires_at),
        )),
        ..dummy_credential("OPENID4VC", CredentialStateEnum::Accepted, false)
    };

    credential_repository
        .expect_get_credentials_by_interaction_id()
        .withf(move |interaction_id_, _| *interaction_id_ == interaction_id)
        .once()
        .return_once(move |_, _| Ok(vec![credential]));

    interaction_repository
        .expect_update_interaction()
        .once()
        .return_once(|_| Ok(()));

    crypto_provider
        .expect_generate_alphanumeric()
        .once()
        .with(predicate::eq(32))
        .return_once(|_| "1ABC".to_string());
    crypto_provider
        .expect_generate_alphanumeric()
        .once()
        .with(predicate::eq(32))
        .return_once(|_| "2ABC".to_string());

    let service = setup_service(Mocks {
        credential_schema_repository,
        credential_repository,
        interaction_repository,
        crypto_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::RefreshToken {
                refresh_token: refresh_token.to_string(),
            },
        )
        .await
        .unwrap();

    assert_eq!("bearer", result.token_type);
    assert_eq!(
        "c62f4237-3c74-42f2-a5ff-c72489e025f7.1ABC",
        result.access_token
    );

    assert_eq!(
        Some("c62f4237-3c74-42f2-a5ff-c72489e025f7.2ABC"),
        result.refresh_token.as_deref()
    );
    assert!(result.refresh_token_expires_in.is_some());
}

#[tokio::test]
async fn test_refresh_token_request_fails_if_refresh_token_is_expired() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();

    let schema = generic_credential_schema();

    credential_schema_repository
        .expect_get_credential_schema()
        .once()
        .with(
            eq(schema.id.to_owned()),
            eq(CredentialSchemaRelations::default()),
        )
        .return_once({
            let schema = schema.clone();
            move |_, _| Ok(Some(schema))
        });

    let interaction_id: Uuid = "c62f4237-3c74-42f2-a5ff-c72489e025f7".parse().unwrap();
    let refresh_token = "c62f4237-3c74-42f2-a5ff-c72489e025f7.AAAAA";
    // expired refresh token
    let refresh_token_expires_at = "2023-10-28T07:03:38.4404734Z";
    let credential = Credential {
        interaction: Some(dummy_interaction(
            false,
            None,
            Some(refresh_token),
            Some(refresh_token_expires_at),
        )),
        ..dummy_credential("OPENID4VC", CredentialStateEnum::Accepted, false)
    };

    credential_repository
        .expect_get_credentials_by_interaction_id()
        .withf(move |interaction_id_, _| *interaction_id_ == interaction_id)
        .once()
        .return_once(move |_, _| Ok(vec![credential]));

    let service = setup_service(Mocks {
        credential_schema_repository,
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::RefreshToken {
                refresh_token: refresh_token.to_string(),
            },
        )
        .await
        .err()
        .unwrap();

    assert2::assert!(let ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken) = result);
}
