use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use indexmap::IndexMap;
use mockall::predicate::{always, eq};
use serde_json::json;
use shared_types::{DidId, DidValue, KeyId, ProofId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, CredentialSchemaType,
    LayoutType, WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::interaction::Interaction;
use crate::model::key::{Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, Presentation,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::exchange_protocol::openid4vc::error::{OpenID4VCError, OpenID4VCIError};
use crate::provider::exchange_protocol::openid4vc::model::*;
use crate::provider::exchange_protocol::provider::MockExchangeProtocolProviderExtra;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::model::CredentialRevocationState;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::error::ServiceError;
use crate::service::key::dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO};
use crate::service::oidc::OIDCService;
use crate::service::test_utilities::*;

#[derive(Default)]
struct Mocks {
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub credential_repository: MockCredentialRepository,
    pub proof_repository: MockProofRepository,
    pub interaction_repository: MockInteractionRepository,
    pub key_repository: MockKeyRepository,
    pub key_provider: MockKeyProvider,
    pub config: CoreConfig,
    pub exchange_provider: MockExchangeProtocolProviderExtra,
    pub did_repository: MockDidRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub validity_credential_repository: MockValidityCredentialRepository,
}

#[allow(clippy::too_many_arguments)]
fn setup_service(mocks: Mocks) -> OIDCService {
    OIDCService::new(
        Some("http://127.0.0.1:3000".to_string()),
        Arc::new(mocks.credential_schema_repository),
        Arc::new(mocks.credential_repository),
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
        Arc::new(mocks.validity_credential_repository),
    )
}

fn generic_credential_schema() -> CredentialSchema {
    let now = OffsetDateTime::now_utc();
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: now,
        last_modified: now,
        name: "SchemaName".to_string(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        format: "JWT".to_string(),
        external_schema: false,
        revocation_method: "".to_string(),
        claim_schemas: Some(vec![CredentialSchemaClaim {
            required: true,
            schema: ClaimSchema {
                array: false,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data_type: "STRING".to_string(),
                key: "key".to_string(),
                id: Uuid::new_v4().into(),
            },
        }]),
        organisation: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
    }
}

fn dummy_interaction(
    id: Option<Uuid>,
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
        id: id.unwrap_or(Uuid::new_v4()),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        host: Some("http://host-base-url".parse().unwrap()),
        data: Some(data.to_string().into_bytes()),
        organisation: None,
    }
}

fn dummy_credential(
    protocol: &str,
    state: CredentialStateEnum,
    pre_authroized_code: bool,
    schema: Option<CredentialSchema>,
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
        state,
        suspend_end_date: None,
        claims: None,
        issuer_did: None,
        holder_did: None,
        schema,
        interaction: Some(dummy_interaction(
            None,
            pre_authroized_code,
            None,
            None,
            None,
        )),
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
    let result = service.oidc_issuer_get_issuer_metadata(&schema.id).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    let credential = result.credential_configurations_supported[0].to_owned();
    assert_eq!("jwt_vc_json".to_string(), credential.format);
    assert_eq!(schema.name, credential.display.unwrap()[0].name);
    assert!(credential.claims.is_none()); // This is present of mdoc only
    let credential_definition = credential.credential_definition.as_ref().unwrap();
    assert!(credential_definition
        .r#type
        .contains(&"VerifiableCredential".to_string()));
    assert!(credential_definition
        .r#credential_subject
        .as_ref()
        .unwrap()
        .claims
        .as_ref()
        .unwrap()
        .get("key")
        .is_some());
}

#[tokio::test]
async fn test_get_issuer_metadata_sd_jwt() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();

    let mut schema = generic_credential_schema();
    schema.format = "SD_JWT".to_string();
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
    let result = service
        .oidc_issuer_get_issuer_metadata(&schema.id)
        .await
        .unwrap();
    let credential = result.credential_configurations_supported[0].to_owned();
    assert_eq!("vc+sd-jwt".to_string(), credential.format);
    assert_eq!(schema.name, credential.display.unwrap()[0].name);
    assert!(credential.claims.is_none()); // This is present of mdoc only
    let credential_definition = credential.credential_definition.as_ref().unwrap();
    assert!(credential_definition
        .r#type
        .contains(&"VerifiableCredential".to_string()));
    assert!(credential_definition
        .r#credential_subject
        .as_ref()
        .unwrap()
        .claims
        .as_ref()
        .unwrap()
        .get("key")
        .is_some());
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
    let result = service
        .oidc_issuer_get_issuer_metadata(&schema.id)
        .await
        .unwrap();
    let credential = result.credential_configurations_supported[0].to_owned();
    assert_eq!("mso_mdoc".to_string(), credential.format);
    assert_eq!(schema.name, credential.display.unwrap()[0].name);
    let claims = credential.claims.unwrap();
    assert_eq!(
        IndexMap::from([(
            "location".to_string(),
            OpenID4VCICredentialSubjectItem {
                claims: Some(IndexMap::from([(
                    "X".to_string(),
                    OpenID4VCICredentialSubjectItem {
                        value_type: Some("string".to_string()),
                        mandatory: Some(true),
                        ..Default::default()
                    }
                )])),
                ..Default::default()
            }
        )]),
        claims
    );
    assert!(credential.credential_definition.is_none()); // Invalid for mdoc
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
    let result = service.oidc_issuer_service_discovery(&schema.id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_oidc_issuer_create_token() {
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

        let clone = schema.clone();
        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(
                    "OPENID4VC",
                    CredentialStateEnum::Pending,
                    false,
                    Some(clone),
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
        .oidc_issuer_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
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
async fn test_oidc_issuer_create_token_empty_pre_authorized_code() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .with(
                eq(schema.id.to_owned()),
                eq(CredentialSchemaRelations::default()),
            )
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let service = setup_service(Mocks {
        config: generic_config().core,
        credential_schema_repository,
        ..Default::default()
    });
    let result = service
        .oidc_issuer_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "".to_string(),
                tx_code: None,
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(OpenID4VCError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest
        )))
    ));
}

#[tokio::test]
async fn test_oidc_issuer_create_token_pre_authorized_code_used() {
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

        let clone = schema.clone();
        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(
                    "OPENID4VC",
                    CredentialStateEnum::Pending,
                    true,
                    Some(clone),
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
        .oidc_issuer_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(OpenID4VCError::OpenID4VCI(
            OpenID4VCIError::InvalidGrant
        )))
    ));
}

#[tokio::test]
async fn test_oidc_issuer_create_token_wrong_credential_state() {
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

        let clone = schema.clone();
        credential_repository
            .expect_get_credentials_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(vec![dummy_credential(
                    "OPENID4VC",
                    CredentialStateEnum::Offered,
                    false,
                    Some(clone),
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
        .oidc_issuer_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCError(
            OpenID4VCError::InvalidCredentialState { .. }
        ))
    ));
}

#[tokio::test]
async fn test_oidc_issuer_create_credential_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut exchange_provider = MockExchangeProtocolProviderExtra::default();
    let mut did_repository = MockDidRepository::default();
    let now = OffsetDateTime::now_utc();

    let schema = generic_credential_schema();
    let credential = dummy_credential(
        "OPENID4VC",
        CredentialStateEnum::Pending,
        true,
        Some(schema.clone()),
    );
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
            .return_once(|_, _| Ok(Some(dummy_interaction(None, true, None, None, None))));

        exchange_provider
            .expect_issue_credential()
            .once()
            .return_once(|_, _, _| {
                Ok(SubmitIssuerResponse {
                    credential: "xyz".to_string(),
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
        .oidc_issuer_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
                }),
                doctype: None,
                proof: OpenID4VCIProofRequestDTO {
                    proof_type: "jwt".to_string(),
                    jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6MTIzNCJ9.eyJhdWQiOiIxMjM0NTY3ODkwIn0.y9vUcoVsVgIt96oO28qpyCqCpc2Mr2Qztligw2PBaYI".to_string(),
                },
            },
        )
        .await;

    //assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!("xyz", result.credential);
}

#[tokio::test]
async fn test_oidc_issuer_create_credential_success_mdoc() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut exchange_provider = MockExchangeProtocolProviderExtra::default();
    let mut did_repository = MockDidRepository::default();
    let now = OffsetDateTime::now_utc();

    let schema = CredentialSchema {
        format: "MDOC".to_string(),
        schema_id: "test.doctype".to_owned(),
        ..generic_credential_schema()
    };
    let credential = dummy_credential(
        "OPENID4VC",
        CredentialStateEnum::Pending,
        true,
        Some(schema.clone()),
    );
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
            .return_once(|_, _| Ok(Some(dummy_interaction(None, true, None, None, None))));

        exchange_provider
            .expect_issue_credential()
            .once()
            .return_once(|_, _, _| {
                Ok(SubmitIssuerResponse {
                    credential: "xyz".to_string(),
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
        .oidc_issuer_create_credential(
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
    assert_eq!("xyz", result.credential);
}

#[tokio::test]
async fn test_oidc_issuer_create_credential_format_invalid() {
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
        .oidc_issuer_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "some_string".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
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
        Err(ServiceError::OpenID4VCError(OpenID4VCError::OpenID4VCI(
            OpenID4VCIError::UnsupportedCredentialFormat
        )))
    ));
}

#[tokio::test]
async fn test_oidc_issuer_create_credential_format_invalid_for_credential_schema() {
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
        .oidc_issuer_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "vc+sd-jwt".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
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
        Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::UnsupportedCredentialFormat
        ))
    ));
}

#[tokio::test]
async fn test_oidc_issuer_create_credential_format_invalid_credential_definition() {
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
        .oidc_issuer_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["some string".to_string()],
                    credential_subject: None,
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
        Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::UnsupportedCredentialType
        ))
    ));
}

#[tokio::test]
async fn test_oidc_issuer_create_credential_format_invalid_bearer_token() {
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
        .oidc_issuer_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
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
        Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidToken))
    ));
}

#[tokio::test]
async fn test_oidc_issuer_create_credential_pre_authorized_code_not_used() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let exchange_provider = MockExchangeProtocolProviderExtra::default();

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
            .return_once(|_, _| Ok(Some(dummy_interaction(None, false, None, None, None))));
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
        .oidc_issuer_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
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
        Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidToken))
    ));
}

#[tokio::test]
async fn test_oidc_issuer_create_credential_interaction_data_invalid() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let exchange_provider = MockExchangeProtocolProviderExtra::default();

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
            .return_once(|_, _| Ok(Some(dummy_interaction(None, true, None, None, None))));
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
        .oidc_issuer_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.123",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
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
        Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidToken))
    ));
}

#[tokio::test]
async fn test_oidc_issuer_create_credential_access_token_expired() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let exchange_provider = MockExchangeProtocolProviderExtra::default();

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
                    None,
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
        .oidc_issuer_create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                format: "jwt_vc_json".to_string(),
                credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
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
        Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidToken))
    ));
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

    let proof_id: ProofId = Uuid::new_v4().into();

    let interaction_data = serde_json::to_vec(&OpenID4VPVerifierInteractionContent {
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
                    limit_disclosure: None,
                },
            }],
        },
        client_id: "client_id".to_string(),
        client_id_scheme: None,
        response_uri: None,
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
                    transport: "HTTP".to_string(),
                    redirect_uri: None,
                    state: ProofStateEnum::Pending,
                    role: ProofRole::Verifier,
                    requested_date: Some(get_dummy_date()),
                    completed_date: None,
                    schema: Some(ProofSchema {
                        id: Uuid::default().into(),
                        created_date: now,
                        imported_source_url: Some("CORE_URL".to_string()),
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
                                imported_source_url: "CORE_URL".to_string(),
                                deleted_at: None,
                                created_date: get_dummy_date(),
                                last_modified: get_dummy_date(),
                                external_schema: false,
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
                                allow_suspension: true,
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
                        organisation: None,
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
async fn test_submit_proof_failed_credential_suspended() {
    let proof_id: ProofId = Uuid::new_v4().into();
    let verifier_did = "did:verifier:123".parse().unwrap();
    let holder_did: DidValue = "did:holder:123".parse().unwrap();
    let issuer_did: DidValue = "did:issuer:123".parse().unwrap();

    let mut proof_repository = MockProofRepository::new();

    let interaction_id = Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36").unwrap();

    let nonce = "7QqBfOcEcydceH6ZrXtu9fhDCvXjtLBv".to_string();

    let claim_id = Uuid::new_v4().into();
    let credential_schema = dummy_credential_schema();
    let interaction_data = OpenID4VPVerifierInteractionContent {
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
                    limit_disclosure: None,
                },
            }],
        },
        client_id: "client_id".to_string(),
        client_id_scheme: None,
        response_uri: None,
    };
    let interaction_data_serialized = serde_json::to_vec(&interaction_data).unwrap();
    let now = OffsetDateTime::now_utc();
    let interaction = Interaction {
        id: interaction_id.to_owned(),
        created_date: now,
        last_modified: now,
        host: None,
        data: Some(interaction_data_serialized),
        organisation: None,
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
                state: ProofStateEnum::Pending,
                schema: Some(ProofSchema {
                    input_schemas: Some(vec![ProofInputSchema {
                        validity_constraint: None,
                        claim_schemas: Some(vec![
                            ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    id: shared_types::ClaimSchemaId::from(Into::<Uuid>::into(
                                        claim_id,
                                    )),
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
                    organisation: Some(Organisation {
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                    }),
                    ..dummy_proof_schema()
                }),
                interaction: Some(interaction),
                ..dummy_proof_with_protocol("OPENID4VC")
            }))
        });

    proof_repository
        .expect_update_proof()
        .withf(move |_proof_id, _, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .returning(|_, _, _| Ok(()));

    let mut formatter = MockCredentialFormatter::new();

    let holder_did_clone = holder_did.clone();
    let issuer_did_clone = issuer_did.clone();
    formatter
        .expect_extract_credentials_unverified()
        .once()
        .returning(move |_| {
            Ok(DetailCredential {
                id: None,
                valid_from: Some(OffsetDateTime::now_utc()),
                valid_until: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did_clone.to_owned()),
                claims: CredentialSubject {
                    claims: HashMap::from([
                        ("unknown_key".to_string(), json!("unknown_key_value")),
                        ("required_key".to_string(), json!("required_key_value")),
                    ]),
                    id: None,
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
        .returning(move |_, _, _| {
            Ok(DetailCredential {
                id: None,
                valid_from: Some(OffsetDateTime::now_utc()),
                valid_until: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did.to_owned()),
                claims: CredentialSubject {
                    claims: HashMap::from([
                        ("unknown_key".to_string(), json!("unknown_key_value")),
                        ("required_key".to_string(), json!("required_key_value")),
                    ]),
                    id: None,
                },
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
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
        .return_once(|_, _, _, _| {
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
        ServiceError::OpenID4VCError(OpenID4VCError::CredentialIsRevokedOrSuspended)
    ));
}

#[tokio::test]
async fn test_submit_proof_incorrect_protocol() {
    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(Some(dummy_proof_with_protocol("OPENID4VC"))));

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
        ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest)
    )));
}

#[tokio::test]
async fn test_get_client_metadata_success() {
    let mut proof_repository = MockProofRepository::default();
    let mut key_algorithm = MockKeyAlgorithm::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let now = OffsetDateTime::now_utc();
    let proof_id: ProofId = Uuid::new_v4().into();
    let proof = Proof {
        id: proof_id,
        created_date: now,
        last_modified: now,
        issuance_date: now,
        exchange: "OPENID4VC".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Pending,
        role: ProofRole::Holder,
        requested_date: Some(now),
        completed_date: None,
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
            did: "did:example:1".parse().unwrap(),
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

        key_algorithm
            .expect_reconstruct_key()
            .return_once(|_, _, _| {
                let mut key_handle = MockSignaturePublicKeyHandle::default();
                key_handle.expect_as_jwk().return_once(|| {
                    Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                        r#use: Some("enc".to_string()),
                        kid: None,
                        crv: "123".to_string(),
                        x: "456".to_string(),
                        y: None,
                    }))
                });
                Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                    Arc::new(key_handle),
                )))
            });

        key_algorithm_provider
            .expect_key_algorithm_from_name()
            .return_once(|_| Some(Arc::new(key_algorithm)));
    }
    let service = setup_service(Mocks {
        key_algorithm_provider,
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service
        .oidc_verifier_get_client_metadata(proof_id)
        .await
        .unwrap();
    assert_eq!(
        OpenID4VPClientMetadata {
            jwks: OpenID4VPClientMetadataJwks {
                keys: vec![OpenID4VPClientMetadataJwkDTO {
                    key_id: "c322aa7f-9803-410d-b891-939b279fb965"
                        .parse::<Uuid>()
                        .unwrap()
                        .into(),
                    jwk: PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
                        r#use: Some("enc".to_string()),
                        kid: None,
                        crv: "123".to_string(),
                        x: "456".to_string(),
                        y: None,
                    }),
                }]
            },
            vp_formats: HashMap::from([
                (
                    "jwt_vp_json".to_string(),
                    OpenID4VPFormat::JwtVpJson(OpenID4VPJwtVpJson {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    })
                ),
                (
                    "ldp_vc".to_string(),
                    OpenID4VPFormat::JwtVpJson(OpenID4VPJwtVpJson {
                        alg: vec![
                            "EdDSA".to_string(),
                            "ES256".to_string(),
                            "BLS12-381G1-SHA256".to_string()
                        ]
                    })
                ),
                (
                    "vc+sd-jwt".to_string(),
                    OpenID4VPFormat::JwtVpJson(OpenID4VPJwtVpJson {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    })
                ),
                (
                    "jwt_vc_json".to_string(),
                    OpenID4VPFormat::JwtVpJson(OpenID4VPJwtVpJson {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    })
                ),
                (
                    "mso_mdoc".to_string(),
                    OpenID4VPFormat::JwtVpJson(OpenID4VPJwtVpJson {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    })
                ),
                (
                    "ldp_vp".to_string(),
                    OpenID4VPFormat::JwtVpJson(OpenID4VPJwtVpJson {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    })
                ),
            ]),
            authorization_encrypted_response_alg: Some(
                AuthorizationEncryptedResponseAlgorithm::EcdhEs
            ),
            authorization_encrypted_response_enc: Some(
                AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM
            ),
            ..Default::default()
        },
        result
    );
}

#[tokio::test]
async fn test_for_mdoc_schema_pre_authorized_grant_type_creates_refresh_token() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

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

    let clone = schema.clone();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| {
            Ok(vec![dummy_credential(
                "OPENID4VC",
                CredentialStateEnum::Pending,
                false,
                Some(clone),
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

    let service = setup_service(Mocks {
        credential_schema_repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_issuer_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
        )
        .await;

    let result = result.unwrap();
    assert_eq!("bearer", result.token_type);
    assert_eq!(
        "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
        result.access_token
    );

    assert!(result
        .refresh_token
        .unwrap()
        .starts_with("c62f4237-3c74-42f2-a5ff-c72489e025f7."));

    assert!(result.refresh_token_expires_in.is_some());
}

#[tokio::test]
async fn test_valid_refresh_token_grant_type_creates_refresh_and_tokens() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

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
            Some(interaction_id),
            false,
            None,
            Some(refresh_token),
            Some(refresh_token_expires_at),
        )),
        ..dummy_credential(
            "OPENID4VC",
            CredentialStateEnum::Accepted,
            false,
            Some(schema.clone()),
        )
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

    let service = setup_service(Mocks {
        credential_schema_repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .oidc_issuer_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::RefreshToken {
                refresh_token: refresh_token.to_string(),
            },
        )
        .await
        .unwrap();

    assert_eq!("bearer", result.token_type);
    assert!(result
        .access_token
        .starts_with("c62f4237-3c74-42f2-a5ff-c72489e025f7."));

    assert!(result
        .refresh_token
        .unwrap()
        .starts_with("c62f4237-3c74-42f2-a5ff-c72489e025f7."));

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
            Some(interaction_id),
            false,
            None,
            Some(refresh_token),
            Some(refresh_token_expires_at),
        )),
        ..dummy_credential(
            "OPENID4VC",
            CredentialStateEnum::Accepted,
            false,
            Some(schema.clone()),
        )
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
        .oidc_issuer_create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::RefreshToken {
                refresh_token: refresh_token.to_string(),
            },
        )
        .await
        .err()
        .unwrap();

    assert2::assert!(let ServiceError::OpenID4VCError(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidToken)) = result);
}

#[tokio::test]
async fn test_verify_submission_incorrect_decryption_key_fails() {
    let service = setup_service(Mocks {
        ..Default::default()
    });

    let mut proof = dummy_proof_with_protocol("OPENID4VC");

    let key_id1 = KeyId::from(Uuid::new_v4());
    let key_id2 = KeyId::from(Uuid::new_v4());
    let state = Uuid::new_v4();

    proof.verifier_key = Some(Key {
        id: key_id1,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: vec![],
        name: "key1".to_string(),
        key_reference: vec![],
        storage_type: "".to_string(),
        key_type: "".to_string(),
        organisation: None,
    });

    let uncecked_request = RequestData {
        encryption_key: Some(key_id2),
        mdoc_generated_nonce: None,
        presentation_submission: PresentationSubmissionMappingDTO {
            id: "id".to_string(),
            definition_id: "definition_id".to_string(),
            descriptor_map: vec![],
        },
        state,
        vp_token: "vp_token".to_string(),
    };

    let result = service
        .oidc_verifier_verify_submission(proof, uncecked_request)
        .await;

    assert!(matches!(
        result.unwrap_err(),
        ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest)
    ));
}
