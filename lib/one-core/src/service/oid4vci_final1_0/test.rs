use std::str::FromStr;
use std::sync::Arc;

use mockall::predicate::{always, eq};
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use secrecy::ExposeSecret;
use serde_json::json;
use shared_types::{CredentialFormat, DidId, InteractionId};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::OID4VCIFinal1_0Service;
use crate::config::core_config::{CoreConfig, KeyAlgorithmType};
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, KeyStorageSecurity,
    LayoutType,
};
use crate::model::did::Did;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::identifier_creator::{MockIdentifierCreator, RemoteIdentifierRelation};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::wallet_unit::MockHolderWalletUnitProto;
use crate::provider::blob_storage_provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::issuance_protocol::MockIssuanceProtocol;
use crate::provider::issuance_protocol::error::{
    IssuanceProtocolError, OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::model::SubmitIssuerResponse;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::*;
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::error::DataLayerError;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::service::error::ServiceError;
use crate::service::test_utilities::*;

#[derive(Default)]
struct Mocks {
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub credential_repository: MockCredentialRepository,
    pub interaction_repository: MockInteractionRepository,
    pub config: CoreConfig,
    pub exchange_provider: MockIssuanceProtocolProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub certificate_validator: MockCertificateValidator,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub holder_wallet_unit_proto: MockHolderWalletUnitProto,
    pub identifier_creator: MockIdentifierCreator,
}

fn setup_service(mocks: Mocks) -> OID4VCIFinal1_0Service {
    OID4VCIFinal1_0Service::new(
        Some("http://127.0.0.1:3000".to_string()),
        "OPENID4VCI_FINAL1".to_string(),
        Arc::new(mocks.credential_schema_repository),
        Arc::new(mocks.credential_repository),
        Arc::new(mocks.interaction_repository),
        Arc::new(mocks.config),
        Arc::new(mocks.exchange_provider),
        Arc::new(mocks.did_method_provider),
        Arc::new(mocks.key_algorithm_provider),
        Arc::new(mocks.formatter_provider),
        Arc::new(mocks.revocation_method_provider),
        Arc::new(mocks.certificate_validator),
        Arc::new(mocks.blob_storage_provider),
        Arc::new(NoTransactionManager),
        Arc::new(mocks.holder_wallet_unit_proto),
        Arc::new(mocks.identifier_creator),
    )
}

fn generic_organisation() -> Organisation {
    let now = OffsetDateTime::now_utc();
    Organisation {
        id: Uuid::new_v4().into(),
        name: "organisation name".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        wallet_provider: None,
        wallet_provider_issuer: None,
    }
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
        key_storage_security: Some(KeyStorageSecurity::Basic),
        format: "JWT".into(),
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
                metadata: false,
            },
        }]),
        organisation: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
        requires_app_attestation: false,
    }
}

fn dummy_interaction(
    id: Option<InteractionId>,
    pre_authorized_code: bool,
    access_token_expires_at: Option<&str>,
    refresh_token: Option<&str>,
    refresh_token_expires_at: Option<&str>,
) -> Interaction {
    let mut data = json!({
        "pre_authorized_code_used": pre_authorized_code,
        "access_token_hash": id.map(|id| SHA256.hash(format!("{id}.asdfasdfasdf").as_bytes()).unwrap()).unwrap_or_default(),
        "access_token_expires_at": access_token_expires_at.unwrap_or("2099-10-28T07:03:38.4404734Z"),
    });

    if let Some(refresh_token) = refresh_token {
        data.as_object_mut().unwrap().insert(
            "refresh_token_hash".to_string(),
            json!(SHA256.hash(refresh_token.as_bytes()).unwrap()),
        );
    }

    if let Some(refresh_token_expires_at) = refresh_token_expires_at {
        data.as_object_mut().unwrap().insert(
            "refresh_token_expires_at".to_string(),
            json!(refresh_token_expires_at),
        );
    }

    Interaction {
        id: id.unwrap_or(Uuid::new_v4().into()),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        data: Some(data.to_string().into_bytes()),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    }
}

fn dummy_credential(
    protocol: &str,
    state: CredentialStateEnum,
    pre_authorized_code: bool,
    schema: Option<CredentialSchema>,
) -> Credential {
    Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: protocol.to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state,
        suspend_end_date: None,
        claims: None,
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema,
        interaction: Some(dummy_interaction(
            None,
            pre_authorized_code,
            None,
            None,
            None,
        )),
        key: None,
        profile: None,
        credential_blob_id: Some(Uuid::new_v4().into()),
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    }
}

fn mock_key_algorithm() -> Arc<dyn KeyAlgorithm> {
    let mut algorithm = MockKeyAlgorithm::new();
    algorithm
        .expect_algorithm_type()
        .returning(|| KeyAlgorithmType::Eddsa);
    algorithm.expect_parse_jwk().returning(|_| {
        let mut handle = MockSignaturePublicKeyHandle::new();
        handle.expect_verify().returning(|_, _| Ok(()));
        Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
            Arc::new(handle),
        )))
    });
    Arc::new(algorithm)
}

#[tokio::test]
async fn test_get_issuer_metadata_jwt() {
    let mut did_method_provider = MockDidMethodProvider::default();
    did_method_provider
        .expect_supported_method_names()
        .return_once(|| vec!["key".to_string()]);
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_supported_verification_jose_alg_ids()
        .return_once(|| vec!["ES256".to_string()]);

    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_issuance_jose_alg_id()
        .return_once(|| Some("ES256".to_string()));

    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Ecdsa))
        .return_once(move |_| Some(Arc::new(key_algorithm)));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec![KeyAlgorithmType::Ecdsa],
            holder_identifier_types: vec![IdentifierType::Did.into()],
            ..Default::default()
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut repository = MockCredentialSchemaRepository::default();
    let mut schema = generic_credential_schema();
    schema.organisation = Some(generic_organisation());
    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        organisation: Some(OrganisationRelations::default()),
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
        did_method_provider,
        key_algorithm_provider,
        config: generic_config().core,
        formatter_provider,
        ..Default::default()
    });
    let result = service.get_issuer_metadata(&schema.id).await;
    assert!(result.is_ok());
    let result = result.unwrap();

    let credential_configuration = result.credential_configurations_supported[0].to_owned();
    assert_eq!("jwt_vc_json".to_string(), credential_configuration.format);
    assert_eq!(
        schema.name,
        credential_configuration
            .credential_metadata
            .as_ref()
            .unwrap()
            .display
            .as_ref()
            .unwrap()[0]
            .name
    );
    assert_eq!(
        credential_configuration
            .cryptographic_binding_methods_supported
            .unwrap(),
        vec!["did:key".to_string()]
    );
    assert_eq!(
        credential_configuration
            .proof_types_supported
            .unwrap()
            .get("jwt")
            .unwrap()
            .proof_signing_alg_values_supported,
        vec!["ES256".to_string()]
    );
    assert_eq!(
        credential_configuration
            .credential_signing_alg_values_supported
            .unwrap(),
        vec![CredentialSigningAlgValue::String("ES256".to_string())]
    );

    assert!(credential_configuration.vct.is_none());

    // Check that credential_metadata is properly structured
    if let Some(metadata) = &credential_configuration.credential_metadata {
        // For JWT format, claims should be in metadata
        assert!(metadata.claims.is_some());
    }
}

#[tokio::test]
async fn test_get_issuer_metadata_sd_jwt() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut did_method_provider = MockDidMethodProvider::default();
    did_method_provider
        .expect_supported_method_names()
        .return_once(|| vec!["key".to_string()]);
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_supported_verification_jose_alg_ids()
        .return_once(|| vec!["ES256".to_string()]);

    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_issuance_jose_alg_id()
        .return_once(|| Some("ES256".to_string()));

    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Ecdsa))
        .return_once(move |_| Some(Arc::new(key_algorithm)));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec![KeyAlgorithmType::Ecdsa],
            holder_identifier_types: vec![IdentifierType::Did.into(), IdentifierType::Key.into()],
            ..Default::default()
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("SD_JWT")))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut schema = generic_credential_schema();
    schema.organisation = Some(generic_organisation());
    schema.format = "SD_JWT".into();
    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        organisation: Some(OrganisationRelations::default()),
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
        did_method_provider,
        key_algorithm_provider,
        config: generic_config().core,
        formatter_provider,
        ..Default::default()
    });
    let result = service.get_issuer_metadata(&schema.id).await.unwrap();
    let credential = result.credential_configurations_supported[0].to_owned();
    assert_eq!("vc+sd-jwt".to_string(), credential.format);
    assert_eq!(
        schema.name,
        credential
            .credential_metadata
            .as_ref()
            .unwrap()
            .display
            .as_ref()
            .unwrap()[0]
            .name
    );
    // SD-JWT format should not have doctype (which is mdoc-specific)
    assert!(credential.doctype.is_none());
    assert_eq!(
        credential.cryptographic_binding_methods_supported.unwrap(),
        vec!["jwk".to_string(), "did:key".to_string()]
    );
    assert_eq!(
        credential
            .proof_types_supported
            .unwrap()
            .get("jwt")
            .unwrap()
            .proof_signing_alg_values_supported,
        vec!["ES256".to_string()]
    );
    assert_eq!(
        credential.credential_signing_alg_values_supported.unwrap(),
        vec![CredentialSigningAlgValue::String("ES256".to_string())]
    );
    // For SD-JWT, check vct field instead of credential_definition
    assert!(credential.vct.is_some());
}

#[tokio::test]
async fn test_get_issuer_metadata_mdoc() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut did_method_provider = MockDidMethodProvider::default();
    did_method_provider
        .expect_supported_method_names()
        .return_once(|| vec!["key".to_string()]);
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_supported_verification_jose_alg_ids()
        .return_once(|| vec!["ES256".to_string()]);

    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_issuance_jose_alg_id()
        .return_once(|| Some("ES256".to_string()));

    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Ecdsa))
        .return_once(move |_| Some(Arc::new(key_algorithm)));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec![KeyAlgorithmType::Ecdsa],
            holder_identifier_types: vec![IdentifierType::Did.into(), IdentifierType::Key.into()],
            ..Default::default()
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("MDOC")))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut schema = generic_credential_schema();
    schema.format = "MDOC".into();
    schema.organisation = Some(generic_organisation());
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
                metadata: false,
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
                metadata: false,
            },
            required: true,
        },
    ]);

    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        organisation: Some(OrganisationRelations::default()),
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
        did_method_provider,
        key_algorithm_provider,
        config: generic_config().core,
        formatter_provider,
        ..Default::default()
    });
    let result = service.get_issuer_metadata(&schema.id).await.unwrap();
    let credential = result.credential_configurations_supported[0].to_owned();
    assert_eq!("mso_mdoc".to_string(), credential.format);
    assert_eq!(
        schema.name,
        credential.credential_metadata.unwrap().display.unwrap()[0].name
    );
    assert_eq!(
        credential.cryptographic_binding_methods_supported.unwrap(),
        vec!["jwk".to_string(), "did:key".to_string()]
    );
    assert_eq!(
        credential
            .proof_types_supported
            .unwrap()
            .get("jwt")
            .unwrap()
            .proof_signing_alg_values_supported,
        vec!["ES256".to_string()]
    );
    // For mDoc format, we don't have credential_metadata with claims like JWT format
    // mDoc uses doctype and order fields instead
    assert!(credential.doctype.is_some());
    assert!(credential.vct.is_none()); // vct is not used for mdoc
}

#[tokio::test]
async fn test_create_token() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let schema = generic_credential_schema();

    let clone = schema.clone();
    repository
        .expect_get_credential_schema()
        .times(1)
        .with(
            eq(schema.id.to_owned()),
            eq(CredentialSchemaRelations::default()),
        )
        .returning(move |_, _| Ok(Some(clone.clone())));

    let credential = dummy_credential(
        "OPENID4VCI_FINAL1",
        CredentialStateEnum::Pending,
        false,
        Some(schema.clone()),
    );
    let interaction_id = credential.interaction.as_ref().unwrap().id;
    let interaction = credential.interaction.clone().unwrap();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![credential]));

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_, _| Ok(()));

    interaction_repository
        .expect_get_interaction()
        .once()
        .return_once(|_, _, _| Ok(Some(interaction)));

    interaction_repository
        .expect_update_interaction()
        .once()
        .return_once(|_, _| Ok(()));

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
            None,
            None,
        )
        .await;

    assert!(result.is_ok());

    let result_content = result.unwrap();
    assert_eq!("bearer", result_content.token_type);
    assert!(
        result_content
            .access_token
            .expose_secret()
            .starts_with(&format!("{interaction_id}."))
    );

    assert!(result_content.refresh_token.is_none());
    assert!(result_content.refresh_token_expires_in.is_none());
}

#[tokio::test]
async fn test_create_token_empty_pre_authorized_code() {
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
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "".to_string(),
                tx_code: None,
            },
            None,
            None,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenIDIssuanceError(
            OpenIDIssuanceError::OpenID4VCI(OpenID4VCIError::InvalidRequest)
        ))
    ));
}

#[tokio::test]
async fn test_create_token_pre_authorized_code_used() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let schema = generic_credential_schema();
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
    let credential = dummy_credential(
        "OPENID4VCI_FINAL1",
        CredentialStateEnum::Pending,
        true,
        Some(clone),
    );
    let interaction = credential.interaction.clone().unwrap();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![credential]));

    interaction_repository
        .expect_get_interaction()
        .once()
        .return_once(|_, _, _| Ok(Some(interaction)));

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
            None,
            None,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenIDIssuanceError(
            OpenIDIssuanceError::OpenID4VCI(OpenID4VCIError::InvalidGrant)
        ))
    ));
}

#[tokio::test]
async fn test_create_token_wrong_credential_state() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let schema = generic_credential_schema();

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
    let credential = dummy_credential(
        "OPENID4VCI_FINAL1",
        CredentialStateEnum::Offered,
        false,
        Some(clone),
    );
    let interaction = credential.interaction.clone().unwrap();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![credential]));
    interaction_repository
        .expect_get_interaction()
        .once()
        .return_once(|_, _, _| Ok(Some(interaction)));

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
            None,
            None,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenIDIssuanceError(
            OpenIDIssuanceError::InvalidCredentialState { .. }
        ))
    ));
}

// const NONCE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3NTgyNjU2NDMsImV4cCI6MTk1ODI2NTY0MywiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTozMDAwIiwianRpIjoiYTRiMTQ5NzYtYzQ2MS00OWNkLWEyODItYzBmZjcyMGY3YTYyIiwiY29udGV4dCI6Imlzc3VhbmNlLW9wZW5pZHZjaS1maW5hbC0xLjAtbm9uY2UifQ.Am8B0y5QqsiJluim9Q6Ov-4Po3VLkLcxAg2L0vDXNu8";
const PROOF_JWT: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3NXcnBvWXRkRjVka1VzZnhpZXZMc0oxaWpkcGtZdm9KcXliVUVjWXllTVJlI2tleS0xIiwidHlwIjoib3BlbmlkNHZjaS1wcm9vZitqd3QifQ.eyJpYXQiOjE3NDE3NzM2OTksImF1ZCI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJub25jZSI6ImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpwWVhRaU9qRTNOVGd5TmpVMk5ETXNJbVY0Y0NJNk1UazFPREkyTlRZME15d2lhWE56SWpvaWFIUjBjRG92THpFeU55NHdMakF1TVRvek1EQXdJaXdpYW5ScElqb2lZVFJpTVRRNU56WXRZelEyTVMwME9XTmtMV0V5T0RJdFl6Qm1aamN5TUdZM1lUWXlJaXdpWTI5dWRHVjRkQ0k2SW1semMzVmhibU5sTFc5d1pXNXBaSFpqYVMxbWFXNWhiQzB4TGpBdGJtOXVZMlVpZlEuQW04QjB5NVFxc2lKbHVpbTlRNk92LTRQbzNWTGtMY3hBZzJMMHZEWE51OCJ9.9or3jJO7ZKVfajqQa3ef21v45IdFuBsICzW6f2UA-dfPXWlyZToW6NYeMGofo2dxoY7CrkuX5vrCVPNMlaSZBw";

#[tokio::test]
async fn test_create_credential_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut exchange_provider = MockIssuanceProtocolProvider::default();

    let mut schema = generic_credential_schema();
    schema.key_storage_security = None;
    let credential = dummy_credential(
        "OPENID4VCI_FINAL1",
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

        let interaction_id = Uuid::from_str("3fa85f64-5717-4562-b3fc-2c963f66afa6")
            .unwrap()
            .into();
        interaction_repository
            .expect_get_interaction()
            .times(2)
            .returning(move |_, _, _| {
                Ok(Some(dummy_interaction(
                    Some(interaction_id),
                    true,
                    None,
                    None,
                    None,
                )))
            });
        interaction_repository
            .expect_mark_nonce_as_used()
            .return_once(|_, _| Ok(()));

        interaction_repository
            .expect_update_interaction()
            .once()
            .withf(move |id, _| *id == interaction_id)
            .returning(|_, _| Ok(()));

        let mut issuance_protocol = MockIssuanceProtocol::default();
        issuance_protocol
            .expect_issuer_issue_credential()
            .once()
            .return_once(|_, _, _| {
                Ok(SubmitIssuerResponse {
                    credential: "xyz".to_string(),
                    redirect_uri: None,
                    notification_id: Some("notification".to_string()),
                })
            });
        exchange_provider
            .expect_get_protocol()
            .once()
            .return_once(move |_| Some(Arc::new(issuance_protocol)));

        credential_repository
            .expect_update_credential()
            .once()
            .withf(move |id, request| {
                *id == credential.id
                    && request.holder_identifier_id == Some(Uuid::from(holder_did_id).into())
            })
            .returning(move |_, _| Ok(()));
    }

    let key_algorithm = mock_key_algorithm();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("EdDSA"))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some((KeyAlgorithmType::Eddsa, key_algorithm.clone()))
        });
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Eddsa))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some(key_algorithm.clone())
        });
    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |did_value| {
            Ok(DidDocument {
                context: serde_json::Value::Null,
                id: did_value.clone(),
                verification_method: vec![DidVerificationMethod {
                    id: format!("{did_value}#key-1"),
                    r#type: "".to_string(),
                    controller: did_value.to_string(),
                    // proof.jwt did key
                    public_key_jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "Ed25519".to_string(),
                        x: "whP_b7GlegxzU0Q1J6fNV3XDxYuPMkdt7oIA-1dnkE0".to_string(),
                        y: None,
                    }),
                }],
                authentication: Some(vec![format!("{did_value}#key-1")]),
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .returning(move |_, _, _| {
            Ok((
                Identifier {
                    id: Uuid::from(holder_did_id).into(),
                    r#type: IdentifierType::Did,
                    ..dummy_identifier()
                },
                RemoteIdentifierRelation::Did(Did {
                    id: holder_did_id,
                    ..dummy_did()
                }),
            ))
        });

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        exchange_provider,
        identifier_creator,
        key_algorithm_provider,
        did_method_provider,
        ..Default::default()
    });

    let result = service
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    schema.schema_id,
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
            },
        )
        .await;

    let result = result.unwrap();
    assert_eq!(
        "xyz",
        result.credentials.unwrap().first().unwrap().credential
    );
}

#[tokio::test]
async fn test_create_credential_success_sd_jwt_vc() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut exchange_provider = MockIssuanceProtocolProvider::default();

    let mut schema = generic_credential_schema();
    schema.format = "SD_JWT_VC".into();
    schema.key_storage_security = None;
    let credential = dummy_credential(
        "OPENID4VCI_FINAL1",
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

        let interaction_id = Uuid::from_str("3fa85f64-5717-4562-b3fc-2c963f66afa6")
            .unwrap()
            .into();
        interaction_repository
            .expect_get_interaction()
            .times(2)
            .returning(move |_, _, _| {
                Ok(Some(dummy_interaction(
                    Some(interaction_id),
                    true,
                    None,
                    None,
                    None,
                )))
            });
        interaction_repository
            .expect_mark_nonce_as_used()
            .return_once(|_, _| Ok(()));

        let mut issuance_protocol = MockIssuanceProtocol::default();
        issuance_protocol
            .expect_issuer_issue_credential()
            .once()
            .return_once(|_, _, _| {
                Ok(SubmitIssuerResponse {
                    credential: "xyz".to_string(),
                    redirect_uri: None,
                    notification_id: None,
                })
            });
        exchange_provider
            .expect_get_protocol()
            .once()
            .return_once(move |_| Some(Arc::new(issuance_protocol)));

        credential_repository
            .expect_update_credential()
            .once()
            .withf(move |id, request| {
                *id == credential.id
                    && request.holder_identifier_id == Some(Uuid::from(holder_did_id).into())
            })
            .returning(move |_, _| Ok(()));
    }

    let key_algorithm = mock_key_algorithm();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("EdDSA"))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some((KeyAlgorithmType::Eddsa, key_algorithm.clone()))
        });
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Eddsa))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some(key_algorithm.clone())
        });
    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |did_value| {
            Ok(DidDocument {
                context: serde_json::Value::Null,
                id: did_value.clone(),
                verification_method: vec![DidVerificationMethod {
                    id: format!("{did_value}#key-1"),
                    r#type: "".to_string(),
                    controller: did_value.to_string(),
                    // proof.jwt did key
                    public_key_jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "Ed25519".to_string(),
                        x: "whP_b7GlegxzU0Q1J6fNV3XDxYuPMkdt7oIA-1dnkE0".to_string(),
                        y: None,
                    }),
                }],
                authentication: Some(vec![format!("{did_value}#key-1")]),
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .returning(move |_, _, _| {
            Ok((
                Identifier {
                    id: Uuid::from(holder_did_id).into(),
                    r#type: IdentifierType::Did,
                    ..dummy_identifier()
                },
                RemoteIdentifierRelation::Did(Did {
                    id: holder_did_id,
                    ..dummy_did()
                }),
            ))
        });

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        exchange_provider,
        identifier_creator,
        key_algorithm_provider,
        did_method_provider,
        ..Default::default()
    });

    let result = service
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    schema.schema_id,
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
            },
        )
        .await;

    let result = result.unwrap();
    assert_eq!(
        "xyz",
        result.credentials.unwrap().first().unwrap().credential
    );
}

#[tokio::test]
async fn test_create_credential_success_mdoc() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut exchange_provider = MockIssuanceProtocolProvider::default();

    let schema = CredentialSchema {
        format: "MDOC".into(),
        schema_id: "test.doctype".to_owned(),
        key_storage_security: None,
        ..generic_credential_schema()
    };
    let credential = dummy_credential(
        "OPENID4VCI_FINAL1",
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
            .times(2)
            .returning(|_, _, _| {
                Ok(Some(dummy_interaction(
                    Some(
                        Uuid::from_str("3fa85f64-5717-4562-b3fc-2c963f66afa6")
                            .unwrap()
                            .into(),
                    ),
                    true,
                    None,
                    None,
                    None,
                )))
            });
        interaction_repository
            .expect_mark_nonce_as_used()
            .return_once(|_, _| Ok(()));
        interaction_repository
            .expect_update_interaction()
            .return_once(|_, _| Ok(()));

        let mut issuance_protocol = MockIssuanceProtocol::default();
        issuance_protocol
            .expect_issuer_issue_credential()
            .once()
            .return_once(|_, _, _| {
                Ok(SubmitIssuerResponse {
                    credential: "xyz".to_string(),
                    redirect_uri: None,
                    notification_id: None,
                })
            });
        exchange_provider
            .expect_get_protocol()
            .once()
            .return_once(move |_| Some(Arc::new(issuance_protocol)));

        credential_repository
            .expect_update_credential()
            .once()
            .withf(move |id, request| {
                *id == credential.id
                    && request.holder_identifier_id == Some(Uuid::from(holder_did_id).into())
            })
            .returning(move |_, _| Ok(()));
    }

    let key_algorithm = mock_key_algorithm();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("EdDSA"))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some((KeyAlgorithmType::Eddsa, key_algorithm.clone()))
        });
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Eddsa))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some(key_algorithm.clone())
        });
    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |did_value| {
            Ok(DidDocument {
                context: serde_json::Value::Null,
                id: did_value.clone(),
                verification_method: vec![DidVerificationMethod {
                    id: format!("{did_value}#key-1"),
                    r#type: "".to_string(),
                    controller: did_value.to_string(),
                    // proof.jwt did key
                    public_key_jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "Ed25519".to_string(),
                        x: "whP_b7GlegxzU0Q1J6fNV3XDxYuPMkdt7oIA-1dnkE0".to_string(),
                        y: None,
                    }),
                }],
                authentication: Some(vec![format!("{did_value}#key-1")]),
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .returning(move |_, _, _| {
            Ok((
                Identifier {
                    id: Uuid::from(holder_did_id).into(),
                    r#type: IdentifierType::Did,
                    ..dummy_identifier()
                },
                RemoteIdentifierRelation::Did(Did {
                    id: holder_did_id,
                    ..dummy_did()
                }),
            ))
        });

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        exchange_provider,
        identifier_creator,
        key_algorithm_provider,
        did_method_provider,
        ..Default::default()
    });

    let result = service
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    schema.schema_id,
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
            },
        )
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(
        "xyz",
        result.credentials.unwrap().first().unwrap().credential
    );
}

#[tokio::test]
async fn test_create_credential_configuration_id_invalid() {
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
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    "invalid".to_string(),
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
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
async fn test_create_credential_format_invalid_bearer_token() {
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
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    schema.schema_id,
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
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
async fn test_create_credential_pre_authorized_code_not_used() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let exchange_provider = MockIssuanceProtocolProvider::default();

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
            .return_once(|_, _, _| Ok(Some(dummy_interaction(None, false, None, None, None))));
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
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    schema.schema_id,
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
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
async fn test_create_credential_interaction_data_invalid() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let exchange_provider = MockIssuanceProtocolProvider::default();

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
            .return_once(|_, _, _| Ok(Some(dummy_interaction(None, true, None, None, None))));
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
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.123",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    schema.schema_id,
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
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
async fn test_create_credential_access_token_expired() {
    let mut repository = MockCredentialSchemaRepository::default();
    let credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let exchange_provider = MockIssuanceProtocolProvider::default();

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
            .return_once(|_, _, _| {
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
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    schema.schema_id,
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
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
async fn test_create_credential_issuer_failed() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut exchange_provider = MockIssuanceProtocolProvider::default();

    let mut schema = generic_credential_schema();
    schema.key_storage_security = None;
    let credential = dummy_credential(
        "OPENID4VCI_FINAL1",
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

        let interaction_id = Uuid::from_str("3fa85f64-5717-4562-b3fc-2c963f66afa6")
            .unwrap()
            .into();
        interaction_repository
            .expect_get_interaction()
            .times(2)
            .returning(move |_, _, _| {
                Ok(Some(dummy_interaction(
                    Some(interaction_id),
                    true,
                    None,
                    None,
                    None,
                )))
            });
        interaction_repository
            .expect_mark_nonce_as_used()
            .return_once(|_, _| Ok(()));

        let mut issuance_protocol = MockIssuanceProtocol::default();
        issuance_protocol
            .expect_issuer_issue_credential()
            .once()
            .return_once(|_, _, _| {
                Err(IssuanceProtocolError::Failed("issuing failed".to_string()))
            });
        exchange_provider
            .expect_get_protocol()
            .once()
            .return_once(move |_| Some(Arc::new(issuance_protocol)));

        credential_repository
            .expect_update_credential()
            .once()
            .withf(move |id, request| {
                *id == credential.id && request.state == Some(CredentialStateEnum::Error)
            })
            .returning(move |_, _| Ok(()));
    }

    let key_algorithm = mock_key_algorithm();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("EdDSA"))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some((KeyAlgorithmType::Eddsa, key_algorithm.clone()))
        });
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Eddsa))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some(key_algorithm.clone())
        });
    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |did_value| {
            Ok(DidDocument {
                context: serde_json::Value::Null,
                id: did_value.clone(),
                verification_method: vec![DidVerificationMethod {
                    id: format!("{did_value}#key-1"),
                    r#type: "".to_string(),
                    controller: did_value.to_string(),
                    // proof.jwt did key
                    public_key_jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "Ed25519".to_string(),
                        x: "whP_b7GlegxzU0Q1J6fNV3XDxYuPMkdt7oIA-1dnkE0".to_string(),
                        y: None,
                    }),
                }],
                authentication: Some(vec![format!("{did_value}#key-1")]),
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .returning(move |_, _, _| {
            Ok((
                Identifier {
                    id: Uuid::from(holder_did_id).into(),
                    r#type: IdentifierType::Did,
                    ..dummy_identifier()
                },
                RemoteIdentifierRelation::Did(Did {
                    id: holder_did_id,
                    ..dummy_did()
                }),
            ))
        });

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        exchange_provider,
        key_algorithm_provider,
        did_method_provider,
        identifier_creator,
        ..Default::default()
    });

    let result = service
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    schema.schema_id,
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::IssuanceProtocolError(_))
    ));
}

#[tokio::test]
async fn test_create_credential_nonce_reused() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let schema = generic_credential_schema();
    let credential = dummy_credential(
        "OPENID4VCI_FINAL1",
        CredentialStateEnum::Pending,
        true,
        Some(schema.clone()),
    );

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
            .return_once(|_, _, _| {
                Ok(Some(dummy_interaction(
                    Some(
                        Uuid::from_str("3fa85f64-5717-4562-b3fc-2c963f66afa6")
                            .unwrap()
                            .into(),
                    ),
                    true,
                    None,
                    None,
                    None,
                )))
            });
        interaction_repository
            .expect_mark_nonce_as_used()
            .return_once(|_, _| Err(DataLayerError::RecordNotUpdated));
    }

    let key_algorithm = mock_key_algorithm();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("EdDSA"))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some((KeyAlgorithmType::Eddsa, key_algorithm.clone()))
        });
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Eddsa))
        .once()
        .returning({
            let key_algorithm = key_algorithm.clone();
            move |_| Some(key_algorithm.clone())
        });
    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |did_value| {
            Ok(DidDocument {
                context: serde_json::Value::Null,
                id: did_value.clone(),
                verification_method: vec![DidVerificationMethod {
                    id: format!("{did_value}#key-1"),
                    r#type: "".to_string(),
                    controller: did_value.to_string(),
                    // proof.jwt did key
                    public_key_jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "Ed25519".to_string(),
                        x: "whP_b7GlegxzU0Q1J6fNV3XDxYuPMkdt7oIA-1dnkE0".to_string(),
                        y: None,
                    }),
                }],
                authentication: Some(vec![format!("{did_value}#key-1")]),
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

    let service = setup_service(Mocks {
        credential_schema_repository: repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        key_algorithm_provider,
        did_method_provider,
        ..Default::default()
    });

    let result = service
        .create_credential(
            &schema.id,
            "3fa85f64-5717-4562-b3fc-2c963f66afa6.asdfasdfasdf",
            OpenID4VCICredentialRequestDTO {
                credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                    schema.schema_id,
                ),
                proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![
                    PROOF_JWT.to_string(),
                ])),
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidNonce))
    ));
}

#[tokio::test]
async fn test_for_mdoc_schema_pre_authorized_grant_type_creates_refresh_token() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let mut schema = generic_credential_schema();
    schema.format = "MDOC".into();

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

    let credential = dummy_credential(
        "OPENID4VCI_FINAL1",
        CredentialStateEnum::Pending,
        false,
        Some(schema.clone()),
    );
    let interaction_id = credential.interaction.as_ref().unwrap().id;
    let interaction = credential.interaction.clone().unwrap();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![credential]));

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_, _| Ok(()));

    interaction_repository
        .expect_get_interaction()
        .once()
        .return_once(|_, _, _| Ok(Some(interaction)));
    interaction_repository
        .expect_update_interaction()
        .once()
        .return_once(|_, _| Ok(()));

    let service = setup_service(Mocks {
        credential_schema_repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
            None,
            None,
        )
        .await;

    let result = result.unwrap();
    assert_eq!("bearer", result.token_type);
    assert!(
        result
            .access_token
            .expose_secret()
            .starts_with(&format!("{interaction_id}."))
    );

    assert!(
        result
            .refresh_token
            .unwrap()
            .expose_secret()
            .starts_with("c62f4237-3c74-42f2-a5ff-c72489e025f7.")
    );

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

    let interaction_id = Uuid::from_str("c62f4237-3c74-42f2-a5ff-c72489e025f7")
        .unwrap()
        .into();
    let refresh_token = "c62f4237-3c74-42f2-a5ff-c72489e025f7.AAAAA";
    let refresh_token_expires_at = "2077-10-28T07:03:38.4404734Z";
    let interaction = dummy_interaction(
        Some(interaction_id),
        false,
        None,
        Some(refresh_token),
        Some(refresh_token_expires_at),
    );
    let credential = Credential {
        interaction: Some(interaction.clone()),
        ..dummy_credential(
            "OPENID4VCI_FINAL1",
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
        .expect_get_interaction()
        .once()
        .return_once(|_, _, _| Ok(Some(interaction)));
    interaction_repository
        .expect_update_interaction()
        .once()
        .return_once(|_, _| Ok(()));

    let service = setup_service(Mocks {
        credential_schema_repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::RefreshToken {
                refresh_token: refresh_token.to_string(),
            },
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!("bearer", result.token_type);
    assert!(
        result
            .access_token
            .expose_secret()
            .starts_with("c62f4237-3c74-42f2-a5ff-c72489e025f7.")
    );

    assert!(
        result
            .refresh_token
            .unwrap()
            .expose_secret()
            .starts_with("c62f4237-3c74-42f2-a5ff-c72489e025f7.")
    );

    assert!(result.refresh_token_expires_in.is_some());
}

#[tokio::test]
async fn test_refresh_token_request_fails_if_refresh_token_is_expired() {
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

    let interaction_id = Uuid::from_str("c62f4237-3c74-42f2-a5ff-c72489e025f7")
        .unwrap()
        .into();
    let refresh_token = "c62f4237-3c74-42f2-a5ff-c72489e025f7.AAAAA";
    // expired refresh token
    let refresh_token_expires_at = "2023-10-28T07:03:38.4404734Z";
    let interaction = dummy_interaction(
        Some(interaction_id),
        false,
        None,
        Some(refresh_token),
        Some(refresh_token_expires_at),
    );
    let credential = Credential {
        interaction: Some(interaction.clone()),
        ..dummy_credential(
            "OPENID4VCI_FINAL1",
            CredentialStateEnum::Accepted,
            false,
            Some(schema.clone()),
        )
    };

    interaction_repository
        .expect_get_interaction()
        .return_once(|_, _, _| Ok(Some(interaction)));

    credential_repository
        .expect_get_credentials_by_interaction_id()
        .withf(move |interaction_id_, _| *interaction_id_ == interaction_id)
        .once()
        .return_once(move |_, _| Ok(vec![credential]));

    let service = setup_service(Mocks {
        credential_schema_repository,
        credential_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::RefreshToken {
                refresh_token: refresh_token.to_string(),
            },
            None,
            None,
        )
        .await
        .err()
        .unwrap();

    assert2::assert!(let ServiceError::OpenIDIssuanceError(OpenIDIssuanceError::OpenID4VCI(OpenID4VCIError::InvalidToken)) = result);
}

#[tokio::test]
async fn test_create_token_eudi_compliant_without_attestation_fails() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();

    let mut schema = generic_credential_schema();
    schema.requires_app_attestation = true;

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

    let service = setup_service(Mocks {
        credential_schema_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
            None,
            None,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest
        ))
    ));
}

#[tokio::test]
async fn test_create_token_eudi_compliant_with_only_attestation_fails() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();

    let mut schema = generic_credential_schema();
    schema.requires_app_attestation = true;

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

    let service = setup_service(Mocks {
        credential_schema_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
            Some("attestation_token"),
            None,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest
        ))
    ));
}

#[tokio::test]
async fn test_create_token_non_eudi_with_attestation_fails() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();

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

    let service = setup_service(Mocks {
        credential_schema_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_token(
            &schema.id,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: "c62f4237-3c74-42f2-a5ff-c72489e025f7".to_string(),
                tx_code: None,
            },
            Some("attestation_token"),
            Some("pop_token"),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest
        ))
    ));
}
