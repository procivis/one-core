use std::assert_matches;
use std::sync::Arc;

use shared_types::{CredentialSchemaId, IdentifierId};
use similar_asserts::assert_eq;
use standardized_types::jwk::PublicJwk;
use uuid::Uuid;

use super::SSIIssuerService;
use crate::config::core_config::CoreConfig;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::{Did, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::relation::Related;
use crate::provider::issuance_protocol::MockIssuanceProtocol;
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::provider_directory::ProviderError;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::error::{DataLayerError, EntityKind};
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::service::ssi_issuer::dto::SdJwtVcIssuerMetadataJwks;
use crate::service::ssi_issuer::error::IssuerServiceError;
use crate::service::test_utilities::{
    dummy_credential_schema, dummy_did, dummy_identifier, dummy_key, generic_config,
};

fn setup_service(
    credential_schema_repository: MockCredentialSchemaRepository,
    identifier_repository: MockIdentifierRepository,
    issuance_protocol_provider: MockIssuanceProtocolProvider,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    config: CoreConfig,
    core_base_url: Option<String>,
) -> SSIIssuerService {
    SSIIssuerService::new(
        Arc::new(credential_schema_repository),
        Arc::new(identifier_repository),
        Arc::new(issuance_protocol_provider),
        Arc::new(key_algorithm_provider),
        Arc::new(config),
        core_base_url,
    )
}

fn issuer_metadata_fixtures() -> (
    String,
    IdentifierId,
    CredentialSchemaId,
    Identifier,
    CredentialSchema,
) {
    let protocol_id = "OPENID4VCI".to_string();
    let identifier_id: IdentifierId = Uuid::new_v4().into();
    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();

    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;

    let mut credential_schema = dummy_credential_schema();
    credential_schema.id = credential_schema_id;

    (
        protocol_id,
        identifier_id,
        credential_schema_id,
        identifier,
        credential_schema,
    )
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_success_with_did() {
    // given
    let (protocol_id, identifier_id, credential_schema_id, mut identifier, credential_schema) =
        issuer_metadata_fixtures();

    let mut did: Did = dummy_did();
    let mut key = dummy_key();
    key.storage_type = "INTERNAL".to_string();
    did.keys = vec![RelatedKey {
        role: KeyRole::AssertionMethod,
        key,
        reference: "key-1".to_string(),
    }]
    .into();
    identifier.data = IdentifierData::Did(did.clone().into());

    let mut protocol_provider = MockIssuanceProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(MockIssuanceProtocol::new())));

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .once()
        .return_once(move |_| Ok(identifier));

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();
    credential_schema_repository
        .expect_get_credential_schema()
        .once()
        .return_once(move |_| Ok(credential_schema));

    let mut mock_public_key = MockSignaturePublicKeyHandle::new();
    mock_public_key.expect_as_jwk().once().return_once(|| {
        Ok(PublicJwk::Ec(standardized_types::jwk::PublicJwkEc {
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "x".to_string(),
            y: Some("y".to_string()),
            alg: None,
        }))
    });

    let mut mock_key_algorithm = MockKeyAlgorithm::new();
    mock_key_algorithm
        .expect_reconstruct_key()
        .once()
        .return_once(move |_, _, _| {
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(mock_public_key),
            )))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_key()
        .once()
        .return_once(move |_| Ok(Arc::new(mock_key_algorithm)));

    let service = setup_service(
        credential_schema_repository,
        identifier_repository,
        protocol_provider,
        key_algorithm_provider,
        generic_config().core,
        Some("https://core.example".to_string()),
    );

    // when
    let result = service
        .get_sd_jwt_vc_issuer_metadata(&protocol_id, &identifier_id, &credential_schema_id)
        .await
        .unwrap();

    // then
    assert_eq!(did.did.as_str(), result.issuer);
    assert_matches!(result.jwks, SdJwtVcIssuerMetadataJwks::Jwks(ref jwks) if jwks.len() == 1);
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_success() {
    // given
    let (protocol_id, identifier_id, credential_schema_id, mut identifier, credential_schema) =
        issuer_metadata_fixtures();

    // Use a Key-type identifier (no DID) to trigger the fallback URL path
    let mut key = dummy_key();
    key.storage_type = "INTERNAL".to_string();
    identifier.data = IdentifierData::Key(Related::from(key));

    let mut protocol_provider = MockIssuanceProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(MockIssuanceProtocol::new())));

    let mut identifier_repository = MockIdentifierRepository::new();
    let expected_identifier_id = identifier.id;
    let expected_schema_id = credential_schema.id;
    identifier_repository
        .expect_get()
        .once()
        .return_once(move |_| Ok(identifier));

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();
    credential_schema_repository
        .expect_get_credential_schema()
        .once()
        .return_once(move |_| Ok(credential_schema));

    let mut mock_public_key = MockSignaturePublicKeyHandle::new();
    mock_public_key.expect_as_jwk().once().return_once(|| {
        Ok(PublicJwk::Ec(standardized_types::jwk::PublicJwkEc {
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "x".to_string(),
            y: Some("y".to_string()),
            alg: None,
        }))
    });

    let mut mock_key_algorithm = MockKeyAlgorithm::new();
    mock_key_algorithm
        .expect_reconstruct_key()
        .once()
        .return_once(move |_, _, _| {
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(mock_public_key),
            )))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_key()
        .once()
        .return_once(move |_| Ok(Arc::new(mock_key_algorithm)));

    let core_base_url = "https://core.example".to_string();
    let service = setup_service(
        credential_schema_repository,
        identifier_repository,
        protocol_provider,
        key_algorithm_provider,
        generic_config().core,
        Some(core_base_url.clone()),
    );

    // when
    let result = service
        .get_sd_jwt_vc_issuer_metadata(&protocol_id, &identifier_id, &credential_schema_id)
        .await
        .unwrap();

    // then
    let expected_issuer = format!(
        "{core_base_url}/ssi/openid4vci/{protocol_id}/{expected_identifier_id}/{expected_schema_id}"
    );
    assert_eq!(expected_issuer, result.issuer);
    assert_matches!(result.jwks, SdJwtVcIssuerMetadataJwks::Jwks(ref jwks) if jwks.len() == 1);
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_fails_when_core_base_url_is_missing() {
    // given
    let service = setup_service(
        MockCredentialSchemaRepository::new(),
        MockIdentifierRepository::new(),
        MockIssuanceProtocolProvider::new(),
        MockKeyAlgorithmProvider::new(),
        generic_config().core,
        None,
    );

    // when
    let result = service
        .get_sd_jwt_vc_issuer_metadata(
            &"OPENID4VCI".to_string(),
            &Uuid::new_v4().into(),
            &Uuid::new_v4().into(),
        )
        .await;

    // then
    assert_matches!(
        result,
        Err(IssuerServiceError::MappingError(message)) if message == "Missing core_base_url for jwt vc issuer metadata"
    );
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_fails_when_protocol_not_found() {
    // given
    let mut protocol_provider = MockIssuanceProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(|_| {
            Err(ProviderError::MissingProvider {
                config_key: "test".to_string(),
                provider_type: "Issuance protocol".to_string(),
            }
            .into())
        });

    let service = setup_service(
        MockCredentialSchemaRepository::new(),
        MockIdentifierRepository::new(),
        protocol_provider,
        MockKeyAlgorithmProvider::new(),
        generic_config().core,
        Some("https://core.example".to_string()),
    );

    let protocol_id = "UNKNOWN".to_string();

    // when
    let result = service
        .get_sd_jwt_vc_issuer_metadata(&protocol_id, &Uuid::new_v4().into(), &Uuid::new_v4().into())
        .await;

    // then
    assert_matches!(
        result,
        Err(IssuerServiceError::MissingProtocol(value)) if value == protocol_id
    );
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_fails_when_identifier_not_found() {
    // given
    let mut protocol_provider = MockIssuanceProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(|_| Ok(Arc::new(MockIssuanceProtocol::new())));

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().once().return_once(|id| {
        Err(DataLayerError::EntityNotFound {
            kind: EntityKind::Identifier,
            id: id.into(),
        })
    });

    let service = setup_service(
        MockCredentialSchemaRepository::new(),
        identifier_repository,
        protocol_provider,
        MockKeyAlgorithmProvider::new(),
        generic_config().core,
        Some("https://core.example".to_string()),
    );

    let identifier_id: IdentifierId = Uuid::new_v4().into();

    // when
    let result = service
        .get_sd_jwt_vc_issuer_metadata(
            &"OPENID4VCI".to_string(),
            &identifier_id,
            &Uuid::new_v4().into(),
        )
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0207);
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_fails_when_credential_schema_not_found() {
    // given
    let mut protocol_provider = MockIssuanceProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(|_| Ok(Arc::new(MockIssuanceProtocol::new())));

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .once()
        .return_once(move |_| Ok(dummy_identifier()));

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();
    credential_schema_repository
        .expect_get_credential_schema()
        .once()
        .return_once(|id| {
            Err(DataLayerError::EntityNotFound {
                kind: EntityKind::CredentialSchema,
                id: (*id).into(),
            })
        });

    let service = setup_service(
        credential_schema_repository,
        identifier_repository,
        protocol_provider,
        MockKeyAlgorithmProvider::new(),
        generic_config().core,
        Some("https://core.example".to_string()),
    );

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();

    // when
    let result = service
        .get_sd_jwt_vc_issuer_metadata(
            &"OPENID4VCI".to_string(),
            &Uuid::new_v4().into(),
            &credential_schema_id,
        )
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0006);
}
