use std::collections::HashMap;
use std::sync::Arc;

use mockall::predicate::eq;
use serde_json::json;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{header_regex, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::Key;
use crate::model::validity_credential::{ValidityCredential, ValidityCredentialType};
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, CredentialStatus, CredentialSubject, DetailCredential,
    IdentifierDetails, MockSignatureProvider,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::lvvc::{LvvcProvider, Params};
use crate::provider::revocation::model::{CredentialDataByRole, CredentialRevocationState};
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;

fn generic_did_credential(role: CredentialRole) -> (Did, Identifier, Credential) {
    let now = OffsetDateTime::now_utc();

    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        deactivated: false,
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                public_key: vec![],
                name: "".to_string(),
                key_reference: None,
                storage_type: "".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            reference: "1".to_string(),
        }]),
        organisation: None,
        log: None,
    };

    let identifier = Identifier {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "identifier".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: None,
        did: Some(did.to_owned()),
        key: None,
        certificates: None,
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: None,
        issuer_identifier: Some(identifier.to_owned()),
        issuer_certificate: None,
        holder_identifier: Some(identifier.to_owned()),
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "LVVC".to_string(),
            wallet_storage_type: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "schema_id".to_string(),
            imported_source_url: "URL".to_string(),
            allow_suspension: true,
            requires_app_attestation: false,
            claim_schemas: None,
            organisation: None,
        }),
        key: None,
        interaction: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
    };

    (did, identifier, credential)
}

fn extracted_credential(status: &str) -> DetailCredential {
    DetailCredential {
        id: None,
        issuance_date: None,
        valid_from: None,
        valid_until: None,
        update_at: None,
        invalid_before: None,
        issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
        subject: None,
        claims: CredentialSubject {
            claims: HashMap::from([(
                "status".to_string(),
                CredentialClaim {
                    selectively_disclosable: false,
                    metadata: false,
                    value: CredentialClaimValue::String(status.to_string()),
                },
            )]),
            id: None,
        },
        status: vec![],
        credential_schema: None,
    }
}

fn create_provider(
    formatter_provider: MockCredentialFormatterProvider,
    key_provider: MockKeyProvider,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    validity_credential_repository: MockValidityCredentialRepository,
) -> LvvcProvider {
    LvvcProvider::new(
        None,
        Arc::new(formatter_provider),
        Arc::new(validity_credential_repository),
        Arc::new(key_provider),
        Arc::new(key_algorithm_provider),
        Arc::new(ReqwestClient::default()),
        Params {
            credential_expiry: Default::default(),
            minimum_refresh_time: Default::default(),
            json_ld_context_url: None,
        },
    )
}

#[tokio::test]
async fn test_check_revocation_status_as_holder_not_cached() {
    let mock_server = MockServer::start().await;

    Mock::given(method(Method::GET))
        .and(path("/lvvcurl"))
        .and(header_regex("Authorization", "Bearer .*\\.c2lnbmVk")) // c2lnbmVk == base64("signed")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential": "this.is.jwt",
            "format": "MOCK"
        })))
        .mount(&mock_server)
        .await;

    let (key_provider, formatter_provider, key_algorithm_provider) = common_mock_providers();

    let (did, _, credential) = generic_did_credential(CredentialRole::Holder);

    let mut validity_credential_repository = MockValidityCredentialRepository::new();
    validity_credential_repository
        .expect_get_latest_by_credential_id()
        .once()
        .with(eq(credential.id), eq(ValidityCredentialType::Lvvc))
        .returning(|_, _| Ok(None));
    validity_credential_repository
        .expect_remove_all_by_credential_id()
        .once()
        .with(eq(credential.id), eq(ValidityCredentialType::Lvvc))
        .returning(|_, _| Ok(()));
    let credential_id = credential.id;
    validity_credential_repository
        .expect_insert()
        .once()
        .withf(move |cred| cred.linked_credential_id == credential_id)
        .returning(|_| Ok(()));

    let lvvc_url = format!("{}/lvvcurl", mock_server.uri()).parse().unwrap();
    let status = CredentialStatus {
        id: Some(lvvc_url),
        r#type: "".to_string(),
        status_purpose: None,
        additional_fields: Default::default(),
    };

    let provider = create_provider(
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        validity_credential_repository,
    );

    let result = provider
        .check_credential_revocation_status(
            &status,
            &IdentifierDetails::Did(did.did),
            Some(CredentialDataByRole::Holder(Box::new(credential))),
            false,
        )
        .await
        .unwrap();
    assert_eq!(CredentialRevocationState::Valid, result);
}

#[tokio::test]
async fn test_check_revocation_status_as_holder_cached() {
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_extract_credentials_unverified()
                .returning(|_, _| Ok(extracted_credential("ACCEPTED")));

            Some(Arc::new(formatter))
        });

    let (did, _, credential) = generic_did_credential(CredentialRole::Holder);

    let mut validity_credential_repository = MockValidityCredentialRepository::new();
    let credential_id = credential.id;
    validity_credential_repository
        .expect_get_latest_by_credential_id()
        .once()
        .returning(move |_, _| {
            Ok(Some(ValidityCredential {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                credential: "this.is.jwt".to_string().into_bytes(),
                linked_credential_id: credential_id,
                r#type: ValidityCredentialType::Lvvc,
            }))
        });

    let status = CredentialStatus {
        id: None,
        r#type: "".to_string(),
        status_purpose: None,
        additional_fields: Default::default(),
    };

    let provider = create_provider(
        formatter_provider,
        MockKeyProvider::new(),
        MockKeyAlgorithmProvider::new(),
        validity_credential_repository,
    );

    let result = provider
        .check_credential_revocation_status(
            &status,
            &IdentifierDetails::Did(did.did),
            Some(CredentialDataByRole::Holder(Box::new(credential))),
            false,
        )
        .await
        .unwrap();
    assert_eq!(CredentialRevocationState::Valid, result);
}

#[tokio::test]
async fn test_check_revocation_status_as_holder_cached_force_refresh_fail() {
    let mock_server = MockServer::start().await;

    Mock::given(method(Method::GET))
        .and(path("/lvvcurl"))
        .and(header_regex("Authorization", "Bearer .*\\.c2lnbmVk")) // c2lnbmVk == base64("signed")
        .respond_with(ResponseTemplate::new(400))
        .mount(&mock_server)
        .await;

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_extract_credentials_unverified()
                .returning(|_, _| Ok(extracted_credential("ACCEPTED")));

            Some(Arc::new(formatter))
        });

    let (did, _, credential) = generic_did_credential(CredentialRole::Holder);

    let mut validity_credential_repository = MockValidityCredentialRepository::new();
    let credential_id = credential.id;
    validity_credential_repository
        .expect_get_latest_by_credential_id()
        .once()
        .returning(move |_, _| {
            Ok(Some(ValidityCredential {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                credential: "this.is.jwt".to_string().into_bytes(),
                linked_credential_id: credential_id,
                r#type: ValidityCredentialType::Lvvc,
            }))
        });

    let (key_provider, formatter_provider, key_algorithm_provider) = common_mock_providers();

    let lvvc_url = format!("{}/lvvcurl", mock_server.uri()).parse().unwrap();
    let status = CredentialStatus {
        id: Some(lvvc_url),
        r#type: "".to_string(),
        status_purpose: None,
        additional_fields: Default::default(),
    };

    let provider = create_provider(
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        validity_credential_repository,
    );

    let result = provider
        .check_credential_revocation_status(
            &status,
            &IdentifierDetails::Did(did.did),
            Some(CredentialDataByRole::Holder(Box::new(credential))),
            true,
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(result, Err(RevocationError::HttpClientError(_))))
}

fn common_mock_providers() -> (
    MockKeyProvider,
    MockCredentialFormatterProvider,
    MockKeyAlgorithmProvider,
) {
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .returning(|_, _, _| {
            let mut auth_fn = MockSignatureProvider::new();
            auth_fn
                .expect_sign()
                .returning(|_| Ok("signed".as_bytes().to_vec()));

            Ok(Box::new(auth_fn))
        });

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_extract_credentials_unverified()
                .returning(|_, _| Ok(extracted_credential("ACCEPTED")));

            Some(Arc::new(formatter))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_issuance_jose_alg_id()
                .returning(|| Some("ES256".to_string()));
            Some(Arc::new(key_algorithm))
        });
    (key_provider, formatter_provider, key_algorithm_provider)
}
