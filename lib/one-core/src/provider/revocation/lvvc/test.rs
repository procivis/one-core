use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use shared_types::DidValue;
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::matchers::{header_regex, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::model::credential::{Credential, CredentialRole};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaType, LayoutType};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::key::Key;
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, MockSignatureProvider,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::lvvc::{LvvcProvider, Params};
use crate::provider::revocation::model::{CredentialDataByRole, CredentialRevocationState};
use crate::provider::revocation::RevocationMethod;

fn generic_did_credential(role: CredentialRole) -> (Did, Credential) {
    let now = OffsetDateTime::now_utc();

    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "did".to_string(),
        did: DidValue::from("did:key:123".to_string()),
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
                key_reference: vec![],
                storage_type: "".to_string(),
                key_type: "".to_string(),
                organisation: None,
            },
        }]),
        organisation: None,
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "OPENID4VC".to_string(),
        redirect_uri: None,
        role,
        state: None,
        claims: None,
        issuer_did: Some(did.to_owned()),
        holder_did: None,
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
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            imported_source_url: "URL".to_string(),
            allow_suspension: true,
            claim_schemas: None,
            organisation: None,
        }),
        key: None,
        interaction: None,
        revocation_list: None,
    };

    (did, credential)
}

fn extracted_credential(status: &str) -> DetailCredential {
    DetailCredential {
        id: None,
        valid_from: None,
        valid_until: None,
        update_at: None,
        invalid_before: None,
        issuer_did: None,
        subject: None,
        claims: CredentialSubject {
            values: HashMap::from([("status".to_string(), json!(status))]),
        },
        status: vec![],
        credential_schema: None,
    }
}

fn create_provider(
    formatter_provider: MockCredentialFormatterProvider,
    key_provider: MockKeyProvider,
) -> LvvcProvider {
    LvvcProvider::new(
        None,
        Arc::new(formatter_provider),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(key_provider),
        Arc::new(ReqwestClient::default()),
        Params {
            credential_expiry: Default::default(),
            minimum_refresh_time: Default::default(),
            json_ld_context_url: None,
        },
    )
}
#[tokio::test]
async fn test_check_revocation_status_as_issuer() {
    let mock_server = MockServer::start().await;

    Mock::given(path("/lvvcurl"))
        .and(header_regex("Authorization", "Bearer .*\\.c2lnbmVk")) // c2lnbmVk == base64("signed")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential": "this.is.jwt",
            "format": "MOCK"
        })))
        .mount(&mock_server)
        .await;

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .returning(|_, _| {
            let mut auth_fn = MockSignatureProvider::new();
            auth_fn
                .expect_sign()
                .returning(|_| Ok("signed".as_bytes().to_vec()));

            Ok(Box::new(auth_fn))
        });

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider.expect_get_formatter().returning(|_| {
        let mut formatter = MockCredentialFormatter::new();
        formatter
            .expect_extract_credentials_unverified()
            .returning(|_| Ok(extracted_credential("ACCEPTED")));

        Some(Arc::new(formatter))
    });

    let lvvc_url = format!("{}/lvvcurl", mock_server.uri()).parse().unwrap();
    let status = CredentialStatus {
        id: Some(lvvc_url),
        r#type: "".to_string(),
        status_purpose: None,
        additional_fields: Default::default(),
    };

    let (did, credential) = generic_did_credential(CredentialRole::Issuer);

    let provider = create_provider(formatter_provider, key_provider);

    let result = provider
        .check_credential_revocation_status(
            &status,
            &did.did,
            Some(CredentialDataByRole::Issuer(credential)),
        )
        .await
        .unwrap();
    assert_eq!(CredentialRevocationState::Valid, result);
}
