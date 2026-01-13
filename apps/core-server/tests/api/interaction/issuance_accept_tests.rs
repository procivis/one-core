use std::collections::HashSet;
use std::str::FromStr;

use one_core::model::certificate::CertificateState;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::credential_schema::{CredentialSchemaClaim, KeyStorageSecurity};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::IdentifierType;
use one_core::model::interaction::InteractionType;
use one_core::proto::jwt::Jwt;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use rcgen::CertificateParams;
use serde_json::json;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::macros::datetime;
use uuid::Uuid;

use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa, fingerprint};
use crate::fixtures::presentation::w3c_jwt_vc;
use crate::fixtures::wallet_provider::create_wallet_unit_attestation_issuer_identifier;
use crate::fixtures::{
    ClaimData, TestingCredentialParams, TestingDidParams, TestingIdentifierParams,
    TestingKeyParams, encrypted_token,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::holder_wallet_unit::TestHolderWalletUnit;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::db_clients::wallet_units::TestWalletUnit;
use crate::utils::field_match::FieldHelpers;

async fn random_document() -> String {
    let key = Ecdsa.generate_key().unwrap();
    let multibase = key.key.public_key_as_multibase().unwrap();
    let did: DidValue = format!("did:key:{multibase}").parse().unwrap();
    w3c_jwt_vc(
        &key,
        "ES256",
        did.clone(),
        did.clone(),
        json!({"string":"value"}),
    )
    .await
}

#[tokio::test]
async fn test_issuance_accept_openid4vc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let issuer_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let metadata_schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: schema_id.into(),
                            key: "string".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: metadata_schema_id.into(),
                            key: "iss".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: true,
                        },
                        required: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", jwt_credential, "JWT", 1, None)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["id"].as_str().unwrap(), credential.id.to_string());

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        holder_did.id,
        credential.holder_identifier.unwrap().did.unwrap().id
    );
    assert_eq!(CredentialStateEnum::Accepted, credential.state);

    let mut claims = credential.claims.unwrap();
    claims.sort_by(|a, b| a.path.cmp(&b.path));
    assert_eq!(claims.len(), 2);
    assert_eq!(claims[0].path, "iss");
    assert_eq!(
        claims[0].value.as_ref().unwrap(),
        &issuer_did.did.to_string()
    );
    assert_eq!(claims[0].selectively_disclosable, false);
    assert_eq!(claims[0].schema.as_ref().unwrap().metadata, true);
    assert_eq!(claims[1].path, "string");
    assert_eq!(claims[1].value.as_ref().unwrap(), "string");
    assert_eq!(claims[1].selectively_disclosable, false);
    assert_eq!(claims[1].schema.as_ref().unwrap().metadata, false);

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    assert_eq!(history.values.len(), 2); // one per state: Accepted + Issued
    assert!(
        history
            .values
            .iter()
            .all(|entry| entry.target == Some(issuer_identifier.id.to_string())),
    );
    let actions = HashSet::from_iter(history.values.iter().map(|value| value.action));
    assert_eq!(
        actions,
        HashSet::from([HistoryAction::Accepted, HistoryAction::Issued])
    );
}

#[tokio::test]
async fn test_issuance_accept_schema_name_already_exists() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let metadata_schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: schema_id.into(),
                            key: "string".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: metadata_schema_id.into(),
                            key: "iss".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: true,
                        },
                        required: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/final-1.0/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "nonce_endpoint": format!("{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/nonce", context.server_mock.uri()),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "credential_metadata": {
            "display": [
                {
                    "lang": "en",
                    "name": "test"
                }
            ]
        },
        "credential_configuration_id": "dummy-config-id",
        "protocol": "OPENID4VCI_FINAL1",
        "format": "jwt_vc_json"
    }))
        .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint_final1(credential_schema.id, "123", jwt_credential, 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "123", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let credential_id = resp.json::<serde_json::Value>().await["id"].parse();
    let credential = context.db.credentials.get(&credential_id).await;
    let credential_schema = credential.schema.as_ref().unwrap();

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    assert_eq!(history.values.len(), 2); // one per state: Accepted + Issued
    let actions = HashSet::from_iter(history.values.iter().map(|value| value.action));
    assert_eq!(
        actions,
        HashSet::from([HistoryAction::Accepted, HistoryAction::Issued])
    );

    // Assert credential schema has been automatically renamed due to clash with existing schema
    // also named "test".
    assert_ne!(credential_schema.name, "test");
    assert!(credential_schema.name.starts_with("test_"));
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_issuer_did_mismatch() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
        .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_credential_endpoint(
            credential_schema.id,
            "123",
            random_document().await,
            "JWT",
            1,
            None,
        )
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0173")
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_issuer_certificate_mismatch() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                is_remote: Some(true),
                ..Default::default()
            },
        )
        .await;
    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);
    let cert = create_cert(
        &mut CertificateParams::default(),
        ecdsa::Key,
        &ca_issuer,
        &ca_params,
    );
    let chain = format!("{}{}", cert.pem(), ca_cert.pem());
    let issuer_cert = context
        .db
        .certificates
        .create(
            issuer_identifier.id,
            TestingCertificateParams {
                name: Some("issuer certificate".to_string()),
                chain: Some(chain),
                fingerprint: Some(fingerprint(&cert)),
                state: Some(CertificateState::Active),
                organisation_id: Some(organisation.id),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
        .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                issuer_certificate: Some(issuer_cert),
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_credential_endpoint(
            credential_schema.id,
            "123",
            random_document().await,
            "JWT",
            1,
            None,
        )
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0173")
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_issuer_invalid_signature() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
        .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    let document = random_document().await;
    let (jwt_content, _sig) = document.rsplit_once(".").unwrap();
    let document_invalid_sig = format!("{jwt_content}.invalid");

    context
        .server_mock
        .ssi_credential_endpoint(
            credential_schema.id,
            "123",
            document_invalid_sig,
            "JWT",
            1,
            None,
        )
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0173")
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_with_key_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"value"}),
    )
    .await;
    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", jwt_credential, "JWT", 1, None)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["id"].as_str().unwrap(), credential.id.to_string());

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        holder_did.id,
        credential.holder_identifier.unwrap().did.unwrap().id
    );
    assert_eq!(key.id, credential.key.unwrap().id);

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_issuance_accept_autogenerate_holder_binding() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        issuer_did.did.clone(),
        json!({"string":"value"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", jwt_credential, "JWT", 1, None)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, None, None, None, None)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["id"].as_str().unwrap(), credential.id.to_string());

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_unknown_did() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(
            interaction.id,
            Some(Uuid::new_v4().into()),
            None,
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0024", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_unknown_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(
            interaction.id,
            holder_did.id,
            Some(Uuid::new_v4().into()),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0037", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_wrong_key_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0096", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_wrong_key_security() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                ..ecdsa_testing_params()
            },
        )
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                key_storage_security: Some(KeyStorageSecurity::EnhancedBasic),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0309", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_no_key_with_auth_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0096", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_wallet_storage_type_not_met() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                key_storage_security: Some(KeyStorageSecurity::High),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0310", resp.error_code().await);
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_with_tx_code() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e",
                "tx_code":{"input_mode":"numeric","length":5,"description":"code"}
            }
        },
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;
    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", jwt_credential, "JWT", 1, None)
        .await;

    let tx_code = "45454";

    context
        .server_mock
        .token_endpoint_tx_code(credential_schema.schema_id, "123", tx_code)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, Some(tx_code), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["id"].as_str().unwrap(), credential.id.to_string());

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        holder_did.id,
        credential.holder_identifier.unwrap().did.unwrap().id
    );

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_update_from_vc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                claims_data: Some(vec![ClaimData {
                    schema_id: schema_id.into(),
                    path: "string".to_string(),
                    value: Some("".to_string()),
                    selectively_disclosable: false,
                }]),
                ..Default::default()
            },
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;
    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", jwt_credential, "JWT", 1, None)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["id"].as_str().unwrap(), credential.id.to_string());

    let credential = context.db.credentials.get(&credential.id).await;
    let claims = credential.claims.unwrap();

    let claim = claims.iter().find(|claim| claim.path == "string").unwrap();

    assert_eq!(claim.value, Some("string".to_string()));
    assert_eq!(claim.schema.as_ref().unwrap().key, "string");
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_update_from_vc_complex() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6MkmbnkXaAsQrxgo9uGVrKSsm5w6jezSr52MwV7RayDWjxL"
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:z6MkviStFZjsFT9KP8R8vaXZJj5i4ouvmHxh7CpGrptzfMHD")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("JSON_LD_CLASSIC".into()),
                claim_schemas: Some(vec![
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "first name".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "last name".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "address".to_string(),
                            data_type: "OBJECT".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "address/postal code".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "address/street".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[0]
                            .schema
                            .id,
                        path: "first name".to_string(),
                        value: Some("John".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[1]
                            .schema
                            .id,
                        path: "last name".to_string(),
                        value: Some("Doe".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[2]
                            .schema
                            .id,
                        path: "address".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[3]
                            .schema
                            .id,
                        path: "address/postal code".to_string(),
                        value: Some("1234".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[4]
                            .schema
                            .id,
                        path: "address/street".to_string(),
                        value: Some("Via Torino".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_credential_endpoint(
            credential_schema.id,
            "123",
            complex_document(),
            "JWT",
            1,
            None,
        )
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["id"].as_str().unwrap(), credential.id.to_string());

    let credential = context.db.credentials.get(&credential.id).await;
    let claims = credential.claims.unwrap();

    let claim = claims
        .iter()
        .find(|claim| claim.path == "first name")
        .unwrap();
    assert_eq!(claim.value, Some("John".to_string()));
    assert_eq!(claim.schema.as_ref().unwrap().key, "first name");

    let claim = claims
        .iter()
        .find(|claim| claim.path == "last name")
        .unwrap();
    assert_eq!(claim.value, Some("Doe".to_string()));
    assert_eq!(claim.schema.as_ref().unwrap().key, "last name");

    let claim = claims
        .iter()
        .find(|claim| claim.path == "address/postal code")
        .unwrap();
    assert_eq!(claim.value, Some("1234".to_string()));
    assert_eq!(claim.schema.as_ref().unwrap().key, "address/postal code");

    let claim = claims
        .iter()
        .find(|claim| claim.path == "address/street")
        .unwrap();
    assert_eq!(claim.value, Some("Via Torino".to_string()));
    assert_eq!(claim.schema.as_ref().unwrap().key, "address/street");
}

fn complex_document() -> &'static str {
    r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                {
                    "ProcivisOneSchema2024": {
                        "@context": {
                            "@protected": true,
                            "id": "@id",
                            "type": "@type",
                            "metadata": {
                                "@id": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#metadata",
                                "@type": "@json"
                            }
                        },
                        "@id": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#ProcivisOneSchema2024"
                    },
                    "SimpleTest": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#SimpleTest",
                    "last name": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#last%20name",
                    "first name": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#first%20name",
                    "address": {
                        "@context": {
                            "@protected": true,
                            "id": "@id",
                            "type": "@type",
                            "postal code": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#postal%20code",
                            "street": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#street"
                        },
                        "@id": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#address"
                    }
                }
            ],
            "type": [
                "VerifiableCredential",
                "SimpleTest"
            ],
            "issuer": "did:key:z6MkmbnkXaAsQrxgo9uGVrKSsm5w6jezSr52MwV7RayDWjxL",
            "validFrom": "2025-03-10T22:13:36.652829Z",
            "validUntil": "2027-03-10T22:13:36.652829Z",
            "credentialSubject": {
                "id": "did:key:z6MkviStFZjsFT9KP8R8vaXZJj5i4ouvmHxh7CpGrptzfMHD",
                "first name": "John",
                "last name": "Doe",
                "address": {
                    "postal code": "1234",
                    "street": "Via Torino"
                }
            },
            "proof": {
                "type": "DataIntegrityProof",
                "created": "2025-03-10T22:13:36.653229Z",
                "cryptosuite": "eddsa-rdfc-2022",
                "verificationMethod": "did:key:z6MkmbnkXaAsQrxgo9uGVrKSsm5w6jezSr52MwV7RayDWjxL#z6MkmbnkXaAsQrxgo9uGVrKSsm5w6jezSr52MwV7RayDWjxL",
                "proofPurpose": "assertionMethod",
                "proofValue": "z3VzJfDiE21cCnhVufh6C9uGHibe7gsn5v2D4DN8w9FZaSTUMqq8wPEtiaCEPKkpSxXAvpjvPj5QMKZJCLtpZGBf7"
            },
            "credentialSchema": {
                "id": "http://0.0.0.0:3000/ssi/schema/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f",
                "type": "ProcivisOneSchema2024"
            }
        }"#
}

#[tokio::test]
async fn test_waa_pop_iss_equals_waa_sub() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    create_wallet_unit_attestation_issuer_identifier(&context, &organisation).await;

    let holder_key_params = ecdsa_testing_params();
    let holder_public_jwk = Ecdsa
        .reconstruct_key(holder_key_params.public_key.as_ref().unwrap(), None, None)
        .unwrap()
        .public_key_as_jwk()
        .unwrap();

    let holder_auth_key = context
        .db
        .keys
        .create(&organisation, holder_key_params)
        .await;

    let wallet_unit = context
        .db
        .wallet_units
        .create(
            organisation.clone(),
            TestWalletUnit {
                public_key: Some(holder_public_jwk),
                ..Default::default()
            },
        )
        .await;

    let holder_wallet_unit = context
        .db
        .holder_wallet_units
        .create(
            organisation.clone(),
            holder_auth_key,
            TestHolderWalletUnit {
                wallet_provider_url: Some(context.config.app.core_base_url.clone()),
                provider_wallet_unit_id: Some(wallet_unit.id),
                ..Default::default()
            },
        )
        .await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let holder_did_key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: holder_did_key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test_waa_pop",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/final-1.0/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/final-1.0/{}/token", context.server_mock.uri(), credential_schema.id),
        "nonce_endpoint": format!("{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/nonce", context.server_mock.uri()),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "credential_metadata": {
            "display": [
                {
                    "lang": "en",
                    "name": "test_waa_pop"
                }
            ]
        },
        "credential_configuration_id": "dummy-config-id",
        "protocol": "OPENID4VCI_FINAL1",
        "format": "jwt_vc_json",
        "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth"]
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"value"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint_final1(credential_schema.id, "123", jwt_credential, 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint_final1(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(
            interaction.id,
            holder_did.id,
            None,
            None,
            holder_wallet_unit.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let requests = context.server_mock.received_requests().await.unwrap();
    let token_request = requests
        .iter()
        .find(|r| r.url.path().contains("/token"))
        .expect("Token request not found");

    let waa_header = token_request
        .headers
        .get("oauth-client-attestation")
        .expect("OAuth-Client-Attestation header not found");
    let waa_pop_header = token_request
        .headers
        .get("oauth-client-attestation-pop")
        .expect("OAuth-Client-Attestation-PoP header not found");

    let waa =
        Jwt::<()>::decompose_token(waa_header.to_str().unwrap()).expect("Failed to parse WAA JWT");
    let waa_pop = Jwt::<()>::decompose_token(waa_pop_header.to_str().unwrap())
        .expect("Failed to parse WAA PoP JWT");

    assert_eq!(
        waa_pop.payload.issuer, waa.payload.subject,
        "WAA PoP 'iss' must equal WAA 'sub' per OAuth Attestation-Based Client Auth spec section 5.2"
    );

    assert_eq!(
        waa.payload.subject,
        Some("eudiw-abca".to_string()),
        "WAA 'sub' should be wallet_client_id from config"
    );
}
