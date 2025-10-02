use std::collections::{HashMap, HashSet};

use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
    WalletStorageTypeEnum,
};
use crate::model::interaction::Interaction;
use crate::provider::verification_protocol::dto::{CredentialGroup, CredentialGroupItem};
use crate::provider::verification_protocol::mapper::get_relevant_credentials_to_credential_schemas;
use crate::service::storage_proxy::MockStorageProxy;
use crate::service::test_utilities::{dummy_organisation, get_dummy_date};

fn object_datatypes() -> HashSet<&'static str> {
    HashSet::from(["OBJECT"])
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_success_jwt() {
    let mut storage = MockStorageProxy::new();
    let mut credential = dummy_credential();
    credential.state = CredentialStateEnum::Accepted;

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "key".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            inapplicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["JWT".to_string()]),
        &object_datatypes(),
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
    assert_eq!(credential.id, result_credentials[0].id);
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_empty_missing_required_claims_simple()
{
    let mut storage = MockStorageProxy::new();
    let mut credential = dummy_credential();

    credential
        .schema
        .as_mut()
        .unwrap()
        .claim_schemas
        .as_mut()
        .unwrap()
        .push(CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "optkey".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
                metadata: false,
            },
            required: false,
        });

    credential.state = CredentialStateEnum::Accepted;

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
            claims: vec![
                CredentialGroupItem {
                    id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                    key: "key".to_string(),
                    required: true,
                },
                CredentialGroupItem {
                    id: "4ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                    key: "optkey".to_string(),
                    required: true,
                },
            ],
            applicable_credentials: vec![],
            inapplicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["JWT".to_string()]),
        &object_datatypes(),
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_failed_wrong_state() {
    let mut storage = MockStorageProxy::new();
    let credential = dummy_credential();

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "key".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            inapplicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["JWT".to_string()]),
        &object_datatypes(),
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    assert_eq!(0, result_credentials.len());
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_failed_format_not_allowed() {
    let mut storage = MockStorageProxy::new();
    let mut credential = dummy_credential();
    credential.state = CredentialStateEnum::Accepted;

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "key".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            inapplicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["SD_JWT".to_string()]),
        &object_datatypes(),
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    assert_eq!(0, result_credentials.len());
}

fn mdoc_credential() -> Credential {
    let mut credential = dummy_credential();

    let new_claim_schemas = [
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespace".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespace/name".to_string(),
            data_type: "STRING".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
        },
    ];

    credential.state = CredentialStateEnum::Accepted;
    let schema = credential.schema.as_mut().unwrap();
    schema.format = "MDOC".to_string();
    *schema.claim_schemas.as_mut().unwrap() = vec![
        CredentialSchemaClaim {
            schema: new_claim_schemas[0].to_owned(),
            required: true,
        },
        CredentialSchemaClaim {
            schema: new_claim_schemas[1].to_owned(),
            required: true,
        },
    ];
    *credential.claims.as_mut().unwrap() = vec![Claim {
        id: Uuid::new_v4(),
        credential_id: credential.id.to_owned(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("john".to_string()),
        path: new_claim_schemas[1].key.clone(),
        selectively_disclosable: false,
        schema: Some(new_claim_schemas[1].to_owned()),
    }];

    credential
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_success_mdoc() {
    let mut storage = MockStorageProxy::new();
    let credential = mdoc_credential();

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "namespace/name".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            inapplicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["MDOC".to_string()]),
        &object_datatypes(),
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_when_first_level_selected() {
    let mut storage = MockStorageProxy::new();
    let credential = mdoc_credential();

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let (result_credentials, result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "namespace".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            inapplicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["MDOC".to_string()]),
        &object_datatypes(),
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
    assert_eq!(1, result_group.len());
    assert_eq!(1, result_group[0].applicable_credentials.len());
    assert_eq!(0, result_group[0].inapplicable_credentials.len());
}

fn mdoc_credential_with_optional_namespace() -> Credential {
    let mut credential = mdoc_credential();

    let new_claim_schemas = [
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespaceReq".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespaceReq/name".to_string(),
            data_type: "STRING".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespaceOpt".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespaceOpt/obj".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespaceOpt/obj/name".to_string(),
            data_type: "STRING".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
        },
    ];

    let schema = credential.schema.as_mut().unwrap();
    *schema.claim_schemas.as_mut().unwrap() = new_claim_schemas
        .iter()
        .map(|claim_schema| CredentialSchemaClaim {
            schema: claim_schema.to_owned(),
            required: claim_schema.key.as_str() != "namespaceOpt",
        })
        .collect();
    *credential.claims.as_mut().unwrap() = vec![Claim {
        id: Uuid::new_v4(),
        credential_id: credential.id.to_owned(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("john".to_string()),
        path: new_claim_schemas[1].key.clone(),
        selectively_disclosable: false,
        schema: Some(new_claim_schemas[1].to_owned()),
    }];

    credential
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_when_missing_object_selected() {
    let mut storage = MockStorageProxy::new();
    let credential = mdoc_credential_with_optional_namespace();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential]));

    let (result_credentials, result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "namespaceOpt/obj".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            inapplicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["MDOC".to_string()]),
        &object_datatypes(),
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
    assert_eq!(1, result_group.len());
    assert_eq!(0, result_group[0].applicable_credentials.len());
    assert_eq!(1, result_group[0].inapplicable_credentials.len());
}

fn dummy_credential() -> Credential {
    let claim_schema_id = Uuid::new_v4().into();
    let credential_id = Uuid::new_v4().into();
    Credential {
        id: credential_id,
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: "protocol".to_string(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Pending,
        suspend_end_date: None,
        profile: None,
        claims: Some(vec![Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            value: Some("claim value".to_string()),
            path: "key".to_string(),
            selectively_disclosable: false,
            schema: Some(ClaimSchema {
                id: claim_schema_id,
                key: "key".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
                metadata: false,
            }),
        }]),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            imported_source_url: "CORE_URL".to_string(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            external_schema: false,
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "revocation method".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: claim_schema_id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    array: false,
                    metadata: false,
                },
                required: true,
            }]),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            organisation: Some(dummy_organisation(None)),
            allow_suspension: true,
        }),
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            host: Some("https://core.dev.one-trust-solution.com".parse().unwrap()),
            data: Some(b"interaction data".to_vec()),
            last_modified: OffsetDateTime::now_utc(),
            organisation: None,
            nonce_id: None,
        }),
        key: None,
        revocation_list: None,
        credential_blob_id: Some(Uuid::new_v4().into()),
        wallet_unit_attestation_blob_id: None,
    }
}
