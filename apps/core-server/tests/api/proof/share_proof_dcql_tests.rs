use std::collections::HashMap;
use std::str::FromStr;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::model::history::HistoryAction;
use one_core::model::interaction::InteractionType;
use one_core::model::proof::{ProofRole, ProofStateEnum};
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{self, assert_history_count};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

async fn create_dcql_test_context() -> (
    TestContext,
    one_core::model::organisation::Organisation,
    one_core::model::did::Did,
    one_core::model::identifier::Identifier,
    one_core::model::key::Key,
) {
    TestContext::new_with_did(Some(
        indoc::indoc! {"
        verificationProtocol:
          OPENID4VP_FINAL1:
            params:
              public:
                useRequestUri: false
          "}
        .to_string(),
    ))
    .await
}

async fn create_credential_schema_with_claims(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
    name: &str,
    format: &str,
    schema_id: &str,
    claim_schemas: &[(Uuid, &str, bool, &str, bool)],
) -> one_core::model::credential_schema::CredentialSchema {
    context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            name,
            organisation,
            claim_schemas,
            format,
            schema_id,
        )
        .await
}

async fn create_proof_with_claims(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
    identifier: &one_core::model::identifier::Identifier,
    key: &one_core::model::key::Key,
    credential_schema: &one_core::model::credential_schema::CredentialSchema,
    proof_claims: Vec<CreateProofClaim<'_>>,
) -> one_core::model::proof::Proof {
    let proof_schema = fixtures::create_proof_schema(
        &context.db.db_conn,
        "test",
        organisation,
        &[CreateProofInputSchema {
            claims: proof_claims,
            credential_schema,
        }],
    )
    .await;

    fixtures::create_proof(
        &context.db.db_conn,
        identifier,
        Some(&proof_schema),
        ProofStateEnum::Created,
        ProofRole::Verifier,
        "OPENID4VP_FINAL1",
        None,
        Some(key),
        None,
        None,
    )
    .await
}

async fn share_proof_and_extract_dcql(
    context: &TestContext,
    proof_id: shared_types::ProofId,
) -> (Value, Value) {
    let resp = context.api.proofs.share(proof_id, None).await;
    assert_eq!(resp.status(), 201);

    let proof = context.db.proofs.get(&proof_id).await;
    let interaction = proof.interaction.as_ref().unwrap().as_ref().await.unwrap();
    let data: Value = serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();

    // presentation_definition should not be in the json value
    assert_eq!(data["presentation_definition"], serde_json::Value::Null);
    let credential_query = data["dcql_query"].to_owned();

    (data, credential_query)
}

#[tokio::test]
async fn test_share_proof_dcql_jwt_success() {
    // GIVEN
    let (context, organisation, _, identifier, key) = create_dcql_test_context().await;

    let name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap();
    let email_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap();
    let age_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap();

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (name_claim_id, "name", true, "STRING", false),
        (email_claim_id, "email", true, "STRING", false),
        (age_claim_id, "age", true, "NUMBER", false),
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context,
        &organisation,
        "PersonalInfo",
        "JWT",
        "test",
        &claim_schemas,
    )
    .await;

    let proof = create_proof_with_claims(
        &context,
        &organisation,
        &identifier,
        &key,
        &credential_schema,
        vec![
            CreateProofClaim {
                id: name_claim_id.into(),
                key: "name",
                required: true,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: email_claim_id.into(),
                key: "email",
                required: false,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: age_claim_id.into(),
                key: "age",
                required: false,
                data_type: "NUMBER",
                array: false,
            },
        ],
    )
    .await;

    // WHEN & THEN
    let (_data, credential_query) = share_proof_and_extract_dcql(&context, proof.id).await;

    let expected = serde_json::json!({
        "credential_sets": [{
            "required": true,
            "options": [[credential_schema.formats.as_ref().await.unwrap()[0].id]]
        }],
        "credentials": [
            {
                "claim_sets": [
                    [
                        name_claim_id,
                        email_claim_id,
                        age_claim_id
                    ], [
                        name_claim_id,
                    ]
                ],
                "claims": [
                    {
                        "id": name_claim_id,
                        "path": ["vc", "credentialSubject", "name"],
                        "required": true,
                    },
                    {
                        "id": email_claim_id,
                        "path": ["vc", "credentialSubject", "email"],
                        "required": false,
                    },
                    {
                        "id": age_claim_id,
                        "path": ["vc", "credentialSubject", "age"],
                        "required": false,
                    }
                ],
                "format": "jwt_vc_json",
                "id": credential_schema.formats.as_ref().await.unwrap()[0].id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id().await.unwrap(), credential_schema.name),
                        ],
                        [credential_schema.name.to_string()]
                    ]
                }
            }
        ]
    });

    assert_eq!(credential_query, expected);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_dcql_mdoc_success() {
    // GIVEN
    let (context, organisation, _, identifier, key) = create_dcql_test_context().await;

    let namespace_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap();
    let given_name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap();
    let family_name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap();
    let birth_date_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c43").unwrap();

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (
            namespace_claim_id,
            "org.iso.18013.5.1",
            true,
            "OBJECT",
            false,
        ),
        (
            given_name_claim_id,
            "org.iso.18013.5.1/given_name",
            true,
            "STRING",
            false,
        ),
        (
            family_name_claim_id,
            "org.iso.18013.5.1/family_name",
            true,
            "STRING",
            false,
        ),
        (
            birth_date_claim_id,
            "org.iso.18013.5.1/birth_date",
            true,
            "STRING",
            false,
        ),
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context,
        &organisation,
        "mDL",
        "MDOC",
        "org.iso.18013.5.1.mDL",
        &claim_schemas,
    )
    .await;

    let proof = create_proof_with_claims(
        &context,
        &organisation,
        &identifier,
        &key,
        &credential_schema,
        vec![
            CreateProofClaim {
                id: given_name_claim_id.into(),
                key: "org.iso.18013.5.1/given_name",
                required: true,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: family_name_claim_id.into(),
                key: "org.iso.18013.5.1/family_name",
                required: true,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: birth_date_claim_id.into(),
                key: "org.iso.18013.5.1/birth_date",
                required: false,
                data_type: "STRING",
                array: false,
            },
        ],
    )
    .await;

    // WHEN & THEN
    let (_data, credential_query) = share_proof_and_extract_dcql(&context, proof.id).await;

    let expected = serde_json::json!({
        "credential_sets": [{
            "required": true,
            "options": [[credential_schema.formats.as_ref().await.unwrap()[0].id]]
        }],
        "credentials": [
            {
                "claim_sets": [
                    [
                        given_name_claim_id,
                        family_name_claim_id,
                        birth_date_claim_id
                    ], [
                        given_name_claim_id,
                        family_name_claim_id
                    ]
                ],
                "claims": [
                    {
                        "id": given_name_claim_id,
                        "path": ["org.iso.18013.5.1", "given_name"],
                        "required": true,
                        "intent_to_retain": true
                    },
                    {
                        "id": family_name_claim_id,
                        "path": ["org.iso.18013.5.1", "family_name"],
                        "required": true,
                        "intent_to_retain": true
                    },
                    {
                        "id": birth_date_claim_id,
                        "path": ["org.iso.18013.5.1", "birth_date"],
                        "required": false,
                        "intent_to_retain": true
                    }
                ],
                "format": "mso_mdoc",
                "id": credential_schema.formats.as_ref().await.unwrap()[0].id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL"
                }
            }
        ]
    });

    assert_eq!(credential_query, expected);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_dcql_jsonld_success() {
    // GIVEN
    let (context, organisation, _, identifier, key) = create_dcql_test_context().await;

    let name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap();
    let email_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap();
    let age_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap();

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (name_claim_id, "name", true, "STRING", false),
        (email_claim_id, "email", true, "STRING", false),
        (age_claim_id, "age", true, "NUMBER", false),
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context,
        &organisation,
        "PersonalInfo",
        "JSON_LD_CLASSIC",
        "test",
        &claim_schemas,
    )
    .await;

    let proof = create_proof_with_claims(
        &context,
        &organisation,
        &identifier,
        &key,
        &credential_schema,
        vec![
            CreateProofClaim {
                id: name_claim_id.into(),
                key: "name",
                required: true,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: email_claim_id.into(),
                key: "email",
                required: false,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: age_claim_id.into(),
                key: "age",
                required: false,
                data_type: "NUMBER",
                array: false,
            },
        ],
    )
    .await;

    // WHEN & THEN
    let (_data, credential_query) = share_proof_and_extract_dcql(&context, proof.id).await;

    let expected = serde_json::json!({
        "credential_sets": [{
            "required": true,
            "options": [[credential_schema.formats.as_ref().await.unwrap()[0].id]]
        }],
        "credentials": [
            {
                "claim_sets": [
                    [
                        name_claim_id,
                        email_claim_id,
                        age_claim_id
                    ], [
                        name_claim_id,
                    ]
                ],
                "claims": [
                    {
                        "id": name_claim_id,
                        "path": ["credentialSubject", "name"],
                        "required": true,
                    },
                    {
                        "id": email_claim_id,
                        "path": ["credentialSubject", "email"],
                        "required": false,
                    },
                    {
                        "id": age_claim_id,
                        "path": ["credentialSubject", "age"],
                        "required": false,
                    }
                ],
                "format": "ldp_vc",
                "id": credential_schema.formats.as_ref().await.unwrap()[0].id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id().await.unwrap(), credential_schema.name)],
                        [credential_schema.name.to_string()]
                    ]
                }
            }
        ]
    });

    assert_eq!(credential_query, expected);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_dcql_jsonld_bbs_success() {
    // GIVEN
    let (context, organisation, _, identifier, key) = create_dcql_test_context().await;

    let name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap();
    let email_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap();
    let age_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap();

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (name_claim_id, "name", true, "STRING", false),
        (email_claim_id, "email", true, "STRING", false),
        (age_claim_id, "age", true, "NUMBER", false),
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context,
        &organisation,
        "PersonalInfo",
        "JSON_LD_BBSPLUS",
        "test",
        &claim_schemas,
    )
    .await;

    let proof = create_proof_with_claims(
        &context,
        &organisation,
        &identifier,
        &key,
        &credential_schema,
        vec![
            CreateProofClaim {
                id: name_claim_id.into(),
                key: "name",
                required: true,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: email_claim_id.into(),
                key: "email",
                required: false,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: age_claim_id.into(),
                key: "age",
                required: false,
                data_type: "NUMBER",
                array: false,
            },
        ],
    )
    .await;

    // WHEN & THEN
    let (_data, credential_query) = share_proof_and_extract_dcql(&context, proof.id).await;

    let expected = serde_json::json!({
        "credential_sets": [{
            "required": true,
            "options": [[credential_schema.formats.as_ref().await.unwrap()[0].id]]
        }],
        "credentials": [
            {
                "claim_sets": [
                    [
                        name_claim_id,
                        email_claim_id,
                        age_claim_id
                    ], [
                        name_claim_id,
                    ]
                ],
                "claims": [
                    {
                        "id": name_claim_id,
                        "path": ["credentialSubject", "name"],
                        "required": true,
                    },
                    {
                        "id": email_claim_id,
                        "path": ["credentialSubject", "email"],
                        "required": false,
                    },
                    {
                        "id": age_claim_id,
                        "path": ["credentialSubject", "age"],
                        "required": false,
                    }
                ],
                "format": "ldp_vc",
                "id": credential_schema.formats.as_ref().await.unwrap()[0].id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id().await.unwrap(), credential_schema.name)],
                        [credential_schema.name.to_string()]
                    ]
                }
            }
        ]
    });

    assert_eq!(credential_query, expected);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_dcql_sd_jwt_success() {
    // GIVEN
    let (context, organisation, _, identifier, key) = create_dcql_test_context().await;

    let given_name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap();
    let family_name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap();
    let age_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap();

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (given_name_claim_id, "given_name", true, "STRING", false),
        (family_name_claim_id, "family_name", true, "STRING", false),
        (age_claim_id, "age", true, "NUMBER", false),
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context,
        &organisation,
        "PersonalInfo",
        "SD_JWT",
        "https://credentials.example.com/identity_credential",
        &claim_schemas,
    )
    .await;

    let proof = create_proof_with_claims(
        &context,
        &organisation,
        &identifier,
        &key,
        &credential_schema,
        vec![
            CreateProofClaim {
                id: given_name_claim_id.into(),
                key: "given_name",
                required: true,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: family_name_claim_id.into(),
                key: "family_name",
                required: false,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: age_claim_id.into(),
                key: "age",
                required: false,
                data_type: "NUMBER",
                array: false,
            },
        ],
    )
    .await;

    // WHEN & THEN
    let (_data, credential_query) = share_proof_and_extract_dcql(&context, proof.id).await;

    let expected = serde_json::json!({
        "credential_sets": [{
            "required": true,
            "options": [[credential_schema.formats.as_ref().await.unwrap()[0].id]]
        }],
        "credentials": [
            {
                "claim_sets": [
                    [
                        given_name_claim_id,
                        family_name_claim_id,
                        age_claim_id
                    ], [
                        given_name_claim_id,
                    ]
                ],
                "claims": [
                    {
                        "id": given_name_claim_id,
                        "path": ["vc", "credentialSubject", "given_name"],
                        "required": true,
                    },
                    {
                        "id": family_name_claim_id,
                        "path": ["vc","credentialSubject", "family_name"],
                        "required": false,
                    },
                    {
                        "id": age_claim_id,
                        "path": ["vc","credentialSubject", "age"],
                        "required": false,
                    }
                ],
                "format": "vc+sd-jwt",
                "id": credential_schema.formats.as_ref().await.unwrap()[0].id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id().await.unwrap(), credential_schema.name)
                        ],
                        [credential_schema.name.to_string()]
                    ]
                }
            }
        ]
    });

    assert_eq!(credential_query, expected);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_dcql_sd_jwt_vc_success() {
    let (context, organisation, _, identifier, key) = create_dcql_test_context().await;

    let given_name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap();
    let family_name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap();
    let age_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap();

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (given_name_claim_id, "given_name", true, "STRING", false),
        (family_name_claim_id, "family_name", true, "STRING", false),
        (age_claim_id, "age", true, "NUMBER", false),
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context,
        &organisation,
        "PersonalInfo",
        "SD_JWT_VC",
        "https://credentials.example.com/identity_credential",
        &claim_schemas,
    )
    .await;

    let proof = create_proof_with_claims(
        &context,
        &organisation,
        &identifier,
        &key,
        &credential_schema,
        vec![
            CreateProofClaim {
                id: given_name_claim_id.into(),
                key: "given_name",
                required: true,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: family_name_claim_id.into(),
                key: "family_name",
                required: false,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: age_claim_id.into(),
                key: "age",
                required: false,
                data_type: "NUMBER",
                array: false,
            },
        ],
    )
    .await;

    // WHEN & THEN
    let (_data, credential_query) = share_proof_and_extract_dcql(&context, proof.id).await;

    let expected = serde_json::json!({
        "credential_sets": [{
            "required": true,
            "options": [[credential_schema.formats.as_ref().await.unwrap()[0].id]]
        }],
        "credentials": [
            {
                "claim_sets": [
                    [
                        given_name_claim_id,
                        family_name_claim_id,
                        age_claim_id
                    ], [
                        given_name_claim_id,
                    ]
                ],
                "claims": [
                    {
                        "id": given_name_claim_id,
                        "path": ["given_name"],
                        "required": true,
                    },
                    {
                        "id": family_name_claim_id,
                        "path": ["family_name"],
                        "required": false,
                    },
                    {
                        "id": age_claim_id,
                        "path": ["age"],
                        "required": false,
                    }
                ],
                "format": "dc+sd-jwt",
                "id": credential_schema.formats.as_ref().await.unwrap()[0].id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "vct_values": [credential_schema.schema_id().await.unwrap()]
                }
            }
        ]
    });

    assert_eq!(credential_query, expected);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_dcql_nested_object_with_array_success() {
    // GIVEN
    let (context, organisation, _, identifier, key) = create_dcql_test_context().await;

    let profile_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap();
    let name_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap();
    let address_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap();
    let phone_numbers_claim_id = Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c43").unwrap();

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (profile_claim_id, "profile", true, "OBJECT", false),
        (name_claim_id, "profile/name", true, "STRING", false),
        (address_claim_id, "profile/address", true, "OBJECT", false),
        (
            phone_numbers_claim_id,
            "profile/address/phoneNumbers",
            true,
            "STRING",
            true,
        ),
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context,
        &organisation,
        "UserProfile",
        "JWT",
        "test-profile",
        &claim_schemas,
    )
    .await;

    let proof = create_proof_with_claims(
        &context,
        &organisation,
        &identifier,
        &key,
        &credential_schema,
        vec![
            CreateProofClaim {
                id: name_claim_id.into(),
                key: "profile/name",
                required: true,
                data_type: "STRING",
                array: false,
            },
            CreateProofClaim {
                id: phone_numbers_claim_id.into(),
                key: "profile/address/phoneNumbers",
                required: true,
                data_type: "STRING",
                array: true,
            },
        ],
    )
    .await;

    // WHEN & THEN
    let (_data, credential_query) = share_proof_and_extract_dcql(&context, proof.id).await;

    let expected = serde_json::json!({
        "credential_sets": [{
            "required": true,
            "options": [[credential_schema.formats.as_ref().await.unwrap()[0].id]]
        }],
        "credentials": [
            {
                "claims": [
                    {
                        "id": name_claim_id,
                        "path": ["vc", "credentialSubject", "profile", "name"],
                        "required": true,
                    },
                    {
                        "id": phone_numbers_claim_id,
                        "path": ["vc", "credentialSubject", "profile", "address", "phoneNumbers"],
                        "required": true,
                    }
                ],
                "format": "jwt_vc_json",
                "id": credential_schema.formats.as_ref().await.unwrap()[0].id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id().await.unwrap(), credential_schema.name)
                        ],
                        [credential_schema.name.to_string()]
                    ]
                }
            }
        ]
    });

    assert_eq!(credential_query, expected);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[rstest::rstest]
#[case::optional_companion(false)]
#[case::required_companion(true)]
#[tokio::test]
async fn test_share_proof_dcql_multiple_options_and_transaction_data(
    #[case] companion_required: bool,
) {
    let (context, organisation, _, identifier, key) = create_dcql_test_context().await;
    let mut schema = context
        .db
        .credential_schemas
        .create(
            "Identity",
            &organisation,
            TestingCreateSchemaParams {
                formats: Some(vec![
                    ("SD_JWT_VC".into(), "identity-vct".into()),
                    ("MDOC".into(), "identity-mdoc".into()),
                ]),
                claim_mappings: Some(HashMap::from([(
                    "firstName".to_string(),
                    "namespace/firstName".to_string(),
                )])),
                ..Default::default()
            },
        )
        .await;
    let mut formats = schema.formats.as_ref().await.unwrap().to_vec();
    formats.sort_by_key(|format| format.format == "MDOC".into());
    let sdjwt_id = formats[0].id;
    let mdoc_id = formats[1].id;
    schema.formats = formats.into();
    let companion = context
        .db
        .credential_schemas
        .create(
            "Companion",
            &organisation,
            TestingCreateSchemaParams {
                schema_id: Some("companion-schema".to_string()),
                ..Default::default()
            },
        )
        .await;
    let companion_id = companion.formats.as_ref().await.unwrap()[0].id;
    let claim = schema.claim_schemas.as_ref().await.unwrap()[0].clone();
    let companion_claim = companion.claim_schemas.as_ref().await.unwrap()[0].clone();
    let main_claims = [(Uuid::from(claim.id), "firstName", true, "STRING", false)];
    let companion_claims = [(
        Uuid::from(companion_claim.id),
        "firstName",
        companion_required,
        "STRING",
        false,
    )];
    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "Multi-format proof",
            &organisation,
            vec![
                CreateProofInputSchema::from((&main_claims[..], &schema)),
                CreateProofInputSchema::from((&companion_claims[..], &companion)),
            ],
        )
        .await;
    let tx_data = json!({
        "numSignatures": 1,
        "signatureQualifier": "eu_eidas_qes",
        "documentInfos": [{
            "label": "Contract",
            "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "hashType": "sodr", "access": {"type": "public"},
            "href": "https://example.com/contract.pdf",
            "checksum": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="
        }],
        "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
    });
    let mut encoded_data = tx_data.clone();
    encoded_data["type"] =
        json!(standardized_types::csc::transaction_data::QES_APPROVAL_TRANSACTION_DATA_TYPE);
    encoded_data["credential_ids"] = json!([sdjwt_id, mdoc_id]);
    let encoded =
        Base64UrlSafeNoPadding::encode_to_string(serde_json::to_vec(&encoded_data).unwrap())
            .unwrap();
    let transaction_data = json!([{
        "type": "QES_APPROVAL",
        "credential_ids": [sdjwt_id, mdoc_id],
        "data": tx_data,
        "encoded": encoded
    }]);
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        &serde_json::to_vec(&json!({"transaction_data": transaction_data})).unwrap(),
        &organisation,
        InteractionType::Verification,
    )
    .await;
    let proof = fixtures::create_proof(
        &context.db.db_conn,
        &identifier,
        Some(&proof_schema),
        ProofStateEnum::Created,
        ProofRole::Verifier,
        "OPENID4VP_FINAL1",
        Some(&interaction),
        Some(&key),
        None,
        None,
    )
    .await;

    let (data, query) = share_proof_and_extract_dcql(&context, proof.id).await;

    let mut expected = json!({
        "credentials": [
            {
                "id": sdjwt_id,
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["identity-vct"]},
                "claims": [{"id": claim.id, "path": ["namespace", "firstName"], "required": true}],
                "multiple": false,
                "require_cryptographic_holder_binding": true
            },
            {
                "id": mdoc_id,
                "format": "mso_mdoc",
                "meta": {"doctype_value": "identity-mdoc"},
                "claims": [{"id": claim.id, "path": ["namespace", "firstName"], "required": true, "intent_to_retain": true}],
                "multiple": false,
                "require_cryptographic_holder_binding": true
            },
            {
                "id": companion_id,
                "format": "jwt_vc_json",
                "meta": {"type_values": [
                    ["https://www.w3.org/2018/credentials#VerifiableCredential", "companion-schema#Companion"],
                    ["Companion"]
                ]},
                "claims": [{"id": companion_claim.id, "path": ["vc", "credentialSubject", "firstName"], "required": companion_required}],
                "multiple": false,
                "require_cryptographic_holder_binding": true
            }
        ],
        "credential_sets": [
            {"required": true, "options": [[sdjwt_id], [mdoc_id]]},
            {"required": companion_required, "options": [[companion_id]]}
        ]
    });
    if !companion_required {
        expected["credentials"][2]["claim_sets"] = json!([[companion_claim.id], []]);
    }
    assert_eq!(query, expected);
    assert_eq!(data["transaction_data"], transaction_data);
}
