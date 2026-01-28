use std::str::FromStr;

use one_core::model::history::HistoryAction;
use one_core::model::proof::{ProofRole, ProofStateEnum};
use serde_json::Value;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{self, assert_history_count};
use crate::utils::context::TestContext;
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
          OPENID4VP_DRAFT25:
            params:
              public:
                useRequestUri: false
                verifier:
                  useDcql: true
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
            None,
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
            validity_constraint: None,
        }],
    )
    .await;

    fixtures::create_proof(
        &context.db.db_conn,
        identifier,
        Some(&proof_schema),
        ProofStateEnum::Created,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT25",
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
    let interaction = proof.interaction.unwrap();
    let data: Value = serde_json::from_slice(&interaction.data.unwrap()).unwrap();

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
                "id": credential_schema.id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id, credential_schema.name),
                        ],
                        [format!("{}", credential_schema.name)]
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
                "id": credential_schema.id,
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
                "id": credential_schema.id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id, credential_schema.name)],
                        [format!("{}", credential_schema.name)]
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
                "id": credential_schema.id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id, credential_schema.name)],
                        [format!("{}", credential_schema.name)]
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
                "id": credential_schema.id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id, credential_schema.name)
                        ],
                        [format!("{}", credential_schema.name)]
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
                "id": credential_schema.id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "vct_values": [credential_schema.schema_id.clone()]
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
                "id": credential_schema.id,
                "multiple": false,
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "type_values": [
                        [
                          "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
                          format!("{}#{}", credential_schema.schema_id, credential_schema.name)
                        ],
                        [format!("{}", credential_schema.name)]
                    ]
                }
            }
        ]
    });

    assert_eq!(credential_query, expected);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}
