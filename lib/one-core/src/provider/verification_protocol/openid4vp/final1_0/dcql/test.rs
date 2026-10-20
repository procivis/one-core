use std::sync::Arc;

use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::*;
use crate::model::proof_schema::ProofInputSchema;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::service::test_utilities::{
    dummy_claim_schema, dummy_credential_schema, dummy_proof_schema, generic_config,
};

fn formatter_provider() -> MockCredentialFormatterProvider {
    let mut provider = MockCredentialFormatterProvider::new();
    provider
        .expect_get_credential_formatter()
        .returning(|name| {
            let prefix = if name == &"JWT".into() {
                vec!["vc".to_string(), "credentialSubject".to_string()]
            } else {
                vec![]
            };
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_user_claims_path().return_const(prefix);
            Ok(Arc::new(formatter))
        });
    provider
}

async fn input(required: bool) -> ProofInputSchema {
    let mut schema = dummy_credential_schema();
    let claim = dummy_claim_schema();
    let optional_claim = dummy_claim_schema();
    let template = schema.formats.as_ref().await.unwrap()[0].clone();
    let formats = ["JWT", "SD_JWT_VC", "MDOC"].map(|name| {
        let mut format = template.clone();
        format.id = Uuid::new_v4().into();
        format.format = name.into();
        format.ecosystem_schema_id = format!("{name}-schema");
        format.claim_mappings = [&claim, &optional_claim]
            .into_iter()
            .enumerate()
            .map(|(index, claim)| CredentialSchemaFormatClaimSchema {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                credential_schema_format_id: format.id,
                claim_schema_id: claim.id,
                technical_key: if index == 0 {
                    "given_name"
                } else {
                    "family_name"
                }
                .to_string(),
                namespace: (name == "MDOC").then(|| "org.example".to_string()),
            })
            .collect::<Vec<_>>()
            .into();
        format
    });
    schema.formats = formats.to_vec().into();
    ProofInputSchema {
        formats: vec!["MDOC".into(), "SD_JWT_VC".into()],
        credential_schema: schema.into(),
        claim_schemas: vec![
            ProofInputClaimSchema {
                schema: claim,
                required,
                order: 0,
            },
            ProofInputClaimSchema {
                schema: optional_claim,
                required: false,
                order: 1,
            },
        ]
        .into(),
    }
}

async fn query(inputs: Vec<ProofInputSchema>) -> Result<DcqlQuery, VerificationProtocolError> {
    let proof_schema = ProofSchema {
        input_schemas: inputs.into(),
        ..dummy_proof_schema()
    };
    create_dcql_query(&proof_schema, &generic_config().core, &formatter_provider()).await
}

#[tokio::test]
async fn selected_formats_have_separate_metadata_paths_and_ordered_alternatives() {
    let input = input(true).await;
    let schema = input.credential_schema.as_ref().await.unwrap();
    let formats = schema.formats.as_ref().await.unwrap();
    let claims = input.claim_schemas.as_ref().await.unwrap();
    let mdoc_id = formats[2].id;
    let sdjwt_id = formats[1].id;
    let required = claims[0].schema.id;
    let optional = claims[1].schema.id;
    let result = serde_json::to_value(query(vec![input.clone()]).await.unwrap()).unwrap();
    assert_eq!(
        result,
        json!({
            "credentials": [
                {
                    "id": mdoc_id,
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": "MDOC-schema"},
                    "claims": [
                        {
                            "id": required,
                            "path": ["org.example", "given_name"],
                            "required": true,
                            "intent_to_retain": true
                        },
                        {
                            "id": optional,
                            "path": ["org.example", "family_name"],
                            "required": false,
                            "intent_to_retain": true
                        }
                    ],
                    "claim_sets": [[required, optional], [required]],
                    "multiple": false,
                    "require_cryptographic_holder_binding": true
                },
                {
                    "id": sdjwt_id,
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": ["SD_JWT_VC-schema"]},
                    "claims": [
                        {"id": required, "path": ["given_name"], "required": true},
                        {"id": optional, "path": ["family_name"], "required": false}
                    ],
                    "claim_sets": [[required, optional], [required]],
                    "multiple": false,
                    "require_cryptographic_holder_binding": true
                }
            ],
            "credential_sets": [
                {"required": true, "options": [[mdoc_id], [sdjwt_id]]}
            ]
        })
    );
}

#[tokio::test]
async fn singleton_and_optional_inputs_get_independent_sets() {
    let mut required = input(true).await;
    required.formats = vec!["JWT".into()];
    let mut optional = input(false).await;
    optional.formats = vec!["SD_JWT_VC".into()];
    let required_schema = required.credential_schema.as_ref().await.unwrap();
    let jwt_id = required_schema.formats.as_ref().await.unwrap()[0].id;
    let required_claims = required.claim_schemas.as_ref().await.unwrap();
    let jwt_given_name = required_claims[0].schema.id;
    let jwt_family_name = required_claims[1].schema.id;
    let optional_schema = optional.credential_schema.as_ref().await.unwrap();
    let sdjwt_id = optional_schema.formats.as_ref().await.unwrap()[1].id;
    let optional_claims = optional.claim_schemas.as_ref().await.unwrap();
    let sdjwt_given_name = optional_claims[0].schema.id;
    let sdjwt_family_name = optional_claims[1].schema.id;
    let result = serde_json::to_value(
        query(vec![required.clone(), optional.clone()])
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        result,
        json!({
            "credentials": [
                {
                    "id": jwt_id,
                    "format": "jwt_vc_json",
                    "meta": {
                        "type_values": [
                            ["https://www.w3.org/2018/credentials#VerifiableCredential", "JWT-schema#Name"],
                            ["Name"]
                        ]
                    },
                    "claims": [
                        {
                            "id": jwt_given_name,
                            "path": ["vc", "credentialSubject", "given_name"],
                            "required": true
                        },
                        {
                            "id": jwt_family_name,
                            "path": ["vc", "credentialSubject", "family_name"],
                            "required": false
                        }
                    ],
                    "claim_sets": [[jwt_given_name, jwt_family_name], [jwt_given_name]],
                    "multiple": false,
                    "require_cryptographic_holder_binding": true
                },
                {
                    "id": sdjwt_id,
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": ["SD_JWT_VC-schema"]},
                    "claims": [
                        {"id": sdjwt_given_name, "path": ["given_name"], "required": false},
                        {"id": sdjwt_family_name, "path": ["family_name"], "required": false}
                    ],
                    "claim_sets": [[sdjwt_given_name, sdjwt_family_name], []],
                    "multiple": false,
                    "require_cryptographic_holder_binding": true
                }
            ],
            "credential_sets": [
                {"required": true, "options": [[jwt_id]]},
                {"required": false, "options": [[sdjwt_id]]}
            ]
        })
    );
}
