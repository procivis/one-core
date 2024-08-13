use std::collections::HashMap;
use uuid::Uuid;

use crate::provider::exchange_protocol::openid4vc::mapper::map_offered_claims_to_credential_schema;
use crate::service::test_utilities::{generic_config, get_dummy_date};
use one_providers::common_models::claim_schema::OpenClaimSchema;
use one_providers::common_models::credential_schema::{
    OpenCredentialSchema, OpenCredentialSchemaClaim, OpenLayoutType,
};
use one_providers::common_models::organisation::OpenOrganisation;
use one_providers::exchange_protocol::openid4vc::model::OpenID4VCICredentialValueDetails;
use one_providers::exchange_protocol::openid4vc::ExchangeProtocolError;

fn generic_schema() -> OpenCredentialSchema {
    OpenCredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "LPTestNestedSelectiveZug".to_string(),
        format: "JSON_LD_BBSPLUS".to_string(),
        revocation_method: "NONE".to_string(),
        wallet_storage_type: None,
        layout_type: OpenLayoutType::Card,
        layout_properties: None,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        schema_type: "ProcivisOneSchema2024".to_string(),
        claim_schemas: Some(vec![
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "First Name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Last Name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: false,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Street".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Number".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Apartment".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: false,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Zip".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/City".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
        ]),
        organisation: Some(OpenOrganisation {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }),
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_success_missing_optional_object() {
    let schema = generic_schema();

    let claim_keys = HashMap::from([
        (
            "Last Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Last Name Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "First Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "First Name Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result = map_offered_claims_to_credential_schema(
        &schema,
        Uuid::new_v4().into(),
        &claim_keys,
        &generic_config().core,
    )
    .unwrap();
    assert_eq!(2, result.len());

    assert_eq!(claim_keys["First Name"].value, result[0].value);
    assert_eq!(claim_keys["Last Name"].value, result[1].value);
}

#[test]
fn test_map_offered_claims_to_credential_schema_failed_partially_missing_optional_object() {
    let schema = generic_schema();

    let claim_keys = HashMap::from([
        (
            "Last Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Last Name Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "First Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "First Name Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Street Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result = map_offered_claims_to_credential_schema(
        &schema,
        Uuid::new_v4().into(),
        &claim_keys,
        &generic_config().core,
    );
    assert!(matches!(result, Err(ExchangeProtocolError::Failed(_))));
}
