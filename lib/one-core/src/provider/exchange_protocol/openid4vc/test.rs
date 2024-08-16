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
        }),
    }
}

fn generic_schema_array_object() -> OpenCredentialSchema {
    OpenCredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "LPTestNestedSelectiveZug".to_string(),
        format: "JSON_LD_CLASSIC".to_string(),
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
                    key: "array_string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                },
                required: true,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "optional_array_string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                },
                required: false,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                },
                required: true,
            },
            OpenCredentialSchemaClaim {
                schema: OpenClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object/Field 1".to_string(),
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
                    key: "array_object/Field 2".to_string(),
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
                    key: "array_object/Field array".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                },
                required: false,
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
                required: true,
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
        ]),
        organisation: Some(OpenOrganisation {
            id: Uuid::new_v4().into(),
        }),
    }
}

fn generic_schema_object_hell() -> OpenCredentialSchema {
    OpenCredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "LPTestNestedSelectiveZug".to_string(),
        format: "JSON_LD_CLASSIC".to_string(),
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
                    key: "opt_obj".to_string(),
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
                    key: "opt_obj/obj_str".to_string(),
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
                    key: "opt_obj/opt_obj".to_string(),
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
                    key: "opt_obj/opt_obj/field_man".to_string(),
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
                    key: "opt_obj/opt_obj/field_opt".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: false,
            },
        ]),
        organisation: Some(OpenOrganisation {
            id: Uuid::new_v4().into(),
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

#[test]
fn test_map_offered_claims_to_credential_schema_success_object_array() {
    let schema = generic_schema_array_object();

    let claim_keys = HashMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "111".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_string/1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "222".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_string/2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "333".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "optional_array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "opt111".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "01".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field array/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "0array0".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field array/1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "0array1".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/1/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "11".to_string(),
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
        // Field 2 and array is missing for array object 2
    ]);

    let result = map_offered_claims_to_credential_schema(
        &schema,
        Uuid::new_v4().into(),
        &claim_keys,
        &generic_config().core,
    )
    .unwrap();
    assert_eq!(10, result.len());

    for claim in result {
        assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_success_optional_array_missing() {
    let schema = generic_schema_array_object();

    let claim_keys = HashMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "1".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "01".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
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
    )
    .unwrap();
    assert_eq!(4, result.len());

    for claim in result {
        assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_mandatory_array_missing_error() {
    let schema = generic_schema_array_object();

    let claim_keys = HashMap::from([
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "01".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
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

    assert!(map_offered_claims_to_credential_schema(
        &schema,
        Uuid::new_v4().into(),
        &claim_keys,
        &generic_config().core,
    )
    .is_err())
}

#[test]
fn test_map_offered_claims_to_credential_schema_mandatory_array_object_field_missing_error() {
    let schema = generic_schema_array_object();

    let claim_keys = HashMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "1".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
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

    assert!(map_offered_claims_to_credential_schema(
        &schema,
        Uuid::new_v4().into(),
        &claim_keys,
        &generic_config().core,
    )
    .is_err())
}

#[test]
fn test_map_offered_claims_to_credential_schema_mandatory_object_error() {
    let schema = generic_schema_array_object();

    let claim_keys = HashMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "1".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(map_offered_claims_to_credential_schema(
        &schema,
        Uuid::new_v4().into(),
        &claim_keys,
        &generic_config().core,
    )
    .is_err())
}

#[test]
fn test_map_offered_claims_to_credential_schema_opt_object_opt_obj_present() {
    let schema = generic_schema_object_hell();

    let claim_keys = HashMap::from([
        (
            "opt_obj/obj_str".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "os".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "opt_obj/opt_obj/field_man".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "oofm".to_string(),
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

    for claim in result {
        assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_opt_object_opt_obj_missing() {
    let schema = generic_schema_object_hell();

    let claim_keys = HashMap::from([(
        "opt_obj/obj_str".to_string(),
        OpenID4VCICredentialValueDetails {
            value: "os".to_string(),
            value_type: "STRING".to_string(),
        },
    )]);

    let result = map_offered_claims_to_credential_schema(
        &schema,
        Uuid::new_v4().into(),
        &claim_keys,
        &generic_config().core,
    )
    .unwrap();
    assert_eq!(1, result.len());

    for claim in result {
        assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_opt_object_opt_obj_present_man_field_missing_error()
{
    let schema = generic_schema_object_hell();

    let claim_keys = HashMap::from([
        (
            "opt_obj/obj_str".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "os".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "opt_obj/opt_obj/field_opt".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "oofm".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(map_offered_claims_to_credential_schema(
        &schema,
        Uuid::new_v4().into(),
        &claim_keys,
        &generic_config().core,
    )
    .is_err())
}

#[test]
fn test_map_offered_claims_to_credential_schema_opt_object_opt_obj_present_man_root_field_missing_error(
) {
    let schema = generic_schema_object_hell();

    let claim_keys = HashMap::from([(
        "opt_obj/opt_obj/field_man".to_string(),
        OpenID4VCICredentialValueDetails {
            value: "oofm".to_string(),
            value_type: "STRING".to_string(),
        },
    )]);

    assert!(map_offered_claims_to_credential_schema(
        &schema,
        Uuid::new_v4().into(),
        &claim_keys,
        &generic_config().core,
    )
    .is_err())
}
