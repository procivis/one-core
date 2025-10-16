use std::collections::HashMap;

use time::OffsetDateTime;
use uuid::Uuid;

use super::error::FormatterError;
use super::model::{CredentialClaim, CredentialClaimValue};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::provider::data_type::provider::DataTypeProvider;

/// Parse model claims/claimSchemas from a JSON-based credential
pub fn parse_claims(
    public_claims: HashMap<String, CredentialClaim>,
    datatype_provider: &dyn DataTypeProvider,
    credential_id: shared_types::CredentialId,
) -> Result<(Vec<Claim>, Vec<CredentialSchemaClaim>), FormatterError> {
    let mut result = vec![];
    for (key, claim_value) in public_claims {
        let claims = parse_claim(&key, &key, claim_value, datatype_provider, credential_id)?;
        result.extend(claims);
    }

    let mut schemas: HashMap<String, ClaimSchema> = HashMap::new();
    for claim in result.iter_mut() {
        let Some(schema) = claim.schema.as_ref() else {
            continue;
        };

        match schemas.get(&schema.key) {
            Some(matching_schema) => {
                let parsed_datatype = &schema.data_type;
                if &matching_schema.data_type != parsed_datatype {
                    tracing::warn!(
                        "Mismatch of detected datatype ({parsed_datatype:?}) of array claim: '{}'",
                        claim.path
                    );
                }

                // reuse the already inserted schema here (to match ids) of array siblings
                claim.schema = Some(matching_schema.to_owned());
            }
            None => {
                schemas.insert(schema.key.to_owned(), schema.to_owned());
            }
        };
    }

    let schemas = schemas
        .values()
        .map(|schema| CredentialSchemaClaim {
            schema: schema.to_owned(),
            required: false,
        })
        .collect();

    Ok((result, schemas))
}

/// Recursively parse a claim and its nested values, creating Claim objects with ClaimSchema
fn parse_claim(
    claim_path: &str,
    claim_schema_path: &str,
    claim_value: CredentialClaim,
    datatype_provider: &dyn DataTypeProvider,
    credential_id: shared_types::CredentialId,
) -> Result<Vec<Claim>, FormatterError> {
    let now = OffsetDateTime::now_utc();

    Ok(match claim_value.value {
        CredentialClaimValue::Array(values) => {
            // Check if array has all elements with the same type
            let Some(first) = values.first() else {
                return Ok(vec![]);
            };
            if !values
                .iter()
                .all(|item| is_same_type(&item.value, &first.value))
            {
                return Err(FormatterError::CouldNotExtractCredentials(format!(
                    "Non-homogenous array at: {claim_path}"
                )));
            }

            let mut subclaims: Vec<Claim> = vec![];
            for (index, value) in values.into_iter().enumerate() {
                let item_path = format!("{claim_path}/{index}");
                let claims = parse_claim(
                    &item_path,
                    claim_schema_path,
                    value,
                    datatype_provider,
                    credential_id,
                )?;
                subclaims.extend(claims);
            }

            // data type of the array elements based on first item data_type
            let Some(first) = subclaims
                .iter()
                .find(|claim| claim.path == format!("{claim_path}/0"))
                .and_then(|claim| claim.schema.as_ref())
            else {
                return Ok(vec![]);
            };

            let mut result = vec![Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: now,
                last_modified: now,
                value: None,
                path: claim_path.to_string(),
                selectively_disclosable: claim_value.selectively_disclosable,
                schema: Some(ClaimSchema {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    key: claim_schema_path.to_string(),
                    data_type: first.data_type.to_owned(),
                    array: true,
                    metadata: claim_value.metadata,
                }),
            }];
            result.extend(subclaims);
            result
        }
        CredentialClaimValue::Object(map) => {
            let mut result = vec![];
            for (key, value) in map {
                let item_path = format!("{claim_path}/{key}");
                let item_schema_path = format!("{claim_schema_path}/{key}");
                let claims = parse_claim(
                    &item_path,
                    &item_schema_path,
                    value,
                    datatype_provider,
                    credential_id,
                )?;
                result.extend(claims);
            }

            result.push(Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: now,
                last_modified: now,
                value: None,
                path: claim_path.to_string(),
                selectively_disclosable: claim_value.selectively_disclosable,
                schema: Some(ClaimSchema {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    key: claim_schema_path.to_string(),
                    data_type: "OBJECT".to_owned(),
                    array: false,
                    metadata: claim_value.metadata,
                }),
            });

            result
        }
        simple_value => {
            // Convert CredentialClaimValue to JSON value for extraction
            let json_value = serde_json::Value::from(simple_value);
            let extracted = datatype_provider
                .extract_json_claim(&json_value)
                .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

            vec![Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: now,
                last_modified: now,
                value: Some(extracted.value),
                path: claim_path.to_string(),
                selectively_disclosable: claim_value.selectively_disclosable,
                schema: Some(ClaimSchema {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    key: claim_schema_path.to_string(),
                    data_type: extracted.data_type,
                    array: false,
                    metadata: claim_value.metadata,
                }),
            }]
        }
    })
}

/// Check if two CredentialClaimValue have the same type
fn is_same_type(a: &CredentialClaimValue, b: &CredentialClaimValue) -> bool {
    matches!(
        (a, b),
        (CredentialClaimValue::Bool(_), CredentialClaimValue::Bool(_))
            | (
                CredentialClaimValue::Number(_),
                CredentialClaimValue::Number(_)
            )
            | (
                CredentialClaimValue::String(_),
                CredentialClaimValue::String(_)
            )
            | (
                CredentialClaimValue::Array(_),
                CredentialClaimValue::Array(_)
            )
            | (
                CredentialClaimValue::Object(_),
                CredentialClaimValue::Object(_)
            )
    )
}
