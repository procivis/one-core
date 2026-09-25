use std::collections::HashMap;

use futures::future::BoxFuture;
use uuid::Uuid;

use super::error::FormatterError;
use super::model::{CredentialClaim, CredentialClaimValue};
use crate::error::ContextWithErrorCode;
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::relation::{Related, RelatedVec};
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

/// Parse model claims/claimSchemas from a JSON-based credential
pub async fn parse_claims(
    public_claims: HashMap<String, CredentialClaim>,
    datatype_provider: &dyn DataTypeProvider,
) -> Result<(Vec<Claim>, Vec<ClaimSchema>), FormatterError> {
    let mut result = vec![];
    for (key, claim_value) in public_claims {
        let claims = parse_claim(&key, &key, claim_value, datatype_provider).await?;
        result.extend(claims);
    }

    let mut schemas: HashMap<String, ClaimSchema> = HashMap::new();
    for claim in result.iter_mut() {
        let schema: ClaimSchema = claim.schema.as_ref().await?.to_owned();

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
                claim.schema = matching_schema.to_owned().into();
            }
            None => {
                schemas.insert(schema.key.to_owned(), schema);
            }
        };
    }

    let schemas = schemas.into_values().collect();

    Ok((result, schemas))
}

/// Recursively parse a claim and its nested values, creating Claim objects with ClaimSchema
// Boxed because the future is recursive.
fn parse_claim<'a>(
    claim_path: &'a str,
    claim_schema_path: &'a str,
    claim_value: CredentialClaim,
    datatype_provider: &'a dyn DataTypeProvider,
) -> BoxFuture<'a, Result<Vec<Claim>, FormatterError>> {
    Box::pin(parse_claim_inner(
        claim_path,
        claim_schema_path,
        claim_value,
        datatype_provider,
    ))
}

async fn parse_claim_inner(
    claim_path: &str,
    claim_schema_path: &str,
    claim_value: CredentialClaim,
    datatype_provider: &dyn DataTypeProvider,
) -> Result<Vec<Claim>, FormatterError> {
    let now = crate::clock::now_utc();

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
                let claims =
                    parse_claim(&item_path, claim_schema_path, value, datatype_provider).await?;
                subclaims.extend(claims);
            }

            // data type of the array elements based on first item data_type
            let Some(first) = subclaims
                .iter()
                .find(|claim| claim.path == format!("{claim_path}/0"))
            else {
                return Ok(vec![]);
            };
            let first_data_type = first.schema.as_ref().await?.data_type.to_owned();

            let mut result = vec![Claim {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                value: None,
                path: claim_path.to_string(),
                selectively_disclosable: claim_value.selectively_disclosable,
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    key: claim_schema_path.to_string(),
                    data_type: first_data_type,
                    array: true,
                    metadata: claim_value.metadata,
                    required: false,
                    translations: Default::default(),
                }
                .into(),
            }];
            result.extend(subclaims);
            result
        }
        CredentialClaimValue::Object(map) => {
            let mut result = vec![];
            for (key, value) in map {
                let item_path = format!("{claim_path}/{key}");
                let item_schema_path = format!("{claim_schema_path}/{key}");
                let claims =
                    parse_claim(&item_path, &item_schema_path, value, datatype_provider).await?;
                result.extend(claims);
            }

            result.push(Claim {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                value: None,
                path: claim_path.to_string(),
                selectively_disclosable: claim_value.selectively_disclosable,
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    key: claim_schema_path.to_string(),
                    data_type: "OBJECT".to_owned(),
                    array: false,
                    metadata: claim_value.metadata,
                    required: false,
                    translations: Default::default(),
                }
                .into(),
            });

            result
        }
        simple_value => {
            // Convert CredentialClaimValue to JSON value for extraction
            let json_value = serde_json::Value::from(simple_value);
            let extracted = datatype_provider
                .extract_json_claim(&json_value)
                .error_while("extracting JSON claim")?;

            vec![Claim {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                value: Some(extracted.value),
                path: claim_path.to_string(),
                selectively_disclosable: claim_value.selectively_disclosable,
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    key: claim_schema_path.to_string(),
                    data_type: extracted.data_type,
                    array: false,
                    metadata: claim_value.metadata,
                    required: false,
                    translations: Default::default(),
                }
                .into(),
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

/// Prepare extracted identifier
pub fn prepare_identifier(
    detail: &IdentifierDetails,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    did_method_provider: &dyn DidMethodProvider,
    organisation: Organisation,
) -> Result<Identifier, FormatterError> {
    let now = crate::clock::now_utc();
    let identifier_id = Uuid::new_v4().into();
    let name = format!("identifier {identifier_id}");

    let identifier_data = match detail {
        IdentifierDetails::Certificate(certificate) => {
            let cert = Certificate {
                id: Uuid::new_v4().into(),
                identifier_id,
                organisation: organisation.to_owned().into(),
                created_date: now,
                last_modified: now,
                deleted_at: None,
                expiry_date: certificate.expiry,
                name: certificate
                    .subject_common_name
                    .clone()
                    .unwrap_or(name.clone()),
                chain: certificate.chain.clone(),
                fingerprint: certificate.fingerprint.clone(),
                state: CertificateState::Active,
                roles: vec![],
                key: None,
            };
            IdentifierData::Certificate(RelatedVec::from(vec![cert]))
        }
        IdentifierDetails::Did(did) => {
            let (did_method, _) = did_method_provider
                .get_did_method_by_method_name(did.method())
                .error_while("getting did method")?;

            let did_model = crate::model::did::Did {
                deleted_at: None,
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: format!("did {identifier_id}"),
                did: did.to_owned(),
                did_type: crate::model::did::DidType::Remote,
                did_method,
                deactivated: false,
                log: None,
                keys: Default::default(),
                organisation: organisation.to_owned().into(),
            };
            IdentifierData::Did(Related::from(did_model))
        }
        IdentifierDetails::Key(key) => {
            let parsed_key = key_algorithm_provider
                .parse_jwk(key)
                .error_while("parsing JWK")?;
            let key_model = Key {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                public_key: parsed_key.key.public_key_as_raw(),
                name: format!("key {identifier_id}"),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: parsed_key.algorithm_type.to_string(),
                autogenerated: true,
                organisation: organisation.to_owned().into(),
            };
            IdentifierData::Key(Related::from(key_model))
        }
    };

    Ok(Identifier {
        id: identifier_id,
        created_date: now,
        last_modified: now,
        name,
        data: identifier_data,
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: true,
        logo: None,
        organisation: organisation.into(),
        trust_information: Default::default(),
        translations: Default::default(),
    })
}
