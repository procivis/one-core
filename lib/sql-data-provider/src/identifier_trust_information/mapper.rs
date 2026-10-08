use anyhow::anyhow;
use one_core::model::identifier_trust_information::{IdentifierTrustInformation, SchemaFormat};
use one_core::repository::error::DataLayerError;
use sea_orm::Set;

use crate::entity::identifier_trust_information;
use crate::entity::identifier_trust_information::ActiveModel;

// Escaping similar to URL encoding, but use ~ as the escape character.
// The reason is that % is the wildcard character in SQL.
// Also escape _ because it matches any single character in SQL.
const ESCAPED_TILDE: &str = "~01";
const ESCAPED_COMMA: &str = "~2C";
const ESCAPED_PIPE: &str = "~7C";
const ESCAPED_PERCENT: &str = "~25";
const ESCAPED_UNDERSCORE: &str = "~02";

fn escape_schema_id(schema_id: &str) -> String {
    schema_id
        .replace("~", ESCAPED_TILDE)
        .replace(",", ESCAPED_COMMA)
        .replace("|", ESCAPED_PIPE)
        .replace("%", ESCAPED_PERCENT)
        .replace("_", ESCAPED_UNDERSCORE)
}

fn unescape_schema_id(schema_id: &str) -> String {
    schema_id
        .replace(ESCAPED_UNDERSCORE, "_")
        .replace(ESCAPED_PERCENT, "%")
        .replace(ESCAPED_PIPE, "|")
        .replace(ESCAPED_COMMA, ",")
        .replace(ESCAPED_TILDE, "~")
}

pub(crate) fn serialize_schema_format(schema_format: &SchemaFormat) -> String {
    format!(
        "{}|{}",
        escape_schema_id(&schema_format.schema_id),
        schema_format.format
    )
}

pub fn deserialize_schema_format(serialized: &str) -> Result<SchemaFormat, DataLayerError> {
    let splits = serialized.split("|").collect::<Vec<_>>();
    if splits.len() != 2 {
        return Err(DataLayerError::MappingError(anyhow!(
            "Schema format must contain exactly two pipe-separated components"
        )));
    }
    let schema_id = unescape_schema_id(splits.first().ok_or_else(|| {
        DataLayerError::MappingError(anyhow!("Schema format is missing schema ID"))
    })?);
    let format = splits
        .get(1)
        .ok_or_else(|| DataLayerError::MappingError(anyhow!("Schema format is missing format")))?
        .to_string();
    Ok(SchemaFormat { schema_id, format })
}

fn serialize_schema_formats(schema_formats: &[SchemaFormat]) -> Option<String> {
    if schema_formats.is_empty() {
        return None;
    }
    Some(
        schema_formats
            .iter()
            .map(serialize_schema_format)
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn deserialize_schema_formats(
    serialized: Option<String>,
) -> Result<Vec<SchemaFormat>, DataLayerError> {
    let Some(serialized) = serialized else {
        return Ok(vec![]);
    };
    serialized
        .split(",")
        .map(deserialize_schema_format)
        .collect()
}

impl From<IdentifierTrustInformation> for ActiveModel {
    fn from(trust_information: IdentifierTrustInformation) -> Self {
        Self {
            id: Set(trust_information.id),
            created_date: Set(trust_information.created_date),
            last_modified: Set(trust_information.last_modified),
            valid_from: Set(trust_information.valid_from),
            valid_to: Set(trust_information.valid_to),
            intended_use: Set(trust_information.intended_use),
            allowed_issuance_types: Set(serialize_schema_formats(
                &trust_information.allowed_issuance_types,
            )),
            allowed_verification_types: Set(serialize_schema_formats(
                &trust_information.allowed_verification_types,
            )),
            identifier_id: Set(trust_information.identifier_id),
            blob_id: Set(trust_information.blob_id),
        }
    }
}

impl TryFrom<identifier_trust_information::Model> for IdentifierTrustInformation {
    type Error = DataLayerError;

    fn try_from(value: identifier_trust_information::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            valid_from: value.valid_from,
            valid_to: value.valid_to,
            intended_use: value.intended_use,
            allowed_issuance_types: deserialize_schema_formats(value.allowed_issuance_types)?,
            allowed_verification_types: deserialize_schema_formats(
                value.allowed_verification_types,
            )?,
            identifier_id: value.identifier_id,
            blob_id: value.blob_id,
        })
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use crate::identifier_trust_information::mapper::{escape_schema_id, unescape_schema_id};

    #[test]
    fn escape_schema_id_test() {
        let test_cases = ["simple", "test,~25|%~~2C7C~7Cesca_ping"];

        for test_case in test_cases {
            let escaped = escape_schema_id(test_case);
            assert!(!escaped.contains(","));
            assert!(!escaped.contains("|"));
            assert_eq!(unescape_schema_id(&escaped), test_case);
        }
    }
}
