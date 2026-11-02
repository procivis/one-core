use crate::provider::presentation_formatter::mso_mdoc::model::DeviceNamespaces;
use crate::provider::transaction_data::error::TransactionDataError;

/// Format-specific representation of processed transaction data, to be merged into the
/// presentation response.
#[derive(Clone, Debug, PartialEq)]
pub enum ProcessedTransactionData {
    /// Top-level claims for the SD-JWT VC Key Binding JWT
    KbJwtClaims(serde_json::Map<String, serde_json::Value>),
    /// Data elements for the mdoc `DeviceSigned` structure
    DeviceSignedElements(DeviceNamespaces),
}

impl ProcessedTransactionData {
    pub fn merge(&mut self, other: Self) -> Result<(), TransactionDataError> {
        match (self, other) {
            (Self::KbJwtClaims(base), Self::KbJwtClaims(other)) => merge_json_object(base, other),
            (Self::DeviceSignedElements(base), Self::DeviceSignedElements(other)) => {
                merge_device_signed_elements(base, other)
            }
            _ => Err(TransactionDataError::TransactionDataConflict(
                "cannot merge transaction data of different types".to_string(),
            )),
        }
    }
}

fn merge_device_signed_elements(
    base: &mut DeviceNamespaces,
    other: DeviceNamespaces,
) -> Result<(), TransactionDataError> {
    for (namespace, other_elements) in other {
        let base_elements = base.entry(namespace).or_default();
        for (element_id, other_value) in other_elements {
            match base_elements.get_mut(&element_id) {
                Some(existing) => merge_cbor_value(existing, other_value, &element_id)?,
                None => {
                    base_elements.insert(element_id, other_value);
                }
            }
        }
    }
    Ok(())
}

fn merge_json_object(
    base: &mut serde_json::Map<String, serde_json::Value>,
    other: serde_json::Map<String, serde_json::Value>,
) -> Result<(), TransactionDataError> {
    for (key, other_value) in other {
        match base.get_mut(&key) {
            Some(existing) => merge_json_value(existing, other_value, &key)?,
            None => {
                base.insert(key, other_value);
            }
        }
    }
    Ok(())
}

fn merge_json_value(
    existing: &mut serde_json::Value,
    other: serde_json::Value,
    key: &str,
) -> Result<(), TransactionDataError> {
    match (existing, other) {
        (serde_json::Value::Array(existing), serde_json::Value::Array(other)) => {
            existing.extend(other);
            Ok(())
        }
        (serde_json::Value::Object(existing), serde_json::Value::Object(other)) => {
            merge_json_object(existing, other)
        }
        // e.g. two entries naming the same hash algorithm
        (existing, other) if *existing == other => Ok(()),
        _ => Err(conflict(key)),
    }
}

fn merge_cbor_value(
    existing: &mut ciborium::Value,
    other: ciborium::Value,
    key: &str,
) -> Result<(), TransactionDataError> {
    match (existing, other) {
        (ciborium::Value::Array(existing), ciborium::Value::Array(other)) => {
            existing.extend(other);
            Ok(())
        }
        (ciborium::Value::Map(existing), ciborium::Value::Map(other)) => {
            merge_cbor_map(existing, other)
        }
        _ => Err(conflict(key)),
    }
}

fn merge_cbor_map(
    base: &mut Vec<(ciborium::Value, ciborium::Value)>,
    other: Vec<(ciborium::Value, ciborium::Value)>,
) -> Result<(), TransactionDataError> {
    for (key, other_value) in other {
        match base
            .iter_mut()
            .find(|(existing_key, _)| *existing_key == key)
        {
            Some((_, existing_value)) => {
                merge_cbor_value(existing_value, other_value, &cbor_key_display(&key))?
            }
            None => base.push((key, other_value)),
        }
    }
    Ok(())
}

fn cbor_key_display(key: &ciborium::Value) -> String {
    match key {
        ciborium::Value::Text(text) => text.clone(),
        other => format!("{other:?}"),
    }
}

fn conflict(key: &str) -> TransactionDataError {
    TransactionDataError::TransactionDataConflict(format!("conflicting values for key `{key}`"))
}

#[cfg(test)]
mod test {
    use std::assert_matches;

    use indexmap::IndexMap;
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    fn kb_jwt(value: serde_json::Value) -> ProcessedTransactionData {
        ProcessedTransactionData::KbJwtClaims(value.as_object().unwrap().clone())
    }

    #[test]
    fn test_merge_kb_jwt_claims_disjoint_keys() {
        let mut a = kb_jwt(json!({"a": 1}));
        let b = kb_jwt(json!({"b": 2}));

        a.merge(b).unwrap();

        assert_eq!(kb_jwt(json!({"a": 1, "b": 2})), a);
    }

    #[test]
    fn test_merge_kb_jwt_claims_extends_overlapping_arrays() {
        let mut a = kb_jwt(json!({"hashes": ["h1"], "other": 1}));
        let b = kb_jwt(json!({"hashes": ["h2", "h3"], "another": 2}));

        a.merge(b).unwrap();

        assert_eq!(
            kb_jwt(json!({"hashes": ["h1", "h2", "h3"], "other": 1, "another": 2})),
            a
        );
    }

    #[test]
    fn test_merge_kb_jwt_claims_merges_nested_objects_recursively() {
        let mut a = kb_jwt(json!({"outer": {"a": 1, "shared": ["x"]}}));
        let b = kb_jwt(json!({"outer": {"b": 2, "shared": ["y"]}}));

        a.merge(b).unwrap();

        assert_eq!(
            kb_jwt(json!({"outer": {"a": 1, "b": 2, "shared": ["x", "y"]}})),
            a
        );
    }

    #[test]
    fn test_merge_kb_jwt_claims_conflicting_scalars() {
        let mut a = kb_jwt(json!({"a": 1}));
        let b = kb_jwt(json!({"a": 2}));

        let err = a.merge(b).unwrap_err();

        assert_matches!(err, TransactionDataError::TransactionDataConflict(_));
    }

    // two transaction data entries authorized by the same credential: their hashes
    // accumulate, and agreeing on the algorithm they were hashed with is not a conflict
    #[test]
    fn test_merge_kb_jwt_claims_entries_sharing_a_hash_algorithm() {
        let mut a = kb_jwt(json!({
            "transaction_data_hashes": ["hash-of-entry-1"],
            "transaction_data_hashes_alg": "sha-256"
        }));
        let b = kb_jwt(json!({
            "transaction_data_hashes": ["hash-of-entry-2"],
            "transaction_data_hashes_alg": "sha-256"
        }));

        a.merge(b).unwrap();

        assert_eq!(
            kb_jwt(json!({
                "transaction_data_hashes": ["hash-of-entry-1", "hash-of-entry-2"],
                "transaction_data_hashes_alg": "sha-256"
            })),
            a
        );
    }

    #[test]
    fn test_merge_kb_jwt_claims_conflicting_nested_scalars() {
        let mut a = kb_jwt(json!({"outer": {"a": 1}}));
        let b = kb_jwt(json!({"outer": {"a": 2}}));

        let err = a.merge(b).unwrap_err();

        assert_matches!(err, TransactionDataError::TransactionDataConflict(_));
    }

    #[test]
    fn test_merge_kb_jwt_claims_array_and_scalar_conflict() {
        let mut a = kb_jwt(json!({"a": ["x"]}));
        let b = kb_jwt(json!({"a": "y"}));

        let err = a.merge(b).unwrap_err();

        assert_matches!(err, TransactionDataError::TransactionDataConflict(_));
    }

    #[test]
    fn test_merge_device_signed_elements_disjoint() {
        let mut a = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([(
            "ns1".to_string(),
            IndexMap::from([("e1".to_string(), ciborium::Value::Integer(1.into()))]),
        )]));
        let b = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([
            (
                "ns1".to_string(),
                IndexMap::from([("e2".to_string(), ciborium::Value::Integer(2.into()))]),
            ),
            (
                "ns2".to_string(),
                IndexMap::from([("e3".to_string(), ciborium::Value::Integer(3.into()))]),
            ),
        ]));

        a.merge(b).unwrap();

        let expected = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([
            (
                "ns1".to_string(),
                IndexMap::from([
                    ("e1".to_string(), ciborium::Value::Integer(1.into())),
                    ("e2".to_string(), ciborium::Value::Integer(2.into())),
                ]),
            ),
            (
                "ns2".to_string(),
                IndexMap::from([("e3".to_string(), ciborium::Value::Integer(3.into()))]),
            ),
        ]));
        assert_eq!(expected, a);
    }

    #[test]
    fn test_merge_device_signed_elements_extends_overlapping_arrays() {
        let mut a = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([(
            "ns1".to_string(),
            IndexMap::from([(
                "e1".to_string(),
                ciborium::Value::Array(vec![ciborium::Value::Integer(1.into())]),
            )]),
        )]));
        let b = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([(
            "ns1".to_string(),
            IndexMap::from([(
                "e1".to_string(),
                ciborium::Value::Array(vec![ciborium::Value::Integer(2.into())]),
            )]),
        )]));

        a.merge(b).unwrap();

        let expected = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([(
            "ns1".to_string(),
            IndexMap::from([(
                "e1".to_string(),
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer(1.into()),
                    ciborium::Value::Integer(2.into()),
                ]),
            )]),
        )]));
        assert_eq!(expected, a);
    }

    #[test]
    fn test_merge_device_signed_elements_merges_nested_maps_recursively() {
        let mut a = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([(
            "ns1".to_string(),
            IndexMap::from([(
                "e1".to_string(),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("a".to_string()),
                    ciborium::Value::Integer(1.into()),
                )]),
            )]),
        )]));
        let b = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([(
            "ns1".to_string(),
            IndexMap::from([(
                "e1".to_string(),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("b".to_string()),
                    ciborium::Value::Integer(2.into()),
                )]),
            )]),
        )]));

        a.merge(b).unwrap();

        let expected = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([(
            "ns1".to_string(),
            IndexMap::from([(
                "e1".to_string(),
                ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("a".to_string()),
                        ciborium::Value::Integer(1.into()),
                    ),
                    (
                        ciborium::Value::Text("b".to_string()),
                        ciborium::Value::Integer(2.into()),
                    ),
                ]),
            )]),
        )]));
        assert_eq!(expected, a);
    }

    #[test]
    fn test_merge_device_signed_elements_conflicting_scalars() {
        let mut a = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([(
            "ns1".to_string(),
            IndexMap::from([("e1".to_string(), ciborium::Value::Integer(1.into()))]),
        )]));
        let b = ProcessedTransactionData::DeviceSignedElements(IndexMap::from([(
            "ns1".to_string(),
            IndexMap::from([("e1".to_string(), ciborium::Value::Integer(2.into()))]),
        )]));

        let err = a.merge(b).unwrap_err();

        assert_matches!(err, TransactionDataError::TransactionDataConflict(_));
    }

    #[test]
    fn test_merge_different_types_conflict() {
        let mut a = kb_jwt(json!({"a": 1}));
        let b = ProcessedTransactionData::DeviceSignedElements(IndexMap::new());

        let err = a.merge(b).unwrap_err();

        assert_matches!(err, TransactionDataError::TransactionDataConflict(_));
    }
}
