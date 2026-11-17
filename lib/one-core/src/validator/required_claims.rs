use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim_schema::ClaimSchema;

#[derive(Debug, thiserror::Error)]
#[error("Missing parent claim schema `{0}`")]
pub(crate) struct MissingParentClaimSchema(String);

impl ErrorCodeMixin for MissingParentClaimSchema {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0109
    }
}

pub(crate) fn missing_required_claim_paths<'a>(
    claim_schemas: &[ClaimSchema],
    is_required: impl Fn(&ClaimSchema) -> bool,
    claim_paths: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, MissingParentClaimSchema> {
    let mut present = HashSet::new();
    for path in claim_paths {
        present.insert(path);
        present.extend(
            path.match_indices(NESTED_CLAIM_MARKER)
                .map(|(index, _)| &path[..index]),
        );
    }
    let schemas_by_key = claim_schemas
        .iter()
        .map(|claim_schema| (claim_schema.key.as_str(), claim_schema))
        .collect::<HashMap<_, _>>();

    let mut expected_by_key = HashMap::new();
    let mut missing = vec![];
    for claim_schema in claim_schemas.iter().filter(|schema| is_required(schema)) {
        let expected = expected_paths(
            &claim_schema.key,
            &schemas_by_key,
            &present,
            &mut expected_by_key,
        )?;
        for path in expected.iter() {
            if !present.contains(path.as_str()) {
                missing.push(path.clone());
            }
        }
    }
    missing.sort();
    Ok(missing)
}

fn expected_paths<'a>(
    key: &'a str,
    schemas_by_key: &HashMap<&str, &ClaimSchema>,
    present: &HashSet<&str>,
    expected_by_key: &mut HashMap<&'a str, Rc<Vec<String>>>,
) -> Result<Rc<Vec<String>>, MissingParentClaimSchema> {
    if let Some(paths) = expected_by_key.get(key) {
        return Ok(paths.clone());
    }

    let mut paths = vec![];
    if let Some((parent_key, leaf)) = key.rsplit_once(NESTED_CLAIM_MARKER) {
        let parent = schemas_by_key
            .get(parent_key)
            .ok_or_else(|| MissingParentClaimSchema(parent_key.to_string()))?;
        let parent_paths = expected_paths(parent_key, schemas_by_key, present, expected_by_key)?;
        for parent_path in parent_paths.iter() {
            if parent.array {
                let element_prefix = format!("{parent_path}{NESTED_CLAIM_MARKER}");
                paths.extend(
                    present
                        .iter()
                        .filter(|path| {
                            path.strip_prefix(&element_prefix)
                                .is_some_and(|index| index.parse::<usize>().is_ok())
                        })
                        .map(|element_path| format!("{element_path}{NESTED_CLAIM_MARKER}{leaf}")),
                );
            } else if present.contains(parent_path.as_str()) {
                paths.push(format!("{parent_path}{NESTED_CLAIM_MARKER}{leaf}"));
            }
        }
    } else {
        paths.push(key.to_string());
    }

    let paths = Rc::new(paths);
    expected_by_key.insert(key, paths.clone());
    Ok(paths)
}
