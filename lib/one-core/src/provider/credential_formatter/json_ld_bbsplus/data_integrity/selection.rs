use std::collections::{BTreeMap, HashSet};

use json_ld::{BlankIdBuf, JsonLdProcessor, Loader, RemoteDocument, rdf_types};
use sophia_api::quad::Spog;

use super::skolemize::to_deskolemized_nquads;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::canonization::TermAdapter;

pub struct SelectionResult {
    pub _selected_document: json_syntax::Value,
    pub selected_deskolemized_nquads: HashSet<Spog<TermAdapter>>,
    pub selected_nquads: HashSet<Spog<TermAdapter>>,
}

pub async fn select_canonical_nquads(
    document: &serde_json::Value,
    pointers: &[String],
    label_map: &BTreeMap<String, String>,
    loader: &impl Loader,
    options: json_ld::Options,
) -> Result<SelectionResult, FormatterError> {
    let selected_document = select_json_ld(document, pointers)
        .map(json_syntax::Value::from_serde_json)
        .map(|selected| RemoteDocument::new(None, None, selected))
        .map_err(|e| FormatterError::Failed(format!("Failed to select document: {e}")))?;

    let expanded = selected_document
        .expand_with_using(&mut (), &loader, options)
        .await
        .map_err(|e| {
            FormatterError::Failed(format!(
                "Failed to expand document during selection step: {e}"
            ))
        })?;

    let deskolemized_nquads: HashSet<Spog<TermAdapter>> = to_deskolemized_nquads(&expanded);

    let selected_nquads: HashSet<Spog<TermAdapter>> = deskolemized_nquads
        .clone()
        .into_iter()
        .map(|(triple, graph)| {
            let triple = triple.map(|term| relabel_blank_node(term, label_map));
            let graph = graph.map(|term| relabel_blank_node(term, label_map));
            (triple, graph)
        })
        .collect();

    Ok(SelectionResult {
        _selected_document: selected_document.into_document(),
        selected_deskolemized_nquads: deskolemized_nquads,
        selected_nquads,
    })
}
// relabel blank nodes using the label map
fn relabel_blank_node(term: TermAdapter, label_map: &BTreeMap<String, String>) -> TermAdapter {
    match term.0 {
        rdf_types::Term::Id(rdf_types::Id::Blank(bid)) => {
            let suffix = &bid[2..];
            let new_label = &label_map[suffix];
            let iri = format!("_:{new_label}");
            let bid = BlankIdBuf::new(iri).expect("should always be a valid BlankIdBuf");
            let term = rdf_types::Term::Id(rdf_types::Id::Blank(bid));
            TermAdapter(term)
        }
        _ => term,
    }
}

pub fn select_json_ld(
    document: &serde_json::Value,
    pointers: &[String],
) -> Result<serde_json::Value, FormatterError> {
    if !document.is_object() {
        return Err(FormatterError::Failed(
            "Document is not an object".to_string(),
        ));
    }

    if pointers.is_empty() {
        return Err(FormatterError::Failed("No pointers provided".to_string()));
    }

    let mut selection_document = initialize_selection(document);
    if let Some(context) = document.get("@context") {
        selection_document["@context"] = context.clone();
    }

    for pointer in pointers {
        let paths = parse_pointer(pointer);

        if paths.is_empty() {
            return Ok(document.clone());
        }

        selection_document =
            select_paths(document, &paths, selection_document).ok_or_else(|| {
                FormatterError::Failed(format!("Failed to select for pointer: {pointer}"))
            })?;
    }

    remove_array_null_paddings(&mut selection_document);

    Ok(selection_document)
}

fn initialize_selection(source: &serde_json::Value) -> serde_json::Value {
    let mut value = serde_json::json!({});

    if let Some(id) = source.get("id") {
        if id.as_str().is_some_and(|id_str| !id_str.starts_with("_:")) {
            value["id"] = id.clone();
        }
    }

    if let Some(type_val) = source.get("type") {
        value["type"] = type_val.clone();
    }

    value
}

fn parse_pointer(pointer: &str) -> Vec<PathComponent> {
    pointer
        .split('/')
        .skip(1)
        .map(|path| {
            path.parse::<usize>()
                .map(PathComponent::Index)
                .unwrap_or(PathComponent::Key(path))
        })
        .collect()
}

fn select_paths(
    source_document: &serde_json::Value,
    paths: &[PathComponent],
    mut selection_document: serde_json::Value,
) -> Option<serde_json::Value> {
    let mut source = source_document;
    let mut selected = &mut selection_document;

    for path in paths {
        // if path doesn't exists in source document we stop
        let value = path.lookup_into(source)?;
        // if path doesn't exists in selection document we need to create it
        let selected_value = path.lookup_into(selected);
        // if the selected value is not present we set it or if null must be array value that we need to initialize
        if selected_value.is_none() || selected_value.is_some_and(|v| v.is_null()) {
            if let Some(array) = value.as_array() {
                let size = array.len();
                path.set_into(
                    selected,
                    // we pad the array with null values so we can insert the selected value at the correct index
                    serde_json::json!(vec![serde_json::Value::Null; size]),
                );
            } else {
                let v = initialize_selection(value);
                path.set_into(selected, v);
            }
        }

        source = value;
        selected = path.lookup_into_mut(selected)?;
    }

    // if document is an object we need to merge it
    if let Some(object) = source.as_object() {
        for (key, value) in object {
            selected[key] = value.clone();
        }
    } else {
        *selected = source.clone();
    }

    Some(selection_document)
}

fn remove_array_null_paddings(document: &mut serde_json::Value) {
    match document {
        serde_json::Value::Object(obj) => obj
            .iter_mut()
            .for_each(|(_, value)| remove_array_null_paddings(value)),
        serde_json::Value::Array(arr) => {
            arr.retain(|value| !value.is_null());
        }
        _ => (),
    }
}

enum PathComponent<'a> {
    Index(usize),
    Key(&'a str),
}

impl PathComponent<'_> {
    fn lookup_into<'a>(&self, document: &'a serde_json::Value) -> Option<&'a serde_json::Value> {
        match self {
            PathComponent::Index(index) => document.get(index),
            PathComponent::Key(key) => document.get(key),
        }
    }

    fn lookup_into_mut<'a>(
        &self,
        document: &'a mut serde_json::Value,
    ) -> Option<&'a mut serde_json::Value> {
        match self {
            PathComponent::Index(index) => document.get_mut(index),
            PathComponent::Key(key) => document.get_mut(key),
        }
    }

    fn set_into(&self, document: &mut serde_json::Value, value: serde_json::Value) {
        match self {
            PathComponent::Index(index) => document[index] = value,
            PathComponent::Key(key) => document[key] = value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_json_ld() {
        let document = serde_json::json!({
          "@context": [
            "https://www.w3.org/ns/credentials/v2"
          ],
          "type": [
            "VerifiableCredential"
          ],
          "id": "credentialId_0",
          "issuer": "https://vc.example/windsurf/racecommittee",
          "credentialSubject": {
            "id": "subjectId_0",
            "sailNumber": "Earth101",
            "sails": [
              {
                "id": "sailId_0",
                "size": 5.5,
                "sailName": "Kihei",
                "year": 2023
              },
              {
                "id": "sailId_1",
                "size": 6.1,
                "sailName": "Lahaina",
                "year": 2023
              },
              {
                "id": "sailId_2",
                "size": 7.0,
                "sailName": "Lahaina",
                "year": 2020
              },
              {
                "id": "sailId_3",
                "size": 7.8,
                "sailName": "Lahaina",
                "year": 2023
              }
            ],
            "boards": [
              {
                "id": "boardId_0",
                "boardName": "CompFoil170",
                "brand": "Wailea",
                "year": 2022
              },
              {
                "id": "boardId_1",
                "boardName": "Kanaha Custom",
                "brand": "Wailea",
                "year": 2019
              }
            ]
          }
        });

        let pointers = [
            "/issuer",
            "/credentialSubject/sailNumber",
            "/credentialSubject/sails/1",
            "/credentialSubject/boards/0/year",
            "/credentialSubject/sails/2",
        ]
        .map(ToString::to_string);

        let expected = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2"
              ],
            "type": [
                "VerifiableCredential"
            ],
            "id": "credentialId_0",
            "issuer": "https://vc.example/windsurf/racecommittee",
            "credentialSubject": {
                "id": "subjectId_0",
                "sailNumber": "Earth101",
                "sails": [
                    {
                        "id": "sailId_1",
                        "size": 6.1,
                        "sailName": "Lahaina",
                        "year": 2023
                    },
                    {
                        "id": "sailId_2",
                        "size": 7.0,
                        "sailName": "Lahaina",
                        "year": 2020
                    }
                ],
                "boards": [
                    {
                        "id": "boardId_0",
                        "year": 2022
                    }
                ]
            }
        });

        let result = select_json_ld(&document, &pointers).unwrap();
        assert_eq!(result, expected);
    }
}
