use std::collections::hash_map::Entry;
use std::collections::HashMap;

use url::Url;

use super::dto::JsonLDContextDTO;
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::service::error::ServiceError;
use crate::service::ssi_issuer::dto::{
    JsonLDEntityDTO, JsonLDNestedContextDTO, JsonLDNestedEntityDTO,
};

impl Default for JsonLDContextDTO {
    fn default() -> Self {
        Self {
            version: 1.1,
            protected: true,
            id: "@id".to_string(),
            r#type: "@type".to_string(),
            entities: HashMap::default(),
        }
    }
}

pub fn generate_jsonld_context_response(
    claim_schemas: &Vec<CredentialSchemaClaim>,
    base_url: &str,
) -> Result<HashMap<String, JsonLDEntityDTO>, ServiceError> {
    let mut entities: HashMap<String, JsonLDEntityDTO> = HashMap::new();
    for claim_schema in claim_schemas {
        if claim_schema.schema.data_type != "OBJECT" {
            let key_parts: Vec<&str> = claim_schema.schema.key.split(NESTED_CLAIM_MARKER).collect();
            insert_claim(&mut entities, &key_parts, base_url, 0)?;
        }
    }
    Ok(entities)
}

fn insert_claim(
    current_claim: &mut HashMap<String, JsonLDEntityDTO>,
    key_parts: &Vec<&str>,
    base_url: &str,
    index: usize,
) -> Result<(), ServiceError> {
    if index >= key_parts.len() {
        return Ok(());
    }

    let part = key_parts[index].to_string();

    let nested_claim = match current_claim.entry(part.clone()) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            entry.insert(JsonLDEntityDTO::NestedObject(JsonLDNestedEntityDTO {
                id: get_url_with_fragment(base_url, &part)?,
                context: JsonLDNestedContextDTO {
                    entities: HashMap::new(),
                },
            }))
        }
    };

    if let JsonLDEntityDTO::NestedObject(nested) = nested_claim {
        insert_claim(&mut nested.context.entities, key_parts, base_url, index + 1)?;
    }

    if index == key_parts.len() - 1 {
        let reference_claim = JsonLDEntityDTO::Reference(get_url_with_fragment(base_url, &part)?);
        current_claim.insert(part, reference_claim);
    }

    Ok(())
}

pub fn get_url_with_fragment(base_url: &str, fragment: &str) -> Result<String, ServiceError> {
    let mut url = Url::parse(base_url).map_err(|e| ServiceError::MappingError(e.to_string()))?;
    // We need to url encode the fragment in case `#` is used in a claim name
    url.set_fragment(Some(&urlencoding::encode(fragment)));
    Ok(url.to_string())
}
