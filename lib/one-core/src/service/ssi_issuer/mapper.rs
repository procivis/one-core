use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::CoreConfig;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::model::did::Did;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::service::credential::mapper::from_vec_claim;
use crate::service::error::ServiceError;
use crate::service::ssi_issuer::dto::{
    JsonLDEntityDTO, JsonLDNestedContextDTO, JsonLDNestedEntityDTO,
};
use shared_types::EntityId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::dto::{ConnectIssuerResponseDTO, JsonLDContextDTO};

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

pub(super) fn credential_rejected_history_event(credential: &Credential) -> History {
    history_event(
        credential.id.into(),
        credential.issuer_did.as_ref(),
        HistoryEntityType::Credential,
        HistoryAction::Rejected,
    )
}

fn history_event(
    entity_id: EntityId,
    issuer_did: Option<&Did>,
    entity_type: HistoryEntityType,
    action: HistoryAction,
) -> History {
    let organisation = issuer_did.and_then(|did| did.organisation.clone());

    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: entity_id.into(),
        entity_type,
        metadata: None,
        organisation,
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
    url.set_fragment(Some(fragment));
    Ok(url.to_string())
}

pub(super) fn connect_issuer_response_from_credential(
    value: Credential,
    config: &CoreConfig,
) -> Result<ConnectIssuerResponseDTO, ServiceError> {
    let schema = value.schema.ok_or(ServiceError::MappingError(
        "credential_schema is None".to_string(),
    ))?;
    let issuer_did = value
        .issuer_did
        .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;
    let claims = value
        .claims
        .ok_or(ServiceError::MappingError("claims is None".to_string()))?;
    Ok(ConnectIssuerResponseDTO {
        id: value.id,
        issuer_did: issuer_did.into(),
        claims: from_vec_claim(claims, &schema, config)?,
        schema: schema.try_into()?,
        redirect_uri: value.redirect_uri,
    })
}
