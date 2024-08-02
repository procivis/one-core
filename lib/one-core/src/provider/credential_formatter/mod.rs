pub mod error;

mod common;

// Implementatio
pub mod json_ld_classic;
pub mod mapper;
pub mod mdoc_formatter;
pub mod physical_card;
pub mod sdjwt_formatter;
pub mod status_list_jwt_formatter;

#[cfg(test)]
mod test;
#[cfg(test)]
pub(crate) mod test_utilities;

use dto_mapper::{From, Into};
use one_providers::credential_formatter::model::{PublishedClaim, PublishedClaimValue};
use serde::Serialize;
use std::collections::HashMap;

use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::service::credential::dto::{
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
};

#[derive(Clone, Default, Serialize, From, Into)]
#[serde(rename_all = "camelCase")]
#[from(one_providers::credential_formatter::model::FormatterCapabilities)]
#[into(one_providers::credential_formatter::model::FormatterCapabilities)]
pub struct FormatterCapabilities {
    pub features: Vec<String>,
    pub selective_disclosure: Vec<String>,
    pub issuance_did_methods: Vec<String>,
    pub issuance_exchange_protocols: Vec<String>,
    pub proof_exchange_protocols: Vec<String>,
    pub revocation_methods: Vec<String>,
    pub signing_key_algorithms: Vec<String>,
    pub verification_key_algorithms: Vec<String>,
    pub datatypes: Vec<String>,
    pub allowed_schema_ids: Vec<String>,
    pub forbidden_claim_names: Vec<String>,
}

fn map_claims(
    config: &CoreConfig,
    claims: &[DetailCredentialClaimResponseDTO],
    array_order: &mut HashMap<String, usize>,
    prefix: &str,
    array_item: bool,
    object_item: bool,
) -> Vec<PublishedClaim> {
    let mut result = vec![];

    for claim in claims {
        let published_claim_value = match &claim.value {
            DetailCredentialClaimValueResponseDTO::Nested(value) => {
                let key = if array_item {
                    let array_index = array_order.entry(prefix.to_string()).or_default();
                    let current_index = array_index.to_owned();
                    *array_index += 1;
                    current_index.to_string()
                } else {
                    claim.schema.key.clone()
                };

                let is_object = config
                    .get_datatypes_of_type(DatatypeType::Object)
                    .contains(&claim.schema.datatype.as_str());

                let nested_claims = map_claims(
                    config,
                    value,
                    array_order,
                    &format!("{prefix}{key}/"),
                    claim.schema.array,
                    is_object,
                );
                result.extend(nested_claims);

                None
            }
            DetailCredentialClaimValueResponseDTO::String(value) => {
                Some(PublishedClaimValue::String(value.to_owned()))
            }
            DetailCredentialClaimValueResponseDTO::Boolean(value) => {
                Some(PublishedClaimValue::Bool(value.to_owned()))
            }
            DetailCredentialClaimValueResponseDTO::Float(value) => {
                Some(PublishedClaimValue::Float(value.to_owned()))
            }
            DetailCredentialClaimValueResponseDTO::Integer(value) => {
                Some(PublishedClaimValue::Integer(value.to_owned()))
            }
        };

        let key = if array_item && !object_item {
            claim.path.clone()
        } else {
            format!("{prefix}{}", claim.schema.key.clone())
        };

        if let Some(value) = published_claim_value {
            result.push(PublishedClaim {
                key,
                value,
                datatype: Some(claim.clone().schema.datatype),
                array_item,
            });
        }
    }

    result
}
