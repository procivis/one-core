pub mod error;

mod common;

// Implementation
pub mod json_ld_classic;
pub mod mapper;
pub mod mdoc_formatter;
pub mod physical_card;
pub mod status_list_jwt_formatter;

#[cfg(test)]
mod test;

use dto_mapper::{From, Into};
use one_providers::credential_formatter::model::{PublishedClaim, PublishedClaimValue};
use serde::Serialize;

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
    pub verification_key_storages: Vec<String>,
    pub datatypes: Vec<String>,
    pub allowed_schema_ids: Vec<String>,
    pub forbidden_claim_names: Vec<String>,
}

fn map_claims(
    claims: &[DetailCredentialClaimResponseDTO],
    array_item: bool,
) -> Vec<PublishedClaim> {
    let mut result = vec![];

    for claim in claims {
        let published_claim_value = match &claim.value {
            DetailCredentialClaimValueResponseDTO::Nested(value) => {
                result.extend(map_claims(value, claim.schema.array));
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

        let key = claim.path.clone();

        if let Some(value) = published_claim_value {
            result.push(PublishedClaim {
                key,
                value,
                datatype: Some(claim.schema.datatype.clone()),
                array_item,
            });
        }
    }

    result
}
