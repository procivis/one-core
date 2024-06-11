use shared_types::DidValue;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::ExchangeProtocolError;
use crate::model::credential::Credential;
use crate::model::did::{Did, DidType};
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, CredentialGroupItem, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum, ProofClaimSchema,
};
use crate::provider::exchange_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
};

pub fn remote_did_from_value(did_value: DidValue, organisation: Organisation) -> Did {
    let id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    Did {
        id: id.into(),
        name: format!("issuer {id}"),
        created_date: now,
        last_modified: now,
        organisation: Some(organisation),
        did: did_value,
        did_type: DidType::Remote,
        did_method: "KEY".to_string(),
        keys: None,
        deactivated: false,
    }
}

pub fn get_base_url(url: &Url) -> Result<Url, ExchangeProtocolError> {
    let mut host_url = format!(
        "{}://{}",
        url.scheme(),
        url.host_str().ok_or(ExchangeProtocolError::Failed(format!(
            "Url cannot be a base {url}"
        )))?
    );

    if let Some(port) = url.port() {
        host_url.push_str(&format!(":{port}"));
    }

    host_url
        .parse()
        .map_err(|_| ExchangeProtocolError::Failed("Invalid URL".to_string()))
}
pub fn create_requested_credential(
    index: usize,
    fields: Vec<CredentialGroupItem>,
    applicable_credentials: Vec<Credential>,
    validity_credential_nbf: Option<OffsetDateTime>,
) -> Result<PresentationDefinitionRequestedCredentialResponseDTO, ExchangeProtocolError> {
    Ok(PresentationDefinitionRequestedCredentialResponseDTO {
        id: format!("input_{}", index),
        name: None,
        purpose: None,
        fields: fields
            .into_iter()
            .map(|field| create_presentation_definition_field(field, &applicable_credentials))
            .collect::<Result<Vec<_>, ExchangeProtocolError>>()?,
        applicable_credentials: applicable_credentials
            .iter()
            .map(|credential| credential.id.to_string())
            .collect(),
        validity_credential_nbf,
    })
}

pub(super) fn presentation_definition_from_proof(
    proof: &Proof,
    credentials: Vec<Credential>,
    credential_groups: Vec<CredentialGroup>,
) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
    Ok(PresentationDefinitionResponseDTO {
        request_groups: vec![PresentationDefinitionRequestGroupResponseDTO {
            id: proof.id.to_string(),
            name: None,
            purpose: None,
            rule: PresentationDefinitionRuleDTO {
                r#type: PresentationDefinitionRuleTypeEnum::All,
                min: None,
                max: None,
                count: None,
            },
            requested_credentials: credential_groups
                .into_iter()
                .enumerate()
                .map(|(index, group)| {
                    create_requested_credential(
                        index,
                        group.claims,
                        group.applicable_credentials,
                        group.validity_credential_nbf,
                    )
                })
                .collect::<Result<Vec<_>, ExchangeProtocolError>>()?,
        }],
        credentials: credential_model_to_credential_dto(credentials)?,
    })
}

pub fn get_proof_claim_schemas_from_proof(
    value: &Proof,
) -> Result<Vec<ProofClaimSchema>, ExchangeProtocolError> {
    let interaction_data = value
        .interaction
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .data
        .to_owned()
        .ok_or(ExchangeProtocolError::Failed(
            "interaction data is missing".to_string(),
        ))?;
    let json_data = String::from_utf8(interaction_data)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let proof_claim_schemas: Vec<ProofClaimSchema> = serde_json::from_str(&json_data)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
    Ok(proof_claim_schemas)
}