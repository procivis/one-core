use super::dto::HandleInvitationURLQuery;
use crate::{
    common_mapper::vector_try_into,
    credential_formatter::{VCCredentialClaimSchemaResponse, VCCredentialSchemaResponse},
    model::{
        claim_schema::ClaimSchema,
        credential_schema::CredentialSchema,
        did::{Did, DidId, DidType},
        organisation::{Organisation, OrganisationId},
    },
    service::{
        credential_schema::dto::GetCredentialSchemaListValueResponseDTO,
        error::ServiceError,
        ssi_verifier::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO},
    },
    transport_protocol::dto::{ConnectVerifierResponse, ProofClaimSchema, ProofCredentialSchema},
};
use std::{collections::HashMap, str::FromStr};
use time::OffsetDateTime;
use uuid::Uuid;

pub(super) fn parse_query(url: &str) -> Result<HandleInvitationURLQuery, ServiceError> {
    let query: HashMap<String, String> = reqwest::Url::parse(url)
        .map_err(|_| ServiceError::IncorrectParameters)?
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();

    fn option_parse_uuid(input: Option<&String>) -> Result<Option<Uuid>, ServiceError> {
        Ok(match input {
            None => None,
            Some(str) => Some(string_to_uuid(str)?),
        })
    }

    Ok(HandleInvitationURLQuery {
        protocol: query
            .get("protocol")
            .ok_or(ServiceError::IncorrectParameters)?
            .to_owned(),
        credential: option_parse_uuid(query.get("credential"))?,
        _proof: option_parse_uuid(query.get("proof"))?,
    })
}

pub fn credential_schema_from_jwt(
    schema: VCCredentialSchemaResponse,
    organisation: Organisation,
) -> Result<CredentialSchema, ServiceError> {
    let now = OffsetDateTime::now_utc();
    Ok(CredentialSchema {
        id: string_to_uuid(&schema.id)?,
        name: schema.name,
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        claim_schemas: Some(vector_try_into(schema.claims)?),
        organisation: Some(organisation),
    })
}

pub fn remote_did_from_value(did_value: String, organisation_id: OrganisationId) -> Did {
    let now = OffsetDateTime::now_utc();
    Did {
        id: DidId::new_v4(),
        name: "issuer".to_string(),
        created_date: now,
        last_modified: now,
        organisation_id,
        did: did_value,
        did_type: DidType::Remote,
        did_method: "KEY".to_string(),
    }
}

impl TryFrom<VCCredentialClaimSchemaResponse> for ClaimSchema {
    type Error = ServiceError;
    fn try_from(value: VCCredentialClaimSchemaResponse) -> Result<Self, Self::Error> {
        let now = OffsetDateTime::now_utc();
        Ok(Self {
            id: string_to_uuid(&value.id)?,
            key: value.key,
            data_type: value.datatype,
            created_date: now,
            last_modified: now,
        })
    }
}

pub fn string_to_uuid(value: &str) -> Result<Uuid, ServiceError> {
    Uuid::from_str(value).map_err(|e| ServiceError::MappingError(e.to_string()))
}

impl TryFrom<ConnectVerifierResponse> for ConnectVerifierResponseDTO {
    type Error = ServiceError;

    fn try_from(value: ConnectVerifierResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            claims: vector_try_into(value.claims)?,
        })
    }
}

impl TryFrom<ProofClaimSchema> for ProofRequestClaimDTO {
    type Error = ServiceError;
    fn try_from(value: ProofClaimSchema) -> Result<Self, Self::Error> {
        Ok(Self {
            id: string_to_uuid(&value.id)?,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
            required: value.required,
            credential_schema: value.credential_schema.try_into()?,
        })
    }
}

impl TryFrom<ProofCredentialSchema> for GetCredentialSchemaListValueResponseDTO {
    type Error = ServiceError;

    fn try_from(value: ProofCredentialSchema) -> Result<Self, Self::Error> {
        Ok(Self {
            id: string_to_uuid(&value.id)?,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
        })
    }
}
