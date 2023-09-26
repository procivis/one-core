use super::dto::HandleInvitationURLQuery;
use crate::{
    common_mapper::vector_try_into,
    credential_formatter::VCCredentialClaimSchemaResponse,
    model::{
        claim_schema::ClaimSchema,
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::{Did, DidId, DidType},
        interaction::Interaction,
        organisation::OrganisationId,
        proof::{self, Proof, ProofStateEnum},
    },
    service::{
        credential::dto::CredentialSchemaResponseDTO,
        credential_schema::dto::{CredentialClaimSchemaDTO, CredentialSchemaListItemResponseDTO},
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

    Ok(HandleInvitationURLQuery {
        protocol: query
            .get("protocol")
            .ok_or(ServiceError::IncorrectParameters)?
            .to_owned(),
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

impl TryFrom<VCCredentialClaimSchemaResponse> for CredentialSchemaClaim {
    type Error = ServiceError;
    fn try_from(value: VCCredentialClaimSchemaResponse) -> Result<Self, Self::Error> {
        let now = OffsetDateTime::now_utc();
        Ok(Self {
            schema: ClaimSchema {
                id: string_to_uuid(&value.id)?,
                key: value.key,
                data_type: value.datatype,
                created_date: now,
                last_modified: now,
            },
            required: value.required,
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
            verifier_did: value.verifier_did,
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

impl TryFrom<ProofCredentialSchema> for CredentialSchemaListItemResponseDTO {
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

pub fn interaction_from_handle_invitation(
    host: String,
    data: Option<Vec<u8>>,
    now: OffsetDateTime,
) -> Interaction {
    Interaction {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        host: Some(host),
        data,
    }
}

pub fn proof_from_handle_invitation(
    protocol: &str,
    verifier_did: Did,
    interaction: Interaction,
    now: OffsetDateTime,
) -> Proof {
    Proof {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        issuance_date: now,
        transport: protocol.to_owned(),
        state: Some(vec![proof::ProofState {
            created_date: now,
            last_modified: now,
            state: ProofStateEnum::Pending,
        }]),
        schema: None,
        claims: None,
        verifier_did: Some(verifier_did),
        holder_did: None,
        interaction: Some(interaction),
    }
}

impl From<CredentialSchemaResponseDTO> for CredentialSchema {
    fn from(value: CredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            deleted_at: None,
            claim_schemas: None,
            organisation: None,
        }
    }
}

impl From<CredentialClaimSchemaDTO> for CredentialSchemaClaim {
    fn from(value: CredentialClaimSchemaDTO) -> Self {
        Self {
            schema: ClaimSchema {
                id: value.id,
                key: value.key,
                data_type: value.datatype,
                created_date: value.created_date,
                last_modified: value.last_modified,
            },
            required: value.required,
        }
    }
}
