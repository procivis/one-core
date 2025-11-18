use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::proof_schema::GetProofSchemaQuery;
use one_core::proto::bluetooth_low_energy::low_level::dto::DeviceInfo;
use one_core::provider::verification_protocol::dto::{
    ApplicableCredentialOrFailureHintEnum, PresentationDefinitionFieldDTO,
    PresentationDefinitionRequestedCredentialResponseDTO,
};
use one_core::service::credential::dto::{
    CredentialDetailResponseDTO, CredentialListItemResponseDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO, DetailCredentialSchemaResponseDTO,
    MdocMsoValidityResponseDTO,
};
use one_core::service::credential_schema::dto::{
    CredentialSchemaListItemResponseDTO, ImportCredentialSchemaClaimSchemaDTO,
};
use one_core::service::did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO};
use one_core::service::error::ServiceError;
use one_core::service::history::dto::{HistoryMetadataResponse, HistoryResponseDTO};
use one_core::service::identifier::dto::{
    CreateIdentifierDidRequestDTO, GetIdentifierListItemResponseDTO,
};
use one_core::service::key::dto::KeyRequestDTO;
use one_core::service::organisation::dto::{
    CreateOrganisationRequestDTO, UpsertOrganisationRequestDTO,
};
use one_core::service::proof::dto::{
    GetProofQueryDTO, ProofClaimValueDTO, ProofDetailResponseDTO, ProofFilterValue,
};
use one_core::service::proof_schema::dto::{
    ImportProofSchemaClaimSchemaDTO, ProofSchemaFilterValue,
};
use one_core::service::ssi_holder::dto::{HandleInvitationResultDTO, InitiateIssuanceRequestDTO};
use one_core::service::trust_anchor::dto::{ListTrustAnchorsQueryDTO, TrustAnchorFilterValue};
use one_core::service::trust_entity::dto::{
    ListTrustEntitiesQueryDTO, TrustEntityFilterValue, TrustListLogo,
};
use one_dto_mapper::{convert_inner, convert_inner_of_inner, try_convert_inner};
use serde_json::json;
use shared_types::{KeyId, TrustEntityKey};
use time::OffsetDateTime;

use super::ble::DeviceInfoBindingDTO;
use crate::binding::credential::{
    ClaimBindingDTO, ClaimValueBindingDTO, CredentialDetailBindingDTO,
    CredentialListItemBindingDTO, MdocMsoValidityResponseBindingDTO,
};
use crate::binding::credential_schema::{
    CredentialSchemaBindingDTO, ImportCredentialSchemaClaimSchemaBindingDTO,
};
use crate::binding::did::{DidRequestBindingDTO, DidRequestKeysBindingDTO};
use crate::binding::history::{
    HistoryErrorMetadataBindingDTO, HistoryListItemBindingDTO, HistoryMetadataBinding,
};
use crate::binding::identifier::CreateIdentifierDidRequestBindingDTO;
use crate::binding::interaction::{
    HandleInvitationResponseBindingEnum, InitiateIssuanceRequestBindingDTO,
};
use crate::binding::key::KeyRequestBindingDTO;
use crate::binding::organisation::{
    CreateOrganisationRequestBindingDTO, UpsertOrganisationRequestBindingDTO,
};
use crate::binding::proof::{
    ApplicableCredentialOrFailureHintBindingEnum, PresentationDefinitionFieldBindingDTO,
    PresentationDefinitionRequestedCredentialBindingDTO, PresentationDefinitionV2ClaimBindingDTO,
    PresentationDefinitionV2ClaimValueBindingDTO,
    PresentationDefinitionV2CredentialDetailBindingDTO, ProofListQueryBindingDTO,
    ProofListQueryExactColumnBindingEnum, ProofResponseBindingDTO,
};
use crate::binding::proof_schema::{
    ImportProofSchemaClaimSchemaBindingDTO, ListProofSchemasFiltersBindingDTO,
    ProofRequestClaimValueBindingDTO, ProofSchemaListQueryExactColumnBinding,
};
use crate::binding::trust_anchor::{
    ExactTrustAnchorFilterColumnBindings, ListTrustAnchorsFiltersBindings,
};
use crate::binding::trust_entity::{
    ExactTrustEntityFilterColumnBindings, ListTrustEntitiesFiltersBindings,
};
use crate::error::ErrorResponseBindingDTO;
use crate::utils::{TimestampFormat, format_timestamp_opt, into_id, into_timestamp};

impl<IN: Into<ClaimBindingDTO>> From<CredentialDetailResponseDTO<IN>>
    for CredentialDetailBindingDTO
{
    fn from(value: CredentialDetailResponseDTO<IN>) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: value.issuance_date.map(|inner| inner.format_timestamp()),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer: value.issuer.map(Into::into),
            holder: value.holder.map(Into::into),
            state: value.state.into(),
            schema: value.schema.into(),
            claims: convert_inner(value.claims),
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            lvvc_issuance_date: value
                .lvvc_issuance_date
                .map(|lvvc_issuance_date| lvvc_issuance_date.format_timestamp()),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
            mdoc_mso_validity: value.mdoc_mso_validity.map(|inner| inner.into()),
            protocol: value.protocol,
            profile: value.profile,
        }
    }
}

impl From<MdocMsoValidityResponseDTO> for MdocMsoValidityResponseBindingDTO {
    fn from(value: MdocMsoValidityResponseDTO) -> Self {
        Self {
            expiration: value.expiration.format_timestamp(),
            next_update: value.next_update.format_timestamp(),
            last_update: value.last_update.format_timestamp(),
        }
    }
}

impl From<CredentialListItemResponseDTO> for CredentialListItemBindingDTO {
    fn from(value: CredentialListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: value.issuance_date.map(|inner| inner.format_timestamp()),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer: optional_identifier_id_string(value.issuer),
            state: value.state.into(),
            schema: value.schema.into(),
            role: value.role.into(),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
            protocol: value.protocol,
            profile: value.profile,
        }
    }
}

impl From<ProofDetailResponseDTO> for ProofResponseBindingDTO {
    fn from(value: ProofDetailResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            state: value.state.into(),
            last_modified: value.last_modified.format_timestamp(),
            proof_schema: convert_inner(value.schema),
            verifier: value.verifier.map(Into::into),
            holder: value.holder.map(Into::into),
            protocol: value.protocol,
            transport: value.transport,
            engagement: value.engagement,
            redirect_uri: value.redirect_uri,
            proof_inputs: convert_inner(value.proof_inputs),
            retain_until_date: value.retain_until_date.map(|date| date.format_timestamp()),
            requested_date: value.requested_date.map(|date| date.format_timestamp()),
            completed_date: value.completed_date.map(|date| date.format_timestamp()),
            claims_removed_at: value.claims_removed_at.map(|date| date.format_timestamp()),
            role: value.role.into(),
            profile: value.profile,
        }
    }
}

impl From<DetailCredentialSchemaResponseDTO> for CredentialSchemaBindingDTO {
    fn from(value: DetailCredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            key_storage_security: convert_inner(value.key_storage_security),
            schema_id: value.schema_id,
            imported_source_url: value.imported_source_url,
            layout_type: convert_inner(value.layout_type),
            layout_properties: convert_inner(value.layout_properties),
        }
    }
}

impl From<DetailCredentialClaimResponseDTO> for ClaimBindingDTO {
    fn from(value: DetailCredentialClaimResponseDTO) -> Self {
        Self {
            id: value.schema.id.to_string(),
            key: value.schema.key,
            array: value.schema.array,
            data_type: value.schema.datatype,
            value: value.value.into(),
        }
    }
}

impl<T: Into<ClaimBindingDTO>> From<DetailCredentialClaimValueResponseDTO<T>>
    for ClaimValueBindingDTO
{
    fn from(value: DetailCredentialClaimValueResponseDTO<T>) -> Self {
        match value {
            DetailCredentialClaimValueResponseDTO::Boolean(value) => {
                ClaimValueBindingDTO::Boolean { value }
            }
            DetailCredentialClaimValueResponseDTO::Float(value) => {
                ClaimValueBindingDTO::Float { value }
            }
            DetailCredentialClaimValueResponseDTO::Integer(value) => {
                ClaimValueBindingDTO::Integer { value }
            }
            DetailCredentialClaimValueResponseDTO::String(value) => {
                ClaimValueBindingDTO::String { value }
            }
            DetailCredentialClaimValueResponseDTO::Nested(value) => ClaimValueBindingDTO::Nested {
                value: value.into_iter().map(|v| v.into()).collect(),
            },
        }
    }
}

impl From<HandleInvitationResultDTO> for HandleInvitationResponseBindingEnum {
    fn from(value: HandleInvitationResultDTO) -> Self {
        match value {
            HandleInvitationResultDTO::Credential {
                interaction_id,
                tx_code,
                key_storage_security,
            } => Self::CredentialIssuance {
                interaction_id: interaction_id.to_string(),
                tx_code: convert_inner(tx_code),
                key_storage_security: convert_inner(key_storage_security),
            },
            HandleInvitationResultDTO::AuthorizationCodeFlow {
                interaction_id,
                authorization_code_flow_url,
            } => Self::AuthorizationCodeFlow {
                interaction_id: interaction_id.to_string(),
                authorization_code_flow_url,
            },
            HandleInvitationResultDTO::ProofRequest {
                interaction_id,
                proof_id,
            } => Self::ProofRequest {
                interaction_id: interaction_id.to_string(),
                proof_id: proof_id.to_string(),
            },
        }
    }
}

impl TryFrom<KeyRequestBindingDTO> for KeyRequestDTO {
    type Error = ServiceError;
    fn try_from(request: KeyRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_id(&request.organisation_id)?,
            key_type: request.key_type,
            key_params: json!(request.key_params),
            name: request.name,
            storage_type: request.storage_type,
            storage_params: json!(request.storage_params),
        })
    }
}

impl TryFrom<DidRequestBindingDTO> for CreateDidRequestDTO {
    type Error = ServiceError;
    fn try_from(request: DidRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_id(&request.organisation_id)?,
            name: request.name,
            did_method: request.did_method,
            keys: request.keys.try_into()?,
            params: Some(json!(request.params)),
        })
    }
}

impl TryFrom<DidRequestKeysBindingDTO> for CreateDidRequestKeysDTO {
    type Error = ServiceError;
    fn try_from(request: DidRequestKeysBindingDTO) -> Result<Self, Self::Error> {
        let convert = |ids: Vec<String>| -> Result<Vec<KeyId>, Self::Error> {
            ids.iter().map(into_id).collect()
        };

        Ok(Self {
            authentication: convert(request.authentication)?,
            assertion_method: convert(request.assertion_method)?,
            key_agreement: convert(request.key_agreement)?,
            capability_invocation: convert(request.capability_invocation)?,
            capability_delegation: convert(request.capability_delegation)?,
        })
    }
}

impl From<HistoryMetadataResponse> for HistoryMetadataBinding {
    fn from(value: HistoryMetadataResponse) -> Self {
        match value {
            HistoryMetadataResponse::UnexportableEntities(value) => Self::UnexportableEntities {
                value: value.into(),
            },
            HistoryMetadataResponse::ErrorMetadata(value) => Self::ErrorMetadata {
                value: HistoryErrorMetadataBindingDTO {
                    error_code: Into::<&'static str>::into(value.error_code).to_string(),
                    message: value.message,
                },
            },
            HistoryMetadataResponse::WalletUnitJWT(value) => {
                HistoryMetadataBinding::WalletUnitJWT(value)
            }
        }
    }
}

impl From<HistoryResponseDTO> for HistoryListItemBindingDTO {
    fn from(value: HistoryResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            action: value.action.into(),
            name: value.name,
            entity_id: value.entity_id.map(|id| id.to_string()),
            entity_type: value.entity_type.into(),
            metadata: convert_inner(value.metadata),
            organisation_id: value.organisation_id.map(|id| id.to_string()),
            target: value.target,
            user: value.user,
        }
    }
}

impl From<CredentialSchemaListItemResponseDTO> for CredentialSchemaBindingDTO {
    fn from(value: CredentialSchemaListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            name: value.name,
            format: value.format,
            imported_source_url: value.imported_source_url,
            revocation_method: value.revocation_method,
            key_storage_security: convert_inner(value.key_storage_security),
            schema_id: value.schema_id,
            layout_type: convert_inner(value.layout_type),
            layout_properties: convert_inner(value.layout_properties),
        }
    }
}

impl TryFrom<ListTrustAnchorsFiltersBindings> for ListTrustAnchorsQueryDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ListTrustAnchorsFiltersBindings) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = value.name.map(|name| {
            TrustAnchorFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactTrustAnchorFilterColumnBindings::Name),
                value: name,
            })
        });

        let is_publisher = value.is_publisher.map(TrustAnchorFilterValue::IsPublisher);

        let r#type = value.r#type.map(|r#type| {
            TrustAnchorFilterValue::Type(StringMatch {
                r#match: get_string_match_type(ExactTrustAnchorFilterColumnBindings::Type),
                value: r#type,
            })
        });

        let created_date_after = value
            .created_date_after
            .map(|date| {
                Ok::<_, ServiceError>(TrustAnchorFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let created_date_before = value
            .created_date_before
            .map(|date| {
                Ok::<_, ServiceError>(TrustAnchorFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let last_modified_after = value
            .last_modified_after
            .map(|date| {
                Ok::<_, ServiceError>(TrustAnchorFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let last_modified_before = value
            .last_modified_before
            .map(|date| {
                Ok::<_, ServiceError>(TrustAnchorFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let filtering = ListFilterCondition::<TrustAnchorFilterValue>::from(name)
            & is_publisher
            & r#type
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before;

        Ok(Self {
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size,
            }),
            sorting: value.sort.map(|column| ListSorting {
                column: column.into(),
                direction: convert_inner(value.sort_direction),
            }),
            filtering: Some(filtering),
            include: None,
        })
    }
}

impl TryFrom<ListTrustEntitiesFiltersBindings> for ListTrustEntitiesQueryDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ListTrustEntitiesFiltersBindings) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = value.name.map(|name| {
            TrustEntityFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactTrustEntityFilterColumnBindings::Name),
                value: name,
            })
        });

        let role = value
            .role
            .map(|role| Ok::<_, ServiceError>(TrustEntityFilterValue::Role(role.into())))
            .transpose()?;

        let trust_anchor = value
            .trust_anchor
            .map(|id| Ok::<_, ServiceError>(TrustEntityFilterValue::TrustAnchor(into_id(&id)?)))
            .transpose()?;

        let organisation_id = value
            .organisation_id
            .map(|id| Ok::<_, ServiceError>(TrustEntityFilterValue::OrganisationId(into_id(&id)?)))
            .transpose()?;

        let types = value
            .types
            .map(convert_inner)
            .map(TrustEntityFilterValue::Types);

        let states = value
            .states
            .map(convert_inner)
            .map(TrustEntityFilterValue::States);

        let entity_key = value
            .entity_key
            .map(|k| TrustEntityFilterValue::EntityKey(TrustEntityKey::from(k)));

        let created_date_after = value
            .created_date_after
            .map(|date| {
                Ok::<_, ServiceError>(TrustEntityFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let created_date_before = value
            .created_date_before
            .map(|date| {
                Ok::<_, ServiceError>(TrustEntityFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let last_modified_after = value
            .last_modified_after
            .map(|date| {
                Ok::<_, ServiceError>(TrustEntityFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let last_modified_before = value
            .last_modified_before
            .map(|date| {
                Ok::<_, ServiceError>(TrustEntityFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let filtering = ListFilterCondition::<TrustEntityFilterValue>::from(name)
            & role
            & trust_anchor
            & organisation_id
            & types
            & entity_key
            & states
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before;

        Ok(Self {
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size,
            }),
            sorting: value.sort.map(|column| ListSorting {
                column: column.into(),
                direction: convert_inner(value.sort_direction),
            }),
            filtering: Some(filtering),
            include: None,
        })
    }
}

impl TryFrom<ListProofSchemasFiltersBindingDTO> for GetProofSchemaQuery {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ListProofSchemasFiltersBindingDTO) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();

        let organisation_id =
            ProofSchemaFilterValue::OrganisationId(into_id(&value.organisation_id)?).condition();

        let name = value.name.map(|name| {
            let filter = if exact.contains(&ProofSchemaListQueryExactColumnBinding::Name) {
                StringMatch::equals(name)
            } else {
                StringMatch::starts_with(name)
            };

            ProofSchemaFilterValue::Name(filter)
        });

        let proof_schema_ids = value
            .ids
            .map(|ids| ids.into_iter().map(|id| into_id(&id)).collect())
            .transpose()?
            .map(ProofSchemaFilterValue::ProofSchemaIds);

        let formats = value.formats.map(ProofSchemaFilterValue::Formats);

        let created_date_after = value
            .created_date_after
            .map(|date| {
                Ok::<_, ServiceError>(ProofSchemaFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let created_date_before = value
            .created_date_before
            .map(|date| {
                Ok::<_, ServiceError>(ProofSchemaFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let last_modified_after = value
            .last_modified_after
            .map(|date| {
                Ok::<_, ServiceError>(ProofSchemaFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let last_modified_before = value
            .last_modified_before
            .map(|date| {
                Ok::<_, ServiceError>(ProofSchemaFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let filtering = organisation_id
            & name
            & proof_schema_ids
            & formats
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before;

        Ok(Self {
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size,
            }),
            sorting: value.sort.map(|sort| ListSorting {
                column: sort.into(),
                direction: convert_inner(value.sort_direction),
            }),
            filtering: Some(filtering),
            ..Default::default()
        })
    }
}

impl TryFrom<ProofListQueryBindingDTO> for GetProofQueryDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ProofListQueryBindingDTO) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();

        let organisation_id =
            ProofFilterValue::OrganisationId(into_id(&value.organisation_id)?).condition();

        let name = value.name.map(|name| {
            let filter = if exact.contains(&ProofListQueryExactColumnBindingEnum::Name) {
                StringMatch::equals(name)
            } else {
                StringMatch::starts_with(name)
            };

            ProofFilterValue::Name(filter)
        });

        let proof_states = value
            .proof_states
            .map(|proof_states| ProofFilterValue::States(convert_inner(proof_states)));

        let proof_roles = value
            .proof_roles
            .map(|proof_roles| ProofFilterValue::Roles(convert_inner(proof_roles)));

        let proof_ids = value
            .ids
            .map(|ids| ids.into_iter().map(|id| into_id(&id)).collect())
            .transpose()?
            .map(ProofFilterValue::ProofIds);

        let proof_schema_ids = value
            .proof_schema_ids
            .map(|ids| ids.into_iter().map(|id| into_id(&id)).collect())
            .transpose()?
            .map(ProofFilterValue::ProofSchemaIds);

        let profile = value.profiles.map(ProofFilterValue::Profiles);

        let created_date_after = value
            .created_date_after
            .map(|date| {
                Ok::<_, ServiceError>(ProofFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let created_date_before = value
            .created_date_before
            .map(|date| {
                Ok::<_, ServiceError>(ProofFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let last_modified_after = value
            .last_modified_after
            .map(|date| {
                Ok::<_, ServiceError>(ProofFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let last_modified_before = value
            .last_modified_before
            .map(|date| {
                Ok::<_, ServiceError>(ProofFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let requested_date_after = value
            .requested_date_after
            .map(|date| {
                Ok::<_, ServiceError>(ProofFilterValue::RequestedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let requested_date_before = value
            .requested_date_before
            .map(|date| {
                Ok::<_, ServiceError>(ProofFilterValue::RequestedDate(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let completed_date_after = value
            .completed_date_after
            .map(|date| {
                Ok::<_, ServiceError>(ProofFilterValue::CompletedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;
        let completed_date_before = value
            .completed_date_before
            .map(|date| {
                Ok::<_, ServiceError>(ProofFilterValue::CompletedDate(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&date)?,
                }))
            })
            .transpose()?;

        let filtering = organisation_id
            & name
            & proof_states
            & proof_roles
            & proof_schema_ids
            & proof_ids
            & profile
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & requested_date_after
            & requested_date_before
            & completed_date_after
            & completed_date_before;

        Ok({
            Self {
                pagination: Some(ListPagination {
                    page: value.page,
                    page_size: value.page_size,
                }),
                sorting: value.sort.map(|sort| ListSorting {
                    column: sort.into(),
                    direction: convert_inner(value.sort_direction),
                }),
                filtering: filtering.into(),
                include: None,
            }
        })
    }
}

impl TryFrom<ImportProofSchemaClaimSchemaBindingDTO> for ImportProofSchemaClaimSchemaDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ImportProofSchemaClaimSchemaBindingDTO) -> Result<Self, Self::Error> {
        let claims = value.claims.unwrap_or_default();
        Ok(Self {
            id: into_id(&value.id)?,
            requested: value.requested,
            required: value.required,
            key: value.key,
            data_type: value.data_type,
            claims: try_convert_inner(claims)?,
            array: value.array,
        })
    }
}

impl TryFrom<ImportCredentialSchemaClaimSchemaBindingDTO> for ImportCredentialSchemaClaimSchemaDTO {
    type Error = ServiceError;

    fn try_from(value: ImportCredentialSchemaClaimSchemaBindingDTO) -> Result<Self, Self::Error> {
        let claims = value.claims.unwrap_or_default();
        Ok(Self {
            id: into_id(&value.id)?,
            created_date: into_timestamp(&value.created_date)?,
            last_modified: into_timestamp(&value.last_modified)?,
            required: value.required,
            key: value.key,
            datatype: value.datatype,
            array: value.array,
            claims: try_convert_inner(claims)?,
        })
    }
}

impl From<DeviceInfoBindingDTO> for DeviceInfo {
    fn from(value: DeviceInfoBindingDTO) -> Self {
        Self::new(value.address, value.mtu)
    }
}

impl From<ProofClaimValueDTO> for ProofRequestClaimValueBindingDTO {
    fn from(value: ProofClaimValueDTO) -> Self {
        match value {
            ProofClaimValueDTO::Value(value) => Self::Value { value },
            ProofClaimValueDTO::Claims(claims) => ProofRequestClaimValueBindingDTO::Claims {
                value: convert_inner(claims),
            },
        }
    }
}

/// uniffi does not support double option.
/// workaround for `Option<Option<String>>`
#[derive(Clone, Debug, uniffi::Enum)]
pub enum OptionalString {
    None,
    Some { value: String },
}

impl From<OptionalString> for Option<String> {
    fn from(value: OptionalString) -> Self {
        match value {
            OptionalString::None => None,
            OptionalString::Some { value } => Some(value),
        }
    }
}

impl TryFrom<OptionalString> for Option<TrustListLogo> {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: OptionalString) -> Result<Self, Self::Error> {
        match value {
            OptionalString::None => Ok(None),
            OptionalString::Some { value } => {
                Some(value.try_into()).transpose().map_err(Into::into)
            }
        }
    }
}

pub(crate) fn optional_time(value: Option<OffsetDateTime>) -> Option<String> {
    value.as_ref().map(TimestampFormat::format_timestamp)
}

pub(crate) fn deserialize_timestamp(value: &str) -> Result<OffsetDateTime, ServiceError> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|e| ServiceError::ValidationError(e.to_string()))
}

pub(crate) fn optional_identifier_id_string(
    value: Option<GetIdentifierListItemResponseDTO>,
) -> Option<String> {
    value.map(|inner| inner.id.to_string())
}

impl TryFrom<CreateOrganisationRequestBindingDTO> for CreateOrganisationRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CreateOrganisationRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id.map(|id| into_id(&id)).transpose()?,
            name: value.name,
        })
    }
}

impl TryFrom<UpsertOrganisationRequestBindingDTO> for UpsertOrganisationRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: UpsertOrganisationRequestBindingDTO) -> Result<Self, Self::Error> {
        let wallet_provider_issuer = value
            .wallet_provider_issuer
            .map(|val| {
                Option::<String>::from(val)
                    .map(|val| into_id(&val))
                    .transpose()
            })
            .transpose()?;

        Ok(Self {
            id: into_id(&value.id)?,
            name: value.name,
            deactivate: value.deactivate,
            wallet_provider: convert_inner(value.wallet_provider),
            wallet_provider_issuer,
        })
    }
}

impl TryFrom<CreateIdentifierDidRequestBindingDTO> for CreateIdentifierDidRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CreateIdentifierDidRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            method: value.method,
            keys: value.keys.try_into()?,
            params: Some(json!(value.params)),
        })
    }
}

impl From<PresentationDefinitionRequestedCredentialResponseDTO>
    for PresentationDefinitionRequestedCredentialBindingDTO
{
    fn from(value: PresentationDefinitionRequestedCredentialResponseDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
            purpose: value.purpose,
            multiple: value.multiple,
            fields: convert_inner(value.fields),
            applicable_credentials: value
                .applicable_credentials
                .iter()
                .map(|item| item.to_string())
                .collect(),
            inapplicable_credentials: value
                .inapplicable_credentials
                .iter()
                .map(|item| item.to_string())
                .collect(),
            validity_credential_nbf: format_timestamp_opt(value.validity_credential_nbf),
        }
    }
}

impl From<PresentationDefinitionFieldDTO> for PresentationDefinitionFieldBindingDTO {
    fn from(value: PresentationDefinitionFieldDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
            purpose: value.purpose,
            required: value.required.unwrap_or(true),
            key_map: value
                .key_map
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
        }
    }
}

impl TryFrom<InitiateIssuanceRequestBindingDTO> for InitiateIssuanceRequestDTO {
    type Error = ServiceError;
    fn try_from(request: InitiateIssuanceRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_id(request.organisation_id)?,
            protocol: request.protocol,
            issuer: request.issuer,
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            scope: request.scope,
            authorization_details: convert_inner_of_inner(request.authorization_details),
            issuer_state: None,
            authorization_server: None,
        })
    }
}

impl<IN: Into<PresentationDefinitionV2ClaimBindingDTO>> From<CredentialDetailResponseDTO<IN>>
    for PresentationDefinitionV2CredentialDetailBindingDTO
{
    fn from(value: CredentialDetailResponseDTO<IN>) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: optional_time(value.issuance_date),
            revocation_date: optional_time(value.revocation_date),
            state: value.state.into(),
            last_modified: value.last_modified.format_timestamp(),
            schema: value.schema.into(),
            issuer: convert_inner(value.issuer),
            issuer_certificate: convert_inner(value.issuer_certificate),
            claims: convert_inner(value.claims),
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            lvvc_issuance_date: optional_time(value.lvvc_issuance_date),
            suspend_end_date: optional_time(value.suspend_end_date),
            mdoc_mso_validity: convert_inner(value.mdoc_mso_validity),
            holder: convert_inner(value.holder),
            protocol: value.protocol,
            profile: value.profile,
        }
    }
}

impl<T: Into<PresentationDefinitionV2ClaimBindingDTO>>
    From<DetailCredentialClaimValueResponseDTO<T>>
    for PresentationDefinitionV2ClaimValueBindingDTO
{
    fn from(value: DetailCredentialClaimValueResponseDTO<T>) -> Self {
        match value {
            DetailCredentialClaimValueResponseDTO::Boolean(value) => Self::Boolean { value },
            DetailCredentialClaimValueResponseDTO::Float(value) => Self::Float { value },
            DetailCredentialClaimValueResponseDTO::Integer(value) => Self::Integer { value },
            DetailCredentialClaimValueResponseDTO::String(value) => Self::String { value },
            DetailCredentialClaimValueResponseDTO::Nested(value) => Self::Nested {
                value: value.into_iter().map(|v| v.into()).collect(),
            },
        }
    }
}

impl From<ApplicableCredentialOrFailureHintEnum> for ApplicableCredentialOrFailureHintBindingEnum {
    fn from(value: ApplicableCredentialOrFailureHintEnum) -> Self {
        match value {
            ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
                applicable_credentials,
            } => Self::ApplicableCredentials {
                applicable_credentials: convert_inner(applicable_credentials),
            },
            ApplicableCredentialOrFailureHintEnum::FailureHint { failure_hint } => {
                Self::FailureHint {
                    failure_hint: (*failure_hint).into(),
                }
            }
        }
    }
}
