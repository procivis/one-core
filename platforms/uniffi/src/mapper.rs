use std::collections::HashMap;

use dto_mapper::{convert_inner, convert_inner_of_inner, try_convert_inner};
use one_core::model::common::GetListQueryParams;
use one_core::model::did::DidType;
use one_core::model::list_filter::{ListFilterValue, StringMatch, StringMatchType};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::proof_schema::SortableProofSchemaColumn;
use one_core::provider::bluetooth_low_energy::low_level::dto::DeviceInfo;
use one_core::provider::exchange_protocol::openid4vc::model::InvitationResponseDTO;
use one_core::service::credential::dto::{
    CredentialDetailResponseDTO, CredentialListItemResponseDTO, CredentialSchemaType,
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
    DetailCredentialSchemaResponseDTO,
};
use one_core::service::credential_schema::dto::{
    CredentialSchemaListItemResponseDTO, ImportCredentialSchemaClaimSchemaDTO,
};
use one_core::service::did::dto::{
    CreateDidRequestDTO, CreateDidRequestKeysDTO, DidListItemResponseDTO,
};
use one_core::service::error::ServiceError;
use one_core::service::history::dto::{HistoryMetadataResponse, HistoryResponseDTO};
use one_core::service::key::dto::KeyRequestDTO;
use one_core::service::proof::dto::{GetProofQueryDTO, ProofDetailResponseDTO, ProofFilterValue};
use one_core::service::proof_schema::dto::ImportProofSchemaClaimSchemaDTO;
use one_core::service::trust_anchor::dto::{
    CreateTrustAnchorRequestDTO, ListTrustAnchorsQueryDTO, TrustAnchorFilterValue,
};
use serde_json::json;
use shared_types::KeyId;
use time::OffsetDateTime;

use super::dto::{ClaimBindingDTO, ClaimValueBindingDTO, CredentialSchemaBindingDTO};
use crate::dto::{
    CredentialDetailBindingDTO, CredentialListItemBindingDTO, DidRequestBindingDTO,
    DidRequestKeysBindingDTO, HandleInvitationResponseBindingEnum, KeyRequestBindingDTO,
    ProofRequestBindingDTO,
};
use crate::error::BindingError;
use crate::utils::{into_id, into_timestamp, TimestampFormat};
use crate::{
    CreateTrustAnchorRequestBindingDTO, CredentialSchemaTypeBindingEnum, DeviceInfoBindingDTO,
    ExactTrustAnchorFilterColumnBindings, HistoryListItemBindingDTO, HistoryMetadataBinding,
    ImportCredentialSchemaClaimSchemaBindingDTO, ImportProofSchemaClaimSchemaBindingDTO,
    ListProofSchemasFiltersBindingDTO, ListTrustAnchorsFiltersBindings, ProofListQueryBindingDTO,
    ProofListQueryExactColumnBindingEnum,
};

pub(crate) fn serialize_config_entity(
    input: HashMap<String, serde_json::Value>,
) -> HashMap<String, String> {
    input
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .collect()
}

impl From<CredentialDetailResponseDTO> for CredentialDetailBindingDTO {
    fn from(value: CredentialDetailResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer_did: optional_did_string(value.issuer_did),
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
        }
    }
}

impl From<CredentialListItemResponseDTO> for CredentialListItemBindingDTO {
    fn from(value: CredentialListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer_did: optional_did_string(value.issuer_did),
            state: value.state.into(),
            schema: value.schema.into(),
            role: value.role.into(),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
        }
    }
}

impl From<ProofDetailResponseDTO> for ProofRequestBindingDTO {
    fn from(value: ProofDetailResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            state: value.state.into(),
            last_modified: value.last_modified.format_timestamp(),
            proof_schema: convert_inner(value.schema),
            verifier_did: optional_did_string(value.verifier_did),
            exchange: value.exchange,
            redirect_uri: value.redirect_uri,
            proof_inputs: convert_inner(value.proof_inputs),
            retain_until_date: value
                .retain_until_date
                .map(|retain_until_date| retain_until_date.format_timestamp()),
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
            wallet_storage_type: convert_inner(value.wallet_storage_type),
            schema_id: value.schema_id,
            schema_type: value.schema_type.into(),
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

impl From<DetailCredentialClaimValueResponseDTO> for ClaimValueBindingDTO {
    fn from(value: DetailCredentialClaimValueResponseDTO) -> Self {
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

impl From<InvitationResponseDTO> for HandleInvitationResponseBindingEnum {
    fn from(value: InvitationResponseDTO) -> Self {
        match value {
            InvitationResponseDTO::Credential {
                credentials,
                interaction_id,
            } => Self::CredentialIssuance {
                interaction_id: interaction_id.to_string(),
                credential_ids: credentials.iter().map(|item| item.id.to_string()).collect(),
            },
            InvitationResponseDTO::ProofRequest {
                interaction_id,
                proof,
            } => Self::ProofRequest {
                interaction_id: interaction_id.to_string(),
                proof_id: proof.id.to_string(),
            },
        }
    }
}

impl TryFrom<KeyRequestBindingDTO> for KeyRequestDTO {
    type Error = ServiceError;
    fn try_from(request: KeyRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_id(&request.organisation_id)?,
            key_type: request.key_type.to_owned(),
            key_params: json!(request.key_params),
            name: request.name.to_owned(),
            storage_type: request.storage_type.to_owned(),
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
            did_type: DidType::Local,
            keys: request.keys.try_into()?,
            params: Some(json!(request.params)),
        })
    }
}

impl TryFrom<DidRequestKeysBindingDTO> for CreateDidRequestKeysDTO {
    type Error = ServiceError;
    fn try_from(request: DidRequestKeysBindingDTO) -> Result<Self, Self::Error> {
        let convert = |ids: Vec<String>| -> Result<Vec<KeyId>, Self::Error> {
            ids.iter().map(|id| into_id(id)).collect()
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
        }
    }
}

impl From<HistoryResponseDTO> for HistoryListItemBindingDTO {
    fn from(value: HistoryResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            action: value.action.into(),
            entity_id: value.entity_id.map(|id| id.to_string()),
            entity_type: value.entity_type.into(),
            metadata: convert_inner(value.metadata),
            organisation_id: value.organisation_id.to_string(),
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
            wallet_storage_type: convert_inner(value.wallet_storage_type),
            schema_id: value.schema_id,
            schema_type: value.schema_type.into(),
            layout_type: convert_inner(value.layout_type),
            layout_properties: convert_inner(value.layout_properties),
        }
    }
}

impl From<CredentialSchemaType> for CredentialSchemaTypeBindingEnum {
    fn from(value: CredentialSchemaType) -> Self {
        match value {
            CredentialSchemaType::ProcivisOneSchema2024 => Self::ProcivisOneSchema2024 {},
            CredentialSchemaType::FallbackSchema2024 => Self::FallbackSchema2024 {},
            CredentialSchemaType::Mdoc => Self::Mdoc {},
            CredentialSchemaType::Other(value) => Self::Other { value },
        }
    }
}

impl From<CredentialSchemaTypeBindingEnum> for CredentialSchemaType {
    fn from(value: CredentialSchemaTypeBindingEnum) -> Self {
        match value {
            CredentialSchemaTypeBindingEnum::ProcivisOneSchema2024 { .. } => {
                CredentialSchemaType::ProcivisOneSchema2024
            }
            CredentialSchemaTypeBindingEnum::FallbackSchema2024 { .. } => {
                CredentialSchemaType::FallbackSchema2024
            }
            CredentialSchemaTypeBindingEnum::Mdoc { .. } => CredentialSchemaType::Mdoc,
            CredentialSchemaTypeBindingEnum::Other { value } => CredentialSchemaType::Other(value),
        }
    }
}

impl From<CredentialSchemaTypeBindingEnum>
    for one_core::model::credential_schema::CredentialSchemaType
{
    fn from(value: CredentialSchemaTypeBindingEnum) -> Self {
        match value {
            CredentialSchemaTypeBindingEnum::ProcivisOneSchema2024 { .. } => {
                Self::ProcivisOneSchema2024
            }
            CredentialSchemaTypeBindingEnum::FallbackSchema2024 { .. } => Self::FallbackSchema2024,
            CredentialSchemaTypeBindingEnum::Mdoc { .. } => Self::Mdoc,
            CredentialSchemaTypeBindingEnum::Other { value } => Self::Other(value),
        }
    }
}

impl TryFrom<CreateTrustAnchorRequestBindingDTO> for CreateTrustAnchorRequestDTO {
    type Error = ServiceError;
    fn try_from(value: CreateTrustAnchorRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            r#type: value.r#type,
            role: value.role.into(),
            priority: value.priority,
            organisation_id: into_id(&value.organisation_id)?,
        })
    }
}

impl TryFrom<ListTrustAnchorsFiltersBindings> for ListTrustAnchorsQueryDTO {
    type Error = BindingError;

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

        let role = value
            .role
            .map(|role| TrustAnchorFilterValue::Role(role.into()));

        let type_ = value.r#type.map(|type_| {
            TrustAnchorFilterValue::Type(StringMatch {
                r#match: get_string_match_type(ExactTrustAnchorFilterColumnBindings::Type),
                value: type_,
            })
        });

        let organisation_id =
            TrustAnchorFilterValue::OrganisationId(into_id(&value.organisation_id)?).condition();

        let filtering = organisation_id & name & role & type_;

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

impl TryFrom<ListProofSchemasFiltersBindingDTO> for GetListQueryParams<SortableProofSchemaColumn> {
    type Error = BindingError;

    fn try_from(value: ListProofSchemasFiltersBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            name: value.name,
            organisation_id: into_id(&value.organisation_id)?,
            exact: convert_inner_of_inner(value.exact),
            ids: value
                .ids
                .map(|ids| ids.into_iter().map(|id| into_id(&id)).collect())
                .transpose()?,
        })
    }
}

impl TryFrom<ProofListQueryBindingDTO> for GetProofQueryDTO {
    type Error = BindingError;

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
            .map(|proof_states| ProofFilterValue::ProofStates(convert_inner(proof_states)));

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

        let filtering = organisation_id & name & proof_states & proof_schema_ids & proof_ids;

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
    type Error = BindingError;

    fn try_from(value: ImportProofSchemaClaimSchemaBindingDTO) -> Result<Self, Self::Error> {
        let claims = value.claims.unwrap_or_default();
        Ok(Self {
            id: into_id(&value.id)?,
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

pub fn optional_time(value: Option<OffsetDateTime>) -> Option<String> {
    value.as_ref().map(TimestampFormat::format_timestamp)
}

pub fn optional_did_string(value: Option<DidListItemResponseDTO>) -> Option<String> {
    value.map(|inner| inner.id.to_string())
}
