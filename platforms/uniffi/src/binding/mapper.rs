use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::proof_schema::GetProofSchemaQuery;
use one_core::model::trust_entity::TrustEntityType;
use one_core::provider::bluetooth_low_energy::low_level::dto::DeviceInfo;
use one_core::service::credential::dto::{
    CredentialDetailResponseDTO, CredentialListItemResponseDTO, CredentialSchemaType,
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
    DetailCredentialSchemaResponseDTO, MdocMsoValidityResponseDTO,
};
use one_core::service::credential_schema::dto::{
    CredentialSchemaListItemResponseDTO, ImportCredentialSchemaClaimSchemaDTO,
};
use one_core::service::did::dto::{
    CreateDidRequestDTO, CreateDidRequestKeysDTO, DidListItemResponseDTO,
};
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
use one_core::service::ssi_holder::dto::HandleInvitationResultDTO;
use one_core::service::trust_anchor::dto::{ListTrustAnchorsQueryDTO, TrustAnchorFilterValue};
use one_core::service::trust_entity::dto::{
    ListTrustEntitiesQueryDTO, TrustEntityFilterValue, TrustListLogo,
};
use one_dto_mapper::{convert_inner, try_convert_inner};
use serde_json::json;
use shared_types::{KeyId, TrustEntityKey};
use time::OffsetDateTime;

use super::ble::DeviceInfoBindingDTO;
use crate::binding::credential::{
    ClaimBindingDTO, ClaimValueBindingDTO, CredentialDetailBindingDTO,
    CredentialListItemBindingDTO, MdocMsoValidityResponseBindingDTO,
};
use crate::binding::credential_schema::{
    CredentialSchemaBindingDTO, CredentialSchemaTypeBindingEnum,
    ImportCredentialSchemaClaimSchemaBindingDTO,
};
use crate::binding::did::{DidRequestBindingDTO, DidRequestKeysBindingDTO};
use crate::binding::history::{
    HistoryErrorMetadataBindingDTO, HistoryListItemBindingDTO, HistoryMetadataBinding,
};
use crate::binding::identifier::CreateIdentifierDidRequestBindingDTO;
use crate::binding::interaction::HandleInvitationResponseBindingEnum;
use crate::binding::key::KeyRequestBindingDTO;
use crate::binding::organisation::{
    CreateOrganisationRequestBindingDTO, UpsertOrganisationRequestBindingDTO,
};
use crate::binding::proof::{
    ProofListQueryBindingDTO, ProofListQueryExactColumnBindingEnum, ProofResponseBindingDTO,
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
use crate::utils::{TimestampFormat, into_id, into_timestamp};

impl From<CredentialDetailResponseDTO> for CredentialDetailBindingDTO {
    fn from(value: CredentialDetailResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer_did: value.issuer_did.map(Into::into),
            issuer: value.issuer.map(Into::into),
            holder_did: value.holder_did.map(Into::into),
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
            issuance_date: value.issuance_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer_did: optional_did_id_string(value.issuer_did),
            issuer: optional_identifier_id_string(value.issuer),
            state: value.state.into(),
            schema: value.schema.into(),
            role: value.role.into(),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
            protocol: value.protocol,
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
            verifier_did: value.verifier_did.map(Into::into),
            verifier: value.verifier.map(Into::into),
            holder_did: value.holder_did.map(Into::into),
            holder: value.holder.map(Into::into),
            protocol: value.protocol,
            transport: value.transport,
            redirect_uri: value.redirect_uri,
            proof_inputs: convert_inner(value.proof_inputs),
            retain_until_date: value.retain_until_date.map(|date| date.format_timestamp()),
            requested_date: value.requested_date.map(|date| date.format_timestamp()),
            completed_date: value.completed_date.map(|date| date.format_timestamp()),
            claims_removed_at: value.claims_removed_at.map(|date| date.format_timestamp()),
            role: value.role.into(),
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

impl From<HandleInvitationResultDTO> for HandleInvitationResponseBindingEnum {
    fn from(value: HandleInvitationResultDTO) -> Self {
        match value {
            HandleInvitationResultDTO::Credential {
                credential_ids,
                interaction_id,
                tx_code,
            } => Self::CredentialIssuance {
                interaction_id: interaction_id.to_string(),
                credential_ids: credential_ids.iter().map(|item| item.to_string()).collect(),
                tx_code: convert_inner(tx_code),
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
            CredentialSchemaType::SdJwtVc => Self::SdJwtVc {},
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
            CredentialSchemaTypeBindingEnum::SdJwtVc {} => CredentialSchemaType::SdJwtVc,
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
            CredentialSchemaTypeBindingEnum::SdJwtVc {} => Self::SdJwtVc,
            CredentialSchemaTypeBindingEnum::Mdoc { .. } => Self::Mdoc,
            CredentialSchemaTypeBindingEnum::Other { value } => Self::Other(value),
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

        let filtering =
            ListFilterCondition::<TrustAnchorFilterValue>::from(name) & is_publisher & r#type;

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
            .r#type
            .map(|v| v.into_iter().map(TrustEntityType::from).collect())
            .map(TrustEntityFilterValue::Type);

        let entity_key = value
            .entity_key
            .map(|k| TrustEntityFilterValue::EntityKey(TrustEntityKey::from(k)));

        let filtering = ListFilterCondition::<TrustEntityFilterValue>::from(name)
            & role
            & trust_anchor
            & organisation_id
            & types
            & entity_key;

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

        let filtering = organisation_id & name & proof_schema_ids;

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
            .map(|proof_states| ProofFilterValue::ProofStates(convert_inner(proof_states)));

        let proof_roles = value
            .proof_roles
            .map(|proof_roles| ProofFilterValue::ProofRoles(convert_inner(proof_roles)));

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

        let filtering =
            organisation_id & name & proof_states & proof_roles & proof_schema_ids & proof_ids;

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

pub fn optional_time(value: Option<OffsetDateTime>) -> Option<String> {
    value.as_ref().map(TimestampFormat::format_timestamp)
}

pub fn optional_did_id_string(value: Option<DidListItemResponseDTO>) -> Option<String> {
    value.map(|inner| inner.id.to_string())
}

pub fn optional_identifier_id_string(
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
        Ok(Self {
            id: into_id(&value.id)?,
            name: value.name,
            deactivate: value.deactivate,
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
