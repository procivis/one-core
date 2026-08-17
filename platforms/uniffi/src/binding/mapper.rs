use std::collections::HashMap;

use one_core::model::credential::{CredentialListIncludeEntityTypeEnum, SortableCredentialColumn};
use one_core::model::credential_schema::SortableCredentialSchemaColumn;
use one_core::model::did::SortableDidColumn;
use one_core::model::history::SortableHistoryColumn;
use one_core::model::identifier::SortableIdentifierColumn;
use one_core::model::proof::SortableProofColumn;
use one_core::model::proof_schema::SortableProofSchemaColumn;
use one_core::proto::bluetooth_low_energy::low_level::dto::DeviceInfo;
use one_core::provider::verification_protocol::dto::{
    ApplicableCredential, ApplicableCredentialOrFailureHintEnum,
};
use one_core::service::common_dto::{ListQueryDTO, TrustInformationDetailResponseEnum};
use one_core::service::credential::dto::{
    CredentialDetailResponseDTO, CredentialFilterParamsDTO, CredentialListItemResponseDTO,
    DetailCredentialClaimValueResponseDTO, DetailCredentialSchemaResponseDTO,
    MdocMsoValidityResponseDTO,
};
use one_core::service::credential_schema::dto::{
    CredentialSchemaListIncludeEntityTypeEnum, CredentialSchemaListItemResponseDTO,
    CredentialSchemaV2FilterParamsDTO, DisclosurePolicyCreateRequest,
    ImportCredentialSchemaClaimSchemaDTO,
};
use one_core::service::did::dto::{
    CreateDidRequestDTO, CreateDidRequestKeysDTO, DidFilterParamsDTO,
};
use one_core::service::error::ServiceError;
use one_core::service::history::dto::{
    HistoryFilterParamsDTO, HistoryMetadataResponse, HistoryResponseDTO,
};
use one_core::service::identifier::dto::{
    CreateIdentifierDidRequestDTO, GetIdentifierListItemResponseDTO, IdentifierFilterParamsDTO,
};
use one_core::service::key::dto::KeyRequestDTO;
use one_core::service::organisation::dto::{
    CreateOrganisationRequestDTO, TrustCollectionInfoDTO, UpsertOrganisationConfigurationDTO,
    UpsertOrganisationRequestDTO,
};
use one_core::service::proof::dto::{
    CreateProofRequestDTO, CreateProofRequestTransactionDataDTO, ProofClaimValueDTO,
    ProofDetailResponseDTO, ProofFilterParamsDTO, TransactionDataResponseDTO,
};
use one_core::service::proof_schema::dto::{
    ImportProofSchemaClaimSchemaDTO, ProofSchemaFilterParamsDTO,
};
use one_core::service::ssi_holder::dto::{
    HandleInvitationRequestDTO, HandleInvitationResultDTO, InitiateIssuanceRequestDTO,
    PresentationSubmitV2CredentialRequestDTO,
};
use one_dto_mapper::{convert_inner, convert_inner_of_inner, try_convert_inner};
use serde_json::json;
use shared_types::KeyId;
use shared_types::i18n::I18nString;
use standardized_types::etsi_119_472::disclosure_policy::DisclosurePolicy;
use time::OffsetDateTime;
use url::Url;

use super::ble::DeviceInfoBindingDTO;
use super::credential::{
    ClaimBindingDTO, ClaimValueBindingDTO, CredentialDetailBindingDTO,
    CredentialListItemBindingDTO, CredentialListQueryBindingDTO, CredentialSchemaBindingDTO,
    MdocMsoValidityResponseBindingDTO,
};
use super::credential_schema::{
    CredentialSchemaListQueryBindingDTO, DisclosurePolicyBindingDTO,
    DisclosurePolicyCreateRequestBindingDTO, DisclosurePolicyOptionBindingDTO,
    ImportCredentialSchemaV2ClaimSchemaBindingDTO,
};
use super::did::{DidListQueryBindingDTO, DidRequestBindingDTO, DidRequestKeysBindingDTO};
use super::history::{
    HistoryErrorMetadataBindingDTO, HistoryListItemBindingDTO, HistoryListQueryBindingDTO,
    HistoryMetadataBinding, MultiLangStringBindingDTO,
};
use super::identifier::{CreateIdentifierDidRequestBindingDTO, IdentifierListQueryBindingDTO};
use super::interaction::{
    HandleInvitationRequestBindingDTO, HandleInvitationResponseBindingEnum,
    InitiateIssuanceRequestBindingDTO,
};
use super::key::KeyRequestBindingDTO;
use super::organisation::{
    CreateOrganisationRequestBindingDTO, TrustCollectionInfoBindingDTO,
    UpsertOrganisationConfigurationBindingDTO, UpsertOrganisationRequestBindingDTO,
};
use super::proof::{
    ApplicableCredentialOrFailureHintBindingEnum, CreateProofRequestBindingDTO,
    PresentationDefinitionV2ClaimBindingDTO, PresentationDefinitionV2ClaimValueBindingDTO,
    PresentationDefinitionV2CredentialDetailBindingDTO,
    PresentationSubmitV2CredentialRequestBindingDTO, ProofListQueryBindingDTO,
    ProofRequestClaimValueBindingDTO, ProofRequestTransactionDataBindingDTO,
    ProofResponseBindingDTO, TransactionDataResponseBindingDTO,
};
use super::proof_schema::{
    ImportProofSchemaClaimSchemaBindingDTO, ListProofSchemasFiltersBindingDTO,
};
use super::trust_information::TrustInformationDetailResponseBindingEnum;
use crate::error::ErrorResponseBindingDTO;
use crate::utils::{
    TimestampFormat, into_id, into_id_opt, into_id_opt_vec, into_id_vec, into_timestamp,
    into_timestamp_opt,
};

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
            expires_at: value.expires_at.map(|inner| inner.format_timestamp()),
            consumed_at: value.consumed_at.map(|inner| inner.format_timestamp()),
            issuer: value.issuer.map(Into::into),
            holder: value.holder.map(Into::into),
            state: value.state.into(),
            r#type: value.r#type.into(),
            schema: value.schema.into(),
            claims: convert_inner(value.claims),
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            interaction_id: value
                .interaction_id
                .map(|interaction_id| interaction_id.to_string()),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
            mdoc_mso_validity: value.mdoc_mso_validity.map(|inner| inner.into()),
            protocol: value.protocol,
            profile: value.profile,
            trust_information: convert_inner(value.trust_information),
            remaining_batch_item_count: value.remaining_batch_item_count,
            parent_id: value.parent_id.map(|parent_id| parent_id.to_string()),
            ecosystem: value.ecosystem.map(|ecosystem| ecosystem.to_string()),
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
            expires_at: value.expires_at.map(|inner| inner.format_timestamp()),
            consumed_at: value.consumed_at.map(|inner| inner.format_timestamp()),
            issuer: optional_identifier_id_string(value.issuer),
            state: value.state.into(),
            schema: value.schema.into(),
            role: value.role.into(),
            r#type: value.r#type.into(),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
            protocol: value.protocol,
            profile: value.profile,
            parent_id: value.parent_id.map(|parent_id| parent_id.to_string()),
            redirect_uri: value.redirect_uri,
            ecosystem: value.ecosystem.map(|ecosystem| ecosystem.to_string()),
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
            ecosystem: convert_inner(value.ecosystem),
            trust_information: convert_inner(value.trust_information),
            transaction_data: if value.transaction_data.is_empty() {
                None
            } else {
                Some(convert_inner(value.transaction_data))
            },
        }
    }
}

impl From<TransactionDataResponseDTO> for TransactionDataResponseBindingDTO {
    fn from(value: TransactionDataResponseDTO) -> Self {
        Self {
            r#type: value.r#type.to_string(),
            credential_schema_ids: value
                .credential_schema_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            data: value.data.map(|data| data.to_string()),
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
            format: value.format.to_string(),
            revocation_method: value.revocation_method.map(|v| v.to_string()),
            key_storage_security: convert_inner(value.key_storage_security),
            schema_id: value.schema_id,
            imported_source_url: value.imported_source_url,
            layout_type: convert_inner(value.layout_type),
            layout_properties: convert_inner(value.layout_properties),
            allow_suspension: value.allow_suspension,
            requires_wallet_instance_attestation: value.requires_wallet_instance_attestation,
            translations: Some(value.translations.into()),
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
                key_storage_security_levels,
                key_algorithms,
                protocol,
                requires_wallet_instance_attestation,
                ecosystem,
            } => Self::CredentialIssuance {
                interaction_id: interaction_id.to_string(),
                tx_code: convert_inner(tx_code),
                protocol,
                key_storage_security_levels: convert_inner_of_inner(key_storage_security_levels),
                key_algorithms,
                requires_wallet_instance_attestation,
                ecosystem: convert_inner(ecosystem),
            },
            HandleInvitationResultDTO::AuthorizationCodeFlow {
                interaction_id,
                authorization_code_flow_url,
                protocol,
                ecosystem,
            } => Self::AuthorizationCodeFlow {
                interaction_id: interaction_id.to_string(),
                authorization_code_flow_url,
                protocol,
                ecosystem: convert_inner(ecosystem),
            },
            HandleInvitationResultDTO::ProofRequest {
                interaction_id,
                proof_id,
                protocol,
                ecosystem,
            } => Self::ProofRequest {
                interaction_id: interaction_id.to_string(),
                proof_id: proof_id.to_string(),
                protocol,
                ecosystem: convert_inner(ecosystem),
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
            did_method: request.did_method.into(),
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

fn convert_history_metadata(
    value: Option<HistoryMetadataResponse>,
) -> Option<HistoryMetadataBinding> {
    match value {
        None => None,
        Some(value) => match value {
            HistoryMetadataResponse::UnexportableEntities(value) => {
                Some(HistoryMetadataBinding::UnexportableEntities {
                    value: value.into(),
                })
            }
            HistoryMetadataResponse::ErrorMetadata(value) => {
                Some(HistoryMetadataBinding::ErrorMetadata {
                    value: HistoryErrorMetadataBindingDTO {
                        error_code: Into::<&'static str>::into(value.error_code).to_string(),
                        message: value.message,
                    },
                })
            }
            HistoryMetadataResponse::WalletUnitJWT(value) => {
                Some(HistoryMetadataBinding::WalletUnitJWT(value))
            }
            HistoryMetadataResponse::WalletRelyingParty(value) => {
                Some(HistoryMetadataBinding::WalletRelyingParty {
                    value: value.into(),
                })
            }
            // external metadata only used in REST API
            HistoryMetadataResponse::External(_) => None,
            HistoryMetadataResponse::TrustResolution(value) => {
                Some(HistoryMetadataBinding::TrustResolution {
                    value: value.into(),
                })
            }
        },
    }
}

impl From<standardized_types::etsi_119_602::MultiLangString> for MultiLangStringBindingDTO {
    fn from(value: standardized_types::etsi_119_602::MultiLangString) -> Self {
        Self {
            lang: value.lang,
            value: value.value,
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
            metadata: convert_history_metadata(value.metadata),
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
            format: value.format.to_string(),
            imported_source_url: value.imported_source_url,
            revocation_method: value.revocation_method.map(|v| v.to_string()),
            key_storage_security: convert_inner(value.key_storage_security),
            schema_id: value.schema_id,
            layout_type: convert_inner(value.layout_type),
            layout_properties: convert_inner(value.layout_properties),
            allow_suspension: value.allow_suspension,
            requires_wallet_instance_attestation: value.requires_wallet_instance_attestation,
            translations: convert_inner(value.translations),
        }
    }
}

impl TryFrom<CreateProofRequestBindingDTO> for CreateProofRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CreateProofRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_schema_id: into_id(value.proof_schema_id)?,
            verifier_did_id: into_id_opt(value.verifier_did_id)?,
            verifier_identifier_id: into_id_opt(value.verifier_identifier_id)?,
            protocol: value.protocol,
            redirect_uri: value.redirect_uri,
            verifier_key: into_id_opt(value.verifier_key)?,
            verifier_certificate: into_id_opt(value.verifier_certificate)?,
            iso_mdl_engagement: value.iso_mdl_engagement,
            transport: value.transport,
            profile: value.profile,
            engagement: value.engagement,
            webhook_destination_url: None,
            subscriber_information: None,
            transaction_data: value
                .transaction_data
                .unwrap_or_default()
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            ecosystem: convert_inner(value.ecosystem),
        })
    }
}

impl TryFrom<ProofRequestTransactionDataBindingDTO> for CreateProofRequestTransactionDataDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ProofRequestTransactionDataBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: value.r#type.into(),
            credential_schema_ids: into_id_vec(&value.credential_schema_ids)?,
            data: value
                .data
                .map(|data| serde_json::from_str(&data))
                .transpose()
                .map_err(|err| ServiceError::MappingError(err.to_string()))?,
        })
    }
}

impl TryFrom<ProofListQueryBindingDTO> for ListQueryDTO<SortableProofColumn, ProofFilterParamsDTO> {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ProofListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: ProofFilterParamsDTO {
                name: value.name,
                exact: convert_inner_of_inner(value.exact),
                states: convert_inner_of_inner(value.proof_states),
                roles: convert_inner_of_inner(value.proof_roles),
                ecosystems: convert_inner_of_inner(value.ecosystems),
                ids: into_id_opt_vec(&value.ids)?,
                proof_schema_ids: into_id_opt_vec(&value.proof_schema_ids)?,
                verifier_ids: None,
                profiles: value.profiles,
                organisation_id: into_id(value.organisation_id)?,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
                requested_date_after: into_timestamp_opt(value.requested_date_after)?,
                requested_date_before: into_timestamp_opt(value.requested_date_before)?,
                completed_date_after: into_timestamp_opt(value.completed_date_after)?,
                completed_date_before: into_timestamp_opt(value.completed_date_before)?,
            },
            include: None,
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

impl TryFrom<ImportCredentialSchemaV2ClaimSchemaBindingDTO>
    for ImportCredentialSchemaClaimSchemaDTO
{
    type Error = ServiceError;

    fn try_from(value: ImportCredentialSchemaV2ClaimSchemaBindingDTO) -> Result<Self, Self::Error> {
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
            mappings: value
                .mappings
                .map(|ms| ms.into_iter().map(Into::into).collect()),
            translations: convert_inner(value.translations),
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

pub(crate) fn optional_time(value: Option<OffsetDateTime>) -> Option<String> {
    value.as_ref().map(TimestampFormat::format_timestamp)
}

impl TryFrom<HistoryListQueryBindingDTO>
    for ListQueryDTO<SortableHistoryColumn, HistoryFilterParamsDTO>
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: HistoryListQueryBindingDTO) -> Result<Self, Self::Error> {
        let (search_type, search_query) = match value.search {
            Some(s) => (convert_inner(s.r#type), Some(s.text)),
            None => (None, None),
        };

        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: HistoryFilterParamsDTO {
                organisation_ids: Some(vec![into_id(&value.organisation_id)?]),
                entity_ids: into_id_opt_vec(&value.entity_ids)?,
                entity_types: convert_inner_of_inner(value.entity_types),
                actions: convert_inner_of_inner(value.actions),
                identifier_id: into_id_opt(value.identifier_id)?,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                credential_id: into_id_opt(value.credential_id)?,
                credential_schema_id: into_id_opt(value.credential_schema_id)?,
                proof_id: into_id_opt(value.proof_id)?,
                proof_schema_id: into_id_opt(value.proof_schema_id)?,
                trust_collection_id: into_id_opt(value.trust_collection_id)?,
                users: value.users,
                sources: None,
                search_query,
                search_type,
            },
            include: None,
        })
    }
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
            id: into_id_opt(value.id)?,
            parent_organisation: into_id_opt(value.parent_organisation)?,
        })
    }
}

impl TryFrom<UpsertOrganisationRequestBindingDTO> for UpsertOrganisationRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: UpsertOrganisationRequestBindingDTO) -> Result<Self, Self::Error> {
        let wallet_provider_issuer = value
            .wallet_provider_issuer
            .map(Option::<String>::from)
            .map(into_id_opt)
            .transpose()?;

        let verifier_provider_issuer = value
            .verifier_provider_issuer
            .map(Option::<String>::from)
            .map(into_id_opt)
            .transpose()?;

        let parent_organisation = value
            .parent_organisation
            .map(Option::<String>::from)
            .map(into_id_opt)
            .transpose()?;

        let trust_collections = into_id_opt_vec(&value.trust_collections)?;

        Ok(Self {
            id: into_id(&value.id)?,
            deactivate: value.deactivate,
            wallet_provider: convert_inner(value.wallet_provider),
            wallet_provider_issuer,
            verifier_provider: convert_inner(value.verifier_provider),
            verifier_provider_issuer,
            configuration: convert_inner(value.configuration),
            trust_collections,
            parent_organisation,
        })
    }
}

impl From<UpsertOrganisationConfigurationBindingDTO> for UpsertOrganisationConfigurationDTO {
    fn from(value: UpsertOrganisationConfigurationBindingDTO) -> Self {
        Self {
            selected_ecosystems: convert_inner_of_inner(value.selected_ecosystems),
            enforce_ecosystem_as_issuer: value.enforce_ecosystem_as_issuer,
            enforce_ecosystem_as_holder: value.enforce_ecosystem_as_holder,
            enforce_ecosystem_as_verifier: value.enforce_ecosystem_as_verifier,
        }
    }
}

impl From<TrustCollectionInfoDTO> for TrustCollectionInfoBindingDTO {
    fn from(value: TrustCollectionInfoDTO) -> Self {
        Self {
            selected: value.selected,
            id: value.collection.id.to_string(),
            name: value.collection.name,
            logo: value.collection.logo,
            display_name: convert_inner(value.collection.display_name),
            description: convert_inner(value.collection.description),
            default_selected: value.collection.default_selected,
        }
    }
}

impl TryFrom<CreateIdentifierDidRequestBindingDTO> for CreateIdentifierDidRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CreateIdentifierDidRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            method: value.method.into(),
            keys: value.keys.try_into()?,
            params: Some(json!(value.params)),
        })
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
            ecosystem: convert_inner(request.ecosystem),
        })
    }
}

impl From<ApplicableCredential> for PresentationDefinitionV2CredentialDetailBindingDTO {
    fn from(value: ApplicableCredential) -> Self {
        Self {
            id: value.credential.id.to_string(),
            created_date: value.credential.created_date.format_timestamp(),
            issuance_date: optional_time(value.credential.issuance_date),
            revocation_date: optional_time(value.credential.revocation_date),
            state: value.credential.state.into(),
            last_modified: value.credential.last_modified.format_timestamp(),
            schema: value.credential.schema.into(),
            issuer: convert_inner(value.credential.issuer),
            issuer_certificate: convert_inner(value.credential.issuer_certificate),
            claims: convert_inner(value.credential.claims),
            redirect_uri: value.credential.redirect_uri,
            role: value.credential.role.into(),
            suspend_end_date: optional_time(value.credential.suspend_end_date),
            mdoc_mso_validity: convert_inner(value.credential.mdoc_mso_validity),
            holder: convert_inner(value.credential.holder),
            protocol: value.credential.protocol,
            profile: value.credential.profile,
            embedded_disclosure_policy_violation: convert_inner(
                value.embedded_disclosure_policy_violation,
            ),
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
                purpose,
            } => Self::ApplicableCredentials {
                applicable_credentials: convert_inner(applicable_credentials),
                purpose: purpose.map(|p| p.0),
            },
            ApplicableCredentialOrFailureHintEnum::FailureHint { failure_hint } => {
                Self::FailureHint {
                    failure_hint: (*failure_hint).into(),
                }
            }
        }
    }
}

impl TryFrom<IdentifierListQueryBindingDTO>
    for ListQueryDTO<SortableIdentifierColumn, IdentifierFilterParamsDTO>
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: IdentifierListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: IdentifierFilterParamsDTO {
                ids: into_id_opt_vec(&value.ids)?,
                name: value.name,
                types: convert_inner_of_inner(value.types),
                states: convert_inner_of_inner(value.states),
                did_methods: convert_inner_of_inner(value.did_methods),
                is_remote: value.is_remote,
                key_algorithms: value.key_algorithms,
                key_roles: convert_inner_of_inner(value.key_roles),
                key_storages: value.key_storages,
                certificate_roles: convert_inner_of_inner(value.certificate_roles),
                certificate_roles_match_mode: convert_inner(value.certificate_roles_match_mode)
                    .unwrap_or_default(),
                trust_issuance_schema_id: into_id_opt(value.trust_issuance_schema_id)?,
                trust_verification_schema_id: into_id_opt(value.trust_verification_schema_id)?,
                ecosystem: convert_inner(value.ecosystem),
                ecosystem_roles: convert_inner_of_inner(value.ecosystem_roles),
                ecosystem_credential_schema_id: into_id_opt(value.ecosystem_proof_schema_id)?,
                ecosystem_proof_schema_id: into_id_opt(value.ecosystem_credential_schema_id)?,
                exact: convert_inner_of_inner(value.exact),
                organisation_id: into_id(&value.organisation_id)?,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
            },
            include: None,
        })
    }
}

impl TryFrom<DidListQueryBindingDTO> for ListQueryDTO<SortableDidColumn, DidFilterParamsDTO> {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: DidListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: DidFilterParamsDTO {
                name: value.name,
                did: value.did,
                r#type: convert_inner(value.r#type),
                exact: convert_inner_of_inner(value.exact),
                deactivated: value.deactivated,
                key_algorithms: value.key_algorithms,
                key_roles: convert_inner_of_inner(value.key_roles),
                key_storages: value.key_storages,
                key_ids: into_id_opt_vec(&value.key_ids)?,
                did_methods: convert_inner_of_inner(value.did_methods),
                organisation_id: into_id(&value.organisation_id)?,
            },
            include: None,
        })
    }
}

impl TryFrom<CredentialListQueryBindingDTO>
    for ListQueryDTO<
        SortableCredentialColumn,
        CredentialFilterParamsDTO,
        CredentialListIncludeEntityTypeEnum,
    >
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CredentialListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: CredentialFilterParamsDTO {
                organisation_id: into_id(&value.organisation_id)?,
                name: value.name,
                search_text: value.search_text,
                search_type: convert_inner_of_inner(value.search_type),
                exact: convert_inner_of_inner(value.exact),
                roles: convert_inner_of_inner(value.roles),
                ids: into_id_opt_vec(&value.ids)?,
                parent_id: into_id_opt(value.parent_id)?,
                credential_schema_ids: into_id_opt_vec(&value.credential_schema_ids)?,
                ecosystems: convert_inner_of_inner(value.ecosystems),
                issuers: None,
                states: convert_inner_of_inner(value.states),
                types: convert_inner_of_inner(value.types),
                profiles: value.profiles,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
                issuance_date_after: into_timestamp_opt(value.issuance_date_after)?,
                issuance_date_before: into_timestamp_opt(value.issuance_date_before)?,
                revocation_date_after: into_timestamp_opt(value.revocation_date_after)?,
                revocation_date_before: into_timestamp_opt(value.revocation_date_before)?,
                expires_at_after: None,
                expires_at_before: None,
            },
            include: convert_inner_of_inner(value.include),
        })
    }
}

impl TryFrom<ListProofSchemasFiltersBindingDTO>
    for ListQueryDTO<SortableProofSchemaColumn, ProofSchemaFilterParamsDTO>
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ListProofSchemasFiltersBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: ProofSchemaFilterParamsDTO {
                name: value.name,
                exact: convert_inner_of_inner(value.exact),
                organisation_id: into_id(value.organisation_id)?,
                ids: into_id_opt_vec(&value.ids)?,
                formats: value.formats,
                ecosystems: convert_inner_of_inner(value.ecosystems),
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
            },
            include: None,
        })
    }
}

impl TryFrom<CredentialSchemaListQueryBindingDTO>
    for ListQueryDTO<
        SortableCredentialSchemaColumn,
        CredentialSchemaV2FilterParamsDTO,
        CredentialSchemaListIncludeEntityTypeEnum,
    >
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CredentialSchemaListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: CredentialSchemaV2FilterParamsDTO {
                name: value.name,
                exact: convert_inner_of_inner(value.exact),
                organisation_id: into_id(value.organisation_id)?,
                schema_ids: value.schema_ids,
                formats: value.formats,
                ecosystems: convert_inner_of_inner(value.ecosystems),
                requires_wallet_instance_attestation: None,
                key_storage_security: None,
                credential_schema_ids: into_id_opt_vec(&value.ids)?,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
                uses_batch_issuance: value.uses_batch_issuance,
                is_multiformat_schema: value.is_multiformat_schema,
                expiration_greater_than: None,
                expiration_less_than: None,
            },
            include: value
                .include
                .map(|incl| incl.into_iter().map(Into::into).collect()),
        })
    }
}

impl TryFrom<DisclosurePolicyBindingDTO> for DisclosurePolicy {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: DisclosurePolicyBindingDTO) -> Result<Self, Self::Error> {
        use standardized_types::etsi_119_472::disclosure_policy::*;

        let policy = match value.policy.as_str() {
            "none" => PolicyType::None,
            "allowList" => PolicyType::AllowList {
                options: AllowListOptions {
                    values: convert_inner(
                        value
                            .options
                            .ok_or(ServiceError::MappingError("Missing options".to_string()))?
                            .values,
                    ),
                },
            },
            "rootOfTrust" => PolicyType::RootOfTrust {
                options: RootOfTrustOptions {
                    values: try_convert_inner(
                        value
                            .options
                            .ok_or(ServiceError::MappingError("Missing options".to_string()))?
                            .values,
                    )?,
                },
            },
            _ => return Err(ServiceError::MappingError("Invalid policy".to_string()).into()),
        };

        Ok(Self {
            id: value.id,
            policy,
            description: value.description,
            url: value.url,
        })
    }
}

impl TryFrom<DisclosurePolicyCreateRequestBindingDTO> for DisclosurePolicyCreateRequest {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: DisclosurePolicyCreateRequestBindingDTO) -> Result<Self, Self::Error> {
        use standardized_types::etsi_119_472::disclosure_policy::*;

        let policy = match value.policy.as_str() {
            "none" => PolicyType::None,
            "allowList" => PolicyType::AllowList {
                options: AllowListOptions {
                    values: convert_inner(
                        value
                            .options
                            .ok_or(ServiceError::MappingError("Missing options".to_string()))?
                            .values,
                    ),
                },
            },
            "rootOfTrust" => PolicyType::RootOfTrust {
                options: RootOfTrustOptions {
                    values: try_convert_inner(
                        value
                            .options
                            .ok_or(ServiceError::MappingError("Missing options".to_string()))?
                            .values,
                    )?,
                },
            },
            _ => return Err(ServiceError::MappingError("Invalid policy".to_string()).into()),
        };

        Ok(Self {
            policy,
            description: value.description,
            url: value.url,
        })
    }
}

impl From<DisclosurePolicyOptionBindingDTO>
    for standardized_types::etsi_119_472::disclosure_policy::AllowListOption
{
    fn from(value: DisclosurePolicyOptionBindingDTO) -> Self {
        Self {
            dn: value.dn,
            entitlement: value.entitlement,
        }
    }
}

impl TryFrom<DisclosurePolicyOptionBindingDTO>
    for standardized_types::etsi_119_472::disclosure_policy::RootOfTrustOption
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: DisclosurePolicyOptionBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            dn: value
                .dn
                .ok_or(ServiceError::MappingError("Missing dn".to_string()))?,
            serial: value
                .serial
                .ok_or(ServiceError::MappingError("Missing serial".to_string()))?,
        })
    }
}

pub(crate) fn to_i18n_string(value: HashMap<String, String>) -> I18nString {
    I18nString(value)
}
pub(crate) fn from_i18n_string(value: I18nString) -> HashMap<String, String> {
    value.0
}
pub(crate) fn to_i18n_string_opt(value: Option<HashMap<String, String>>) -> Option<I18nString> {
    value.map(to_i18n_string)
}
pub(crate) fn from_i18n_string_opt(value: Option<I18nString>) -> Option<HashMap<String, String>> {
    value.map(from_i18n_string)
}

impl TryFrom<PresentationSubmitV2CredentialRequestBindingDTO>
    for PresentationSubmitV2CredentialRequestDTO
{
    type Error = ServiceError;
    fn try_from(
        value: PresentationSubmitV2CredentialRequestBindingDTO,
    ) -> Result<Self, Self::Error> {
        let PresentationSubmitV2CredentialRequestBindingDTO {
            credential_id,
            user_selections,
            transaction_data_ids,
            ..
        } = value;
        Ok(Self {
            credential_id: into_id(&credential_id)?,
            user_selections: user_selections.unwrap_or_default(),
            transaction_data_ids: into_id_vec(&transaction_data_ids.unwrap_or_default())?,
        })
    }
}

impl TryFrom<HandleInvitationRequestBindingDTO> for HandleInvitationRequestDTO {
    type Error = ServiceError;
    fn try_from(value: HandleInvitationRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            url: Url::parse(&value.url)
                .map_err(|e| ServiceError::ValidationError(e.to_string()))?,
            organisation_id: into_id(value.organisation_id)?,
            transport: value.transport,
            redirect_uri: value.redirect_uri,
            ecosystem: convert_inner(value.ecosystem),
        })
    }
}

impl From<TrustInformationDetailResponseEnum> for TrustInformationDetailResponseBindingEnum {
    fn from(value: TrustInformationDetailResponseEnum) -> Self {
        match value {
            TrustInformationDetailResponseEnum::Eudi(data) => Self::Eudi(data.into()),
        }
    }
}
