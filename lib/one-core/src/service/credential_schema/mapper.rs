use dto_mapper::convert_inner;
use shared_types::{ClaimSchemaId, CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesRequestDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaFilterValue,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLogoPropertiesRequestDTO,
    ImportCredentialSchemaRequestSchemaDTO,
};
use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::list_filter::{ListFilterValue, StringMatch, StringMatchType};
use crate::model::list_query::ListPagination;
use crate::model::organisation::Organisation;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, GetCredentialSchemaQueryDTO,
};
use crate::service::error::{BusinessLogicError, ServiceError};

pub(crate) async fn schema_detail_from_model(
    value: CredentialSchema,
) -> Result<CredentialSchemaDetailResponseDTO, ServiceError> {
    let claim_schemas = renest_claim_schemas(convert_inner(value.claim_schemas.get().await?))?;

    Ok(CredentialSchemaDetailResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        format: value.format,
        revocation_method: value.revocation_method,
        organisation_id: *value.organisation.id(),
        claims: claim_schemas,
        wallet_storage_type: value.wallet_storage_type,
        schema_id: value.schema_id,
        schema_type: value.schema_type.into(),
        layout_type: Some(value.layout_type),
        layout_properties: value.layout_properties.map(|item| item.into()),
    })
}

impl From<CredentialSchemaClaim> for CredentialClaimSchemaDTO {
    fn from(value: CredentialSchemaClaim) -> Self {
        Self {
            id: value.schema.id,
            created_date: value.schema.created_date,
            last_modified: value.schema.last_modified,
            key: value.schema.key,
            datatype: value.schema.data_type,
            required: value.required,
            array: value.schema.array,
            claims: vec![],
        }
    }
}

pub(super) fn create_unique_name_check_request(
    name: &str,
    schema_id: Option<String>,
    organisation_id: OrganisationId,
) -> Result<GetCredentialSchemaQueryDTO, ServiceError> {
    Ok(GetCredentialSchemaQueryDTO {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        filtering: Some(
            CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                & (CredentialSchemaFilterValue::Name(StringMatch {
                    r#match: StringMatchType::Equals,
                    value: name.to_owned(),
                })
                .condition()
                    | schema_id.map(|schema_id| {
                        CredentialSchemaFilterValue::SchemaId(StringMatch {
                            r#match: StringMatchType::Equals,
                            value: schema_id,
                        })
                    })),
        ),
        ..Default::default()
    })
}

pub fn from_create_request(
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    core_base_url: &str,
    format_type: &str,
    schema_type: Option<CredentialSchemaType>,
) -> Result<CredentialSchema, ServiceError> {
    from_create_request_with_id(
        Uuid::new_v4().into(),
        request,
        organisation,
        core_base_url,
        format_type,
        schema_type,
    )
}

pub(super) fn from_create_request_with_id(
    id: CredentialSchemaId,
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    core_base_url: &str,
    format_type: &str,
    schema_type: Option<CredentialSchemaType>,
) -> Result<CredentialSchema, ServiceError> {
    if request.claims.is_empty() {
        return Err(ServiceError::ValidationError(
            "Claim schemas cannot be empty".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

    let schema_id = request
        .schema_id
        .unwrap_or(format!("{core_base_url}/ssi/schema/v1/{id}"));
    let schema_type = schema_type.unwrap_or(match format_type {
        "MDOC" => CredentialSchemaType::Mdoc,
        _ => CredentialSchemaType::ProcivisOneSchema2024,
    });

    Ok(CredentialSchema {
        id,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: request.name,
        format: request.format,
        wallet_storage_type: request.wallet_storage_type,
        revocation_method: request.revocation_method,
        claim_schemas: claim_schemas
            .into_iter()
            .map(|claim_schema| {
                from_jwt_request_claim_schema(
                    now,
                    Uuid::new_v4().into(),
                    claim_schema.key,
                    claim_schema.datatype,
                    claim_schema.required,
                    claim_schema.array,
                )
            })
            .collect(),
        organisation: organisation.into(),
        layout_type: request.layout_type,
        layout_properties: request.layout_properties.map(Into::into),
        schema_type,
        schema_id,
    })
}

pub(super) fn schema_create_history_event(schema: CredentialSchema) -> History {
    history_event(schema, HistoryAction::Created)
}

pub(super) fn schema_delete_history_event(schema: CredentialSchema) -> History {
    history_event(schema, HistoryAction::Deleted)
}

pub(super) fn schema_import_history_event(schema: CredentialSchema) -> History {
    history_event(schema, HistoryAction::Imported)
}

pub(super) fn schema_share_history_event(schema: CredentialSchema) -> History {
    history_event(schema, HistoryAction::Shared)
}

fn history_event(schema: CredentialSchema, action: HistoryAction) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: Some(schema.id.into()),
        entity_type: HistoryEntityType::CredentialSchema,
        metadata: None,
        organisation: Some(Organisation {
            id: *schema.organisation.id(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
    }
}

fn from_jwt_request_claim_schema(
    now: OffsetDateTime,
    id: ClaimSchemaId,
    key: String,
    datatype: String,
    required: bool,
    array: Option<bool>,
) -> CredentialSchemaClaim {
    CredentialSchemaClaim {
        schema: ClaimSchema {
            id,
            key,
            data_type: datatype,
            created_date: now,
            last_modified: now,
            array: array.unwrap_or(false),
        },
        required,
    }
}

pub(super) fn renest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaDTO>,
) -> Result<Vec<CredentialClaimSchemaDTO>, ServiceError> {
    let mut result = vec![];

    // Iterate over all and copy all unnested claims to new vec
    for claim_schema in claim_schemas.iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_none() {
            result.push(claim_schema.to_owned());
        }
    }

    // Find all nested claims and move them to related entries in result vec
    for mut claim_schema in claim_schemas.into_iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_some() {
            let matching_entry = result
                .iter_mut()
                .find(|result_schema| {
                    claim_schema
                        .key
                        .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", result_schema.key))
                })
                .ok_or(ServiceError::BusinessLogic(
                    BusinessLogicError::MissingParentClaimSchema {
                        claim_schema_id: claim_schema.id,
                    },
                ))?;
            claim_schema.key = remove_first_nesting_layer(&claim_schema.key);

            matching_entry.claims.push(claim_schema);
        }
    }

    // Repeat for all claims to nest all subclaims
    result
        .into_iter()
        .map(|mut claim_schema| {
            claim_schema.claims = renest_claim_schemas(claim_schema.claims)?;
            Ok(claim_schema)
        })
        .collect::<Result<Vec<CredentialClaimSchemaDTO>, _>>()
}

pub(super) fn unnest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    unnest_claim_schemas_inner(claim_schemas, "".to_string())
}

fn unnest_claim_schemas_inner(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
    prefix: String,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    let mut result = vec![];

    for claim_schema in claim_schemas {
        let key = format!("{prefix}{}", claim_schema.key);

        let nested =
            unnest_claim_schemas_inner(claim_schema.claims, format!("{key}{NESTED_CLAIM_MARKER}"));

        result.push(CredentialClaimSchemaRequestDTO {
            key,
            claims: vec![],
            ..claim_schema
        });

        result.extend(nested);
    }

    result
}

impl From<ImportCredentialSchemaRequestSchemaDTO> for CreateCredentialSchemaRequestDTO {
    fn from(value: ImportCredentialSchemaRequestSchemaDTO) -> Self {
        CreateCredentialSchemaRequestDTO {
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: value.organisation_id.into(),
            claims: value.claims.into_iter().map(Into::into).collect(),
            wallet_storage_type: convert_inner(value.wallet_storage_type),
            layout_type: value.layout_type.unwrap_or(LayoutType::Card),
            layout_properties: convert_inner(value.layout_properties),
            schema_id: Some(value.schema_id),
        }
    }
}

impl From<CredentialSchemaBackgroundPropertiesRequestDTO>
    for one_providers::common_models::credential_schema::OpenBackgroundProperties
{
    fn from(value: CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: convert_inner(value.color),
            image: convert_inner(value.image),
        }
    }
}

impl From<CredentialSchemaLogoPropertiesRequestDTO>
    for one_providers::common_models::credential_schema::OpenLogoProperties
{
    fn from(value: CredentialSchemaLogoPropertiesRequestDTO) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaCodePropertiesRequestDTO>
    for one_providers::common_models::credential_schema::OpenCodeProperties
{
    fn from(value: CredentialSchemaCodePropertiesRequestDTO) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<CredentialSchemaCodeTypeEnum>
    for one_providers::common_models::credential_schema::OpenCodeTypeEnum
{
    fn from(value: CredentialSchemaCodeTypeEnum) -> Self {
        match value {
            CredentialSchemaCodeTypeEnum::Barcode => Self::Barcode,
            CredentialSchemaCodeTypeEnum::Mrz => Self::Mrz,
            CredentialSchemaCodeTypeEnum::QrCode => Self::QrCode,
        }
    }
}

impl From<CredentialSchemaLayoutPropertiesRequestDTO>
    for one_providers::common_models::credential_schema::OpenLayoutProperties
{
    fn from(value: CredentialSchemaLayoutPropertiesRequestDTO) -> Self {
        Self {
            background: convert_inner(value.background),
            logo: convert_inner(value.logo),
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code: convert_inner(value.code),
        }
    }
}

impl From<one_providers::exchange_protocol::openid4vc::model::CredentialSchemaBackgroundPropertiesRequestDTO>
    for CredentialSchemaBackgroundPropertiesRequestDTO
{
    fn from(value: one_providers::exchange_protocol::openid4vc::model::CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: value.color,
            image: value.image,
        }
    }
}

impl From<one_providers::exchange_protocol::openid4vc::model::CredentialSchemaLogoPropertiesRequestDTO>
    for CredentialSchemaLogoPropertiesRequestDTO
{
    fn from(value: one_providers::exchange_protocol::openid4vc::model::CredentialSchemaLogoPropertiesRequestDTO) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<one_providers::exchange_protocol::openid4vc::model::CredentialSchemaCodePropertiesRequestDTO>
    for CredentialSchemaCodePropertiesRequestDTO
{
    fn from(value: one_providers::exchange_protocol::openid4vc::model::CredentialSchemaCodePropertiesRequestDTO) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<one_providers::exchange_protocol::openid4vc::model::CredentialSchemaCodeTypeEnum>
    for CredentialSchemaCodeTypeEnum
{
    fn from(
        value: one_providers::exchange_protocol::openid4vc::model::CredentialSchemaCodeTypeEnum,
    ) -> Self {
        match value {
            one_providers::exchange_protocol::openid4vc::model::CredentialSchemaCodeTypeEnum::Barcode => Self::Barcode,
            one_providers::exchange_protocol::openid4vc::model::CredentialSchemaCodeTypeEnum::Mrz => Self::Mrz,
            one_providers::exchange_protocol::openid4vc::model::CredentialSchemaCodeTypeEnum::QrCode => Self::QrCode,
        }
    }
}

impl From<one_providers::exchange_protocol::openid4vc::model::CredentialSchemaLayoutPropertiesRequestDTO>
    for CredentialSchemaLayoutPropertiesRequestDTO
{
    fn from(value: one_providers::exchange_protocol::openid4vc::model::CredentialSchemaLayoutPropertiesRequestDTO) -> Self {
        Self {
            background: convert_inner(value.background),
            logo: convert_inner(value.logo),
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code: convert_inner(value.code),
        }
    }
}
