use one_dto_mapper::convert_inner;
use shared_types::{ClaimSchemaId, CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesDTO,
    CredentialSchemaFilterValue, CredentialSchemaLogoPropertiesRequestDTO,
};
use crate::common_mapper::{NESTED_CLAIM_MARKER, remove_first_nesting_layer};
use crate::config::core_config::FormatType;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType,
};
use crate::model::list_filter::{ListFilterValue, StringMatch, StringMatchType};
use crate::model::list_query::ListPagination;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::MetadataClaimSchema;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, GetCredentialSchemaQueryDTO,
};
use crate::service::error::{BusinessLogicError, ServiceError};

impl TryFrom<CredentialSchema> for CredentialSchemaDetailResponseDTO {
    type Error = ServiceError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let claim_schemas = value
            .claim_schemas
            .unwrap_or_default()
            .into_iter()
            .filter(|schema| !schema.schema.metadata)
            .collect::<Vec<_>>();
        let claim_schemas = renest_claim_schemas(convert_inner(claim_schemas))?;

        let organisation_id = match value.organisation {
            None => Err(ServiceError::MappingError(
                "Organisation has not been fetched".to_string(),
            )),
            Some(value) => Ok(value.id),
        }?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            imported_source_url: value.imported_source_url,
            revocation_method: value.revocation_method,
            external_schema: value.external_schema,
            organisation_id,
            claims: claim_schemas,
            wallet_storage_type: value.wallet_storage_type,
            schema_id: value.schema_id,
            schema_type: value.schema_type.into(),
            layout_type: Some(value.layout_type),
            layout_properties: value.layout_properties.map(|item| item.into()),
            allow_suspension: value.allow_suspension,
        })
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

pub(super) fn from_create_request_with_id(
    id: CredentialSchemaId,
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    format_type: &FormatType,
    schema_type: Option<CredentialSchemaType>,
    schema_id: String,
    imported_source_url: String,
) -> Result<CredentialSchema, ServiceError> {
    if request.claims.is_empty() {
        return Err(ServiceError::ValidationError(
            "Claim schemas cannot be empty".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

    let schema_type = schema_type.unwrap_or(match format_type {
        FormatType::Mdoc => CredentialSchemaType::Mdoc,
        FormatType::SdJwtVc => CredentialSchemaType::SdJwtVc,
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
        external_schema: request.external_schema,
        revocation_method: request.revocation_method,
        claim_schemas: Some(
            claim_schemas
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
        ),
        organisation: Some(organisation),
        layout_type: request.layout_type,
        layout_properties: request.layout_properties.map(Into::into),
        schema_type,
        imported_source_url,
        schema_id,
        allow_suspension: request.allow_suspension.unwrap_or_default(),
    })
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
            metadata: false,
        },
        required,
    }
}

pub(crate) fn claim_schema_from_metadata_claim_schema(
    metadata_claim: MetadataClaimSchema,
    now: OffsetDateTime,
) -> CredentialSchemaClaim {
    CredentialSchemaClaim {
        schema: ClaimSchema {
            id: Uuid::new_v4().into(),
            key: metadata_claim.key,
            data_type: metadata_claim.data_type,
            created_date: now,
            last_modified: now,
            array: metadata_claim.array,
            metadata: true,
        },
        required: metadata_claim.required,
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

impl From<CredentialSchemaLogoPropertiesRequestDTO>
    for crate::proto::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO
{
    fn from(value: CredentialSchemaLogoPropertiesRequestDTO) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaCodePropertiesDTO>
    for crate::proto::credential_schema::dto::CredentialSchemaCodePropertiesDTO
{
    fn from(value: CredentialSchemaCodePropertiesDTO) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<CredentialSchemaBackgroundPropertiesRequestDTO>
    for crate::proto::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO
{
    fn from(value: CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: value.color,
            image: value.image,
        }
    }
}
