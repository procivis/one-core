use std::collections::HashMap;
use std::str::FromStr;

use convert_case::{Case, Casing};
use shared_types::{CredentialSchemaId, OrganisationId};
use url::Url;

use super::SSIIssuerService;
use super::dto::{
    JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO,
    SdJwtVcTypeMetadataResponseDTO,
};
use super::error::IssuerServiceError;
use super::mapper::{
    credential_schema_to_sd_jwt_vc_metadata, generate_jsonld_context_response,
    get_url_with_fragment,
};
use crate::config::ConfigValidationError;
use crate::config::core_config::{FormatType, Params};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, CredentialSchemaListIncludeEntityTypeEnum,
    GetCredentialSchemaQueryDTO,
};

pub const W3C_SCHEMA_TYPE: &str = "ProcivisOneSchema2024";

impl SSIIssuerService {
    pub async fn get_json_ld_context(
        &self,
        id: &str,
    ) -> Result<JsonLDContextResponseDTO, IssuerServiceError> {
        if self
            .config
            .format
            .get_by_type::<Params>(FormatType::JsonLdClassic)
            .is_err()
            && self
                .config
                .format
                .get_by_type::<Params>(FormatType::JsonLdBbsPlus)
                .is_err()
        {
            return Err(ConfigValidationError::TypeNotFound("JSON_LD".to_string())
                .error_while("checking config")
                .into());
        }

        let credential_schema_id =
            CredentialSchemaId::from_str(id).map_err(|_| IssuerServiceError::InvalidInput)?;
        self.get_json_ld_context_for_credential_schema(credential_schema_id)
            .await
    }

    async fn get_json_ld_context_for_credential_schema(
        &self,
        credential_schema_id: CredentialSchemaId,
    ) -> Result<JsonLDContextResponseDTO, IssuerServiceError> {
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(
                &credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential schema")?;

        let Some(credential_schema) = credential_schema else {
            return Err(IssuerServiceError::MissingCredentialSchema(
                credential_schema_id,
            ));
        };

        let config = self
            .config
            .format
            .get_fields(&credential_schema.format)
            .error_while("getting format config")?;
        if ![FormatType::JsonLdBbsPlus, FormatType::JsonLdClassic].contains(&config.r#type) {
            return Err(IssuerServiceError::InvalidFormat);
        }

        let claim_schemas =
            credential_schema
                .claim_schemas
                .as_ref()
                .ok_or(IssuerServiceError::MappingError(
                    "claim schemas missing".to_string(),
                ))?;

        let base_url = format!(
            "{}/ssi/context/v1/{credential_schema_id}",
            self.core_base_url
                .as_ref()
                .ok_or(IssuerServiceError::MappingError(
                    "Host URL not specified".to_string()
                ))?,
        );

        let schema_name = credential_schema.name.to_case(Case::Pascal);

        let mut entities = HashMap::from([
            (
                W3C_SCHEMA_TYPE.to_owned(),
                JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                    id: get_url_with_fragment(&base_url, W3C_SCHEMA_TYPE)?,
                    r#type: None,
                    context: Some(JsonLDContextDTO {
                        version: None,
                        protected: true,
                        id: "@id".to_string(),
                        r#type: "@type".to_string(),
                        entities: HashMap::from_iter([(
                            "metadata".to_string(),
                            JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                                id: get_url_with_fragment(&base_url, "metadata")?,
                                r#type: Some("@json".to_string()),
                                context: None,
                            }),
                        )]),
                    }),
                }),
            ),
            (
                schema_name.to_owned(),
                JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                    id: get_url_with_fragment(&base_url, &schema_name)?,
                    r#type: None,
                    context: None,
                }),
            ),
        ]);
        entities.extend(generate_jsonld_context_response(claim_schemas, &base_url)?);

        Ok(JsonLDContextResponseDTO {
            context: JsonLDContextDTO {
                entities,
                ..Default::default()
            },
        })
    }

    pub async fn get_vct_metadata(
        &self,
        organisation_id: OrganisationId,
        vct_type: String,
    ) -> Result<SdJwtVcTypeMetadataResponseDTO, IssuerServiceError> {
        let base_url = self
            .core_base_url
            .as_ref()
            .ok_or(IssuerServiceError::MappingError(
                "Host URL not specified".to_string(),
            ))?;

        let vct = {
            let mut vct = Url::parse(base_url).map_err(|error| {
                IssuerServiceError::MappingError(format!("Invalid base URL: {error}"))
            })?;

            {
                let mut segments = vct.path_segments_mut().map_err(|_| {
                    IssuerServiceError::MappingError("Invalid base URL".to_string())
                })?;
                let organisation_id = organisation_id.to_string();
                // /ssi/vct/v1/:organisation_id/:vct_type
                segments.extend(["ssi", "vct", "v1", &organisation_id, &vct_type]);
            }

            vct.to_string()
        };

        let mut schema_list = self
            .credential_schema_repository
            .get_credential_schema_list(
                GetCredentialSchemaQueryDTO {
                    pagination: None,
                    sorting: None,
                    filtering: Some(
                        CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                            & CredentialSchemaFilterValue::SchemaId(StringMatch::equals(&vct))
                                .condition(),
                    ),
                    include: Some(vec![
                        CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
                    ]),
                },
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential schemas")?;

        let Some(credential_schema) = schema_list.values.pop() else {
            return Err(IssuerServiceError::MissingSdJwtVcTypeMetadata(vct));
        };
        credential_schema_to_sd_jwt_vc_metadata(vct_type, credential_schema)
    }
}
