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
use crate::config::ConfigValidationError;
use crate::config::core_config::{FormatType, Params};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, CredentialSchemaListIncludeEntityTypeEnum,
    GetCredentialSchemaQueryDTO,
};
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::ssi_issuer::mapper::{
    credential_schema_to_sd_jwt_vc_metadata, generate_jsonld_context_response,
    get_url_with_fragment,
};

impl SSIIssuerService {
    pub async fn get_json_ld_context(
        &self,
        id: &str,
    ) -> Result<JsonLDContextResponseDTO, ServiceError> {
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
            return Err(ServiceError::from(ConfigValidationError::TypeNotFound(
                "JSON_LD".to_string(),
            )));
        }

        match id {
            "lvvc.json" => self.get_json_ld_context_for_lvvc().await,
            id => {
                let credential_schema_id = CredentialSchemaId::from_str(id).map_err(|_| {
                    ServiceError::from(BusinessLogicError::GeneralInputValidationError)
                })?;
                self.get_json_ld_context_for_credential_schema(credential_schema_id)
                    .await
            }
        }
    }

    async fn get_json_ld_context_for_lvvc(&self) -> Result<JsonLDContextResponseDTO, ServiceError> {
        let base_url = format!(
            "{}/ssi/context/v1/lvvc.json",
            self.core_base_url
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Host URL not specified".to_string()
                ))?,
        );

        let context = JsonLDContextDTO {
            entities: HashMap::from([
                (
                    "LvvcCredential".to_string(),
                    JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                        id: get_url_with_fragment(&base_url, "LvvcCredential")?,
                        r#type: None,
                        context: None,
                    }),
                ),
                (
                    "status".to_string(),
                    JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                        id: get_url_with_fragment(&base_url, "status")?,
                        r#type: None,
                        context: None,
                    }),
                ),
                (
                    "suspendEndDate".to_string(),
                    JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                        id: get_url_with_fragment(&base_url, "suspendEndDate")?,
                        r#type: None,
                        context: None,
                    }),
                ),
                // needed since we set credentialStatus.type to LVVC
                (
                    "LVVC".to_string(),
                    JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                        id: get_url_with_fragment(&base_url, "LVVC")?,
                        r#type: None,
                        context: None,
                    }),
                ),
            ]),
            ..Default::default()
        };

        Ok(JsonLDContextResponseDTO { context })
    }

    async fn get_json_ld_context_for_credential_schema(
        &self,
        credential_schema_id: CredentialSchemaId,
    ) -> Result<JsonLDContextResponseDTO, ServiceError> {
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(
                &credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential_schema) = credential_schema else {
            return Err(EntityNotFoundError::CredentialSchema(credential_schema_id).into());
        };

        let claim_schemas =
            credential_schema
                .claim_schemas
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "claim schemas missing".to_string(),
                ))?;

        let base_url = format!(
            "{}/ssi/context/v1/{credential_schema_id}",
            self.core_base_url
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Host URL not specified".to_string()
                ))?,
        );

        let schema_name = credential_schema.name.to_case(Case::Pascal);
        let schema_type = credential_schema.schema_type.to_string();

        let mut entities = HashMap::from([
            (
                schema_type.to_owned(),
                JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                    id: get_url_with_fragment(&base_url, &schema_type)?,
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
        schema_id: String,
    ) -> Result<SdJwtVcTypeMetadataResponseDTO, ServiceError> {
        let base_url = self
            .core_base_url
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Host URL not specified".to_string(),
            ))?;

        let vct = {
            let mut url = Url::parse(base_url).map_err(|error| {
                ServiceError::MappingError(format!("Invalid base URL: {error}"))
            })?;

            {
                let mut segments = url
                    .path_segments_mut()
                    .map_err(|_| ServiceError::MappingError("Invalid base URL".to_string()))?;
                let organisation_id = organisation_id.to_string();
                // /ssi/vct/v1/:organisation_id/:schema_id
                segments.extend(["ssi", "vct", "v1", &organisation_id, &schema_id]);
            }

            url.to_string()
        };

        let mut schema_list = self
            .credential_schema_repository
            .get_credential_schema_list(
                GetCredentialSchemaQueryDTO {
                    pagination: None,
                    sorting: None,
                    filtering: Some(
                        CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                            & CredentialSchemaFilterValue::SchemaId(StringMatch::equals(
                                &schema_id,
                            ))
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
            .await?;

        let Some(credential_schema) = schema_list.values.pop() else {
            return Err(ServiceError::EntityNotFound(
                EntityNotFoundError::SdJwtVcTypeMetadata(vct),
            ));
        };
        credential_schema_to_sd_jwt_vc_metadata(vct, credential_schema)
    }
}
