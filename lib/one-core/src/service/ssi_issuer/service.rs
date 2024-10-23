use std::collections::HashMap;
use std::str::FromStr;

use convert_case::{Case, Casing};
use shared_types::CredentialSchemaId;

use super::dto::{
    JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO,
};
use super::SSIIssuerService;
use crate::config::core_config::Params;
use crate::config::ConfigValidationError;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::ssi_issuer::mapper::{generate_jsonld_context_response, get_url_with_fragment};

impl SSIIssuerService {
    pub async fn get_json_ld_context(
        &self,
        id: &str,
    ) -> Result<JsonLDContextResponseDTO, ServiceError> {
        if self
            .config
            .format
            .get_by_type::<Params>("JSON_LD_CLASSIC".to_owned())
            .is_err()
            && self
                .config
                .format
                .get_by_type::<Params>("JSON_LD_BBSPLUS".to_owned())
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
        let version = 1.1;
        let protected = true;
        let id = "@id";
        let r#type = "@type";

        let base_url = format!(
            "{}/ssi/context/v1/lvvc.json",
            self.core_base_url
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Host URL not specified".to_string()
                ))?,
        );

        Ok(JsonLDContextResponseDTO {
            context: JsonLDContextDTO {
                version,
                protected,
                id: id.to_owned(),
                r#type: r#type.to_owned(),
                entities: HashMap::from([(
                    "LvvcCredential".to_string(),
                    JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                        id: get_url_with_fragment(&base_url, "LvvcCredential")?,
                        context: JsonLDContextDTO {
                            version,
                            protected,
                            id: id.to_owned(),
                            r#type: r#type.to_owned(),
                            entities: HashMap::from([
                                (
                                    "status".to_string(),
                                    JsonLDEntityDTO::Reference(get_url_with_fragment(
                                        &base_url, "status",
                                    )?),
                                ),
                                (
                                    "suspendEndDate".to_string(),
                                    JsonLDEntityDTO::Reference(get_url_with_fragment(
                                        &base_url,
                                        "suspendEndDate",
                                    )?),
                                ),
                            ]),
                        },
                    }),
                )]),
            },
        })
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
        let credential_name = format!("{schema_name}Credential");
        let subject_name = format!("{schema_name}Subject");
        let claims = generate_jsonld_context_response(claim_schemas, &base_url)?;

        Ok(JsonLDContextResponseDTO {
            context: JsonLDContextDTO {
                entities: HashMap::from([
                    (
                        credential_name.to_owned(),
                        JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                            id: get_url_with_fragment(&base_url, &credential_name)?,
                            context: JsonLDContextDTO::default(),
                        }),
                    ),
                    (
                        subject_name.to_owned(),
                        JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                            id: get_url_with_fragment(&base_url, &subject_name)?,
                            context: JsonLDContextDTO {
                                entities: claims,
                                ..Default::default()
                            },
                        }),
                    ),
                ]),
                ..Default::default()
            },
        })
    }
}
