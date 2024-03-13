use std::collections::HashMap;

use super::dto::{
    JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO,
};
use super::{dto::IssuerResponseDTO, SSIIssuerService};
use crate::common_mapper::get_or_create_did;
use crate::common_validator::throw_if_latest_credential_state_not_eq;
use crate::config::core_config::{FormatType, Params};
use crate::config::ConfigValidationError;
use crate::model::credential_schema::CredentialSchemaId;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ValidationError};
use crate::{
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
        credential::{
            CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
            UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::DidRelations,
        organisation::OrganisationRelations,
    },
    service::{
        credential::dto::CredentialDetailResponseDTO, error::ServiceError,
        ssi_validator::validate_config_entity_presence,
    },
};
use convert_case::{Case, Casing};
use shared_types::{CredentialId, DidId, DidValue, KeyId};
use time::OffsetDateTime;
use url::Url;

impl SSIIssuerService {
    pub async fn issuer_connect(
        &self,
        credential_id: &CredentialId,
        holder_did_value: &DidValue,
    ) -> Result<CredentialDetailResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(mut credential) = credential else {
            return Err(EntityNotFoundError::Credential(credential_id.to_owned()).into());
        };

        throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Pending)?;

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        /*
         * TODO: holder_did_value is not verified if it's a valid/supported DID
         * I was able to insert 'test' string as a DID value and it got accepted
         */
        let holder_did = get_or_create_did(
            &*self.did_repository,
            &credential_schema.organisation,
            holder_did_value,
        )
        .await?;

        let now = OffsetDateTime::now_utc();
        let new_state = CredentialStateEnum::Offered;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                holder_did_id: Some(holder_did.id),
                state: Some(CredentialState {
                    created_date: now,
                    state: new_state.clone(),
                    suspend_end_date: None,
                }),
                credential: None,
                issuer_did_id: None,
                interaction: None,
                key: None,
                redirect_uri: None,
            })
            .await?;

        // Update local copy for conversion.
        credential.holder_did = Some(holder_did);
        if let Some(states) = &mut credential.state {
            states.push(CredentialState {
                created_date: now,
                state: new_state,
                suspend_end_date: None,
            });
        }

        credential.try_into()
    }

    pub async fn issuer_submit(
        &self,
        credential_id: &CredentialId,
        did_id: DidId,
        key_id: Option<KeyId>,
    ) -> Result<IssuerResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let Some(did) = self
            .did_repository
            .get_did(
                &did_id,
                &DidRelations {
                    keys: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(ValidationError::DidNotFound.into());
        };

        let token = self
            .protocol_provider
            .issue_credential(credential_id, did, key_id)
            .await?;
        Ok(IssuerResponseDTO {
            credential: token.credential,
            format: token.format,
        })
    }

    pub async fn issuer_reject(&self, credential_id: &CredentialId) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        };

        throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Offered)?;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                state: Some(CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Rejected,
                    suspend_end_date: None,
                }),
                credential: None,
                holder_did_id: None,
                issuer_did_id: None,
                interaction: None,
                key: None,
                redirect_uri: None,
            })
            .await?;

        Ok(())
    }

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
                .get_by_type::<Params>(FormatType::JsonLdBbsplus)
                .is_err()
        {
            return Err(ServiceError::from(ConfigValidationError::TypeNotFound(
                "JSON_LD".to_string(),
            )));
        }

        match id {
            "lvvc.json" => self.get_json_ld_context_for_lvvc().await,
            id => {
                let credential_schema_id = CredentialSchemaId::parse_str(id).map_err(|_| {
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
                entities: HashMap::from([
                    (
                        "LvvcCredential".to_string(),
                        JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                            id: get_url_with_fragment(&base_url, "LvvcCredential")?,
                            context: JsonLDContextDTO {
                                version,
                                protected,
                                id: id.to_owned(),
                                r#type: r#type.to_owned(),
                                entities: Default::default(),
                            },
                        }),
                    ),
                    (
                        "LvvcSubject".to_string(),
                        JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                            id: get_url_with_fragment(&base_url, "LvvcSubject")?,
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
                    ),
                ]),
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
        let claims = claim_schemas
            .iter()
            .map(|claim_schema| {
                Ok((
                    claim_schema.schema.key.to_owned(),
                    JsonLDEntityDTO::Reference(get_url_with_fragment(
                        &base_url,
                        &claim_schema.schema.key,
                    )?),
                ))
            })
            .collect::<Result<HashMap<String, JsonLDEntityDTO>, ServiceError>>()?;

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

fn get_url_with_fragment(base_url: &str, fragment: &str) -> Result<String, ServiceError> {
    let mut url = Url::parse(base_url).map_err(|e| ServiceError::MappingError(e.to_string()))?;
    url.set_fragment(Some(fragment));
    Ok(url.to_string())
}
