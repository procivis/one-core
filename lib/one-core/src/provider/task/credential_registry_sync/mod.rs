use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};
use shared_types::{CredentialFormat, OrganisationId};

use super::Task;
use crate::config::core_config::{CoreConfig, FormatType};
use crate::error::ContextWithErrorCode;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialCommon, CredentialFilterValue, CredentialRole, CredentialStateEnum,
    CredentialType, HolderCredentialData,
};
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::localized_text::{LocalizedText, LocalizedTextField};
use crate::model::relation::RelatedVec;
use crate::proto::native_credential_manager::{
    DigitalCredentialClaim, DigitalCredentialDisplay, DigitalCredentialMetadata,
    DigitalCredentialRegistration, NativeCredentialManager,
};
use crate::repository::credential_repository::CredentialRepository;
use crate::service::error::ServiceError;

#[cfg(test)]
mod test;

pub struct CredentialRegistrySync {
    config: Arc<CoreConfig>,
    credential_repository: Arc<dyn CredentialRepository>,
    native_credential_manager: Option<Arc<dyn NativeCredentialManager>>,
}

impl CredentialRegistrySync {
    pub(crate) fn new(
        config: Arc<CoreConfig>,
        credential_repository: Arc<dyn CredentialRepository>,
        native_credential_manager: Option<Arc<dyn NativeCredentialManager>>,
    ) -> Self {
        Self {
            config,
            credential_repository,
            native_credential_manager,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    pub organisation_id: OrganisationId,
    pub language: String,
}

#[async_trait::async_trait]
impl Task for CredentialRegistrySync {
    async fn run(&self, params: Option<Value>) -> Result<Value, ServiceError> {
        let Some(params) = params else {
            return Err(ServiceError::ValidationError("Missing params".to_string()));
        };
        let params: Params = serde_json::from_value(params)
            .map_err(|e| ServiceError::ValidationError(e.to_string()))?;

        let Some(credential_manager) = &self.native_credential_manager else {
            return Err(ServiceError::ValidationError(
                "Missing credential manager".to_string(),
            ));
        };

        let credentials = self
            .credential_repository
            .get_credential_list(ListQuery {
                include_count: false,
                filtering: Some(
                    CredentialFilterValue::OrganisationId(params.organisation_id).condition()
                        & CredentialFilterValue::Roles(vec![CredentialRole::Holder])
                        & CredentialFilterValue::States(vec![CredentialStateEnum::Accepted])
                        & CredentialFilterValue::Deleted(false)
                        & ((CredentialFilterValue::Types(vec![CredentialType::BatchParent])
                            .condition()
                            & CredentialFilterValue::HasUnconsumedBatchItems(true))
                            | (CredentialFilterValue::Types(vec![CredentialType::Single])
                                .condition()
                                & CredentialFilterValue::Formats(self.supported_formats()))),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting credentials")?
            .values;

        let mut credential_registrations = Vec::with_capacity(credentials.len());
        for credential in credentials {
            match credential {
                Credential::HolderSingle { common, credential } => {
                    credential_registrations.push(
                        self.convert_holder_credential(&common, &credential, &params.language)
                            .await?,
                    );
                }
                Credential::HolderBatchParent { common } => {
                    credential_registrations
                        .extend(self.convert_batch_parent(common, &params.language).await?);
                }
                _ => {
                    return Err(ServiceError::MappingError(
                        "Invalid credential role/type".to_string(),
                    ));
                }
            }
        }

        credential_manager
            .synchronize(credential_registrations)
            .await
            .error_while("synchronizing credentials")?;

        Ok(json!({}))
    }
}

impl CredentialRegistrySync {
    fn supported_formats(&self) -> Vec<CredentialFormat> {
        self.config
            .format
            .iter()
            .filter(|(_, fields)| matches!(fields.r#type, FormatType::SdJwtVc | FormatType::Mdoc))
            .map(|(format, _)| format.to_owned())
            .collect()
    }

    async fn convert_holder_credential(
        &self,
        common: &CredentialCommon,
        credential: &HolderCredentialData,
        language: &str,
    ) -> Result<DigitalCredentialRegistration, ServiceError> {
        Ok(DigitalCredentialRegistration {
            credential_id: common.id,
            metadata: self.metadata(credential).await?,
            claims: claims(common, credential, language).await?,
            display: display(common, credential, language).await?,
        })
    }

    async fn convert_batch_parent(
        &self,
        common: CredentialCommon,
        language: &str,
    ) -> Result<Vec<DigitalCredentialRegistration>, ServiceError> {
        let batch_items = self
            .credential_repository
            .get_credential_list(ListQuery {
                include_count: false,
                filtering: Some(
                    CredentialFilterValue::ParentCredential(common.id).condition()
                        & CredentialFilterValue::Formats(self.supported_formats())
                        & CredentialFilterValue::States(vec![CredentialStateEnum::Accepted])
                        & CredentialFilterValue::Consumed(false)
                        & CredentialFilterValue::Deleted(false),
                ),

                ..Default::default()
            })
            .await
            .error_while("getting batch items")?
            .values
            .into_iter()
            .filter_map(|cred| {
                if let Credential::HolderBatchItem { credential, .. } = cred {
                    Some(credential)
                } else {
                    None
                }
            });

        // find all formats, pick one item per format type
        let mut formats = HashMap::<FormatType, HolderCredentialData>::new();
        for batch_item in batch_items {
            let r#type = {
                let format = batch_item.format.as_ref().await?;
                self.config
                    .format
                    .get_type(&format.format)
                    .error_while("finding format type")?
            };
            formats.entry(r#type).or_insert(batch_item);
        }

        let mut result = Vec::with_capacity(formats.len());
        for batch_item in formats.into_values() {
            result.push(
                self.convert_holder_credential(&common, &batch_item, language)
                    .await?,
            );
        }
        Ok(result)
    }

    async fn metadata(
        &self,
        credential: &HolderCredentialData,
    ) -> Result<DigitalCredentialMetadata, ServiceError> {
        let format = credential.format.as_ref().await?;
        let r#type = self
            .config
            .format
            .get_type(&format.format)
            .error_while("finding format type")?;

        Ok(match r#type {
            FormatType::SdJwtVc => DigitalCredentialMetadata::SdJwtVc {
                vct: format.ecosystem_schema_id.to_owned(),
            },
            FormatType::Mdoc => DigitalCredentialMetadata::Mdoc {
                doctype: format.ecosystem_schema_id.to_owned(),
            },
            other => {
                return Err(ServiceError::MappingError(format!("Invalid type: {other}")));
            }
        })
    }
}

async fn claims(
    common: &CredentialCommon,
    credential: &HolderCredentialData,
    language: &str,
) -> Result<Vec<DigitalCredentialClaim>, ServiceError> {
    let schema = common.schema.as_ref().await?;
    let claim_schemas = schema.claim_schemas.as_ref().await?;
    let format = credential.format.as_ref().await?;
    let claim_mappings = format.claim_mappings.as_ref().await?;
    let claims = credential.claims.as_ref().await?;
    let mut result = Vec::<DigitalCredentialClaim>::with_capacity(claims.len());
    for claim in &claims {
        if let Some(claim) = convert_claim(claim, &claim_schemas, &claim_mappings, language).await?
            // avoid duplicit entries (for example array claims)
            && !result.iter().any(|c| c.path == claim.path)
        {
            result.push(claim);
        }
    }
    Ok(result)
}

async fn convert_claim(
    claim: &Claim,
    claim_schemas: &[ClaimSchema],
    mappings: &[CredentialSchemaFormatClaimSchema],
    language: &str,
) -> Result<Option<DigitalCredentialClaim>, ServiceError> {
    let schema = claim.schema.as_ref().await?;

    // skip metadata claims
    if schema.metadata {
        return Ok(None);
    }

    // only produce entries for claims not nested inside arrays,
    // since path can only contain strings (so array claims cannot be properly mapped)
    if is_nested_under_array(&schema, claim_schemas) {
        return Ok(None);
    };

    let mapping = mappings
        .iter()
        .find(|mapping| mapping.claim_schema_id == claim.schema.id())
        .ok_or(ServiceError::MappingError(format!(
            "Missing mapping for: `{}`({})",
            claim.path, claim.id
        )))?;

    // construct path from technical keys
    let path = {
        let mut path: Vec<String> = mapping
            .technical_key
            .split(NESTED_CLAIM_MARKER)
            .map(ToString::to_string)
            .collect();

        // prepend namespace for mdocs
        if let Some(namespace) = &mapping.namespace {
            path.insert(0, namespace.to_owned());
        }

        path
    };

    Ok(Some(DigitalCredentialClaim {
        path,
        display_name: pick_translation(&schema.translations, language).await?,
        selectively_disclosable: claim.selectively_disclosable,
    }))
}

fn is_nested_under_array(target: &ClaimSchema, all_claim_schemas: &[ClaimSchema]) -> bool {
    let Some((parent_path, _)) = target.key.rsplit_once(NESTED_CLAIM_MARKER) else {
        // if root claim, then not array-nested
        return false;
    };

    let Some(parent_claim_schema) = all_claim_schemas.iter().find(|cs| cs.key == parent_path)
    else {
        tracing::warn!(
            "Could not find parent claim schema with path: `{parent_path}`, claim schema id: {}",
            target.id
        );
        return false;
    };
    if parent_claim_schema.array {
        return true;
    }

    is_nested_under_array(parent_claim_schema, all_claim_schemas)
}

async fn display(
    common: &CredentialCommon,
    credential: &HolderCredentialData,
    language: &str,
) -> Result<DigitalCredentialDisplay, ServiceError> {
    let schema = common.schema.as_ref().await?;
    let issuer = credential.issuer.identifier.as_ref().await?;

    let logo = if let Some(layout_properties) = &schema.layout_properties
        && let Some(logo) = &layout_properties.logo
    {
        logo.image.clone()
    } else {
        None
    };

    Ok(DigitalCredentialDisplay {
        credential_name: pick_translation(&schema.translations, language)
            .await?
            .unwrap_or_else(|| schema.name.to_owned()),
        issuer_name: pick_translation(&issuer.translations, language).await?,
        logo,
    })
}

async fn pick_translation(
    translations: &RelatedVec<LocalizedText>,
    language: &str,
) -> Result<Option<String>, ServiceError> {
    let translations = translations.as_ref().await?;
    Ok(translations
        .iter()
        .find(|text| text.lang == language && text.field == LocalizedTextField::Name)
        .map(|text| text.value.to_owned()))
}
