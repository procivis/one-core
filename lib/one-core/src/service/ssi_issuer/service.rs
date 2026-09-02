use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use convert_case::{Case, Casing};
use shared_types::{CredentialFormat, CredentialSchemaId, IdentifierId, OrganisationId};
use standardized_types::jwk::{JwkUse, PublicJwk};
use url::Url;

use super::SSIIssuerService;
use super::dto::{
    JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO,
    SdJwtVcIssuerMetadata, SdJwtVcIssuerMetadataJwks, SdJwtVcTypeMetadataResponseDTO,
};
use super::error::IssuerServiceError;
use super::mapper::{
    credential_schema_to_sd_jwt_vc_metadata, generate_jsonld_context_response,
    get_url_with_fragment,
};
use crate::config::ConfigValidationError;
use crate::config::core_config::{FormatType, KeyStorageType, Params};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaListQuery};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::key::Key;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::relation::RelatedVec;
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, CredentialSchemaListIncludeEntityTypeEnum,
};

pub const W3C_SCHEMA_TYPE: &str = "ProcivisOneSchema2024";

async fn filter_schema_to_format(
    mut schema: CredentialSchema,
    format: &CredentialFormat,
    not_found_vct: &str,
) -> Result<CredentialSchema, IssuerServiceError> {
    let formats = schema.formats.as_ref().await?.to_owned();
    let matching_format = formats
        .into_iter()
        .find(|f| f.format == *format)
        .ok_or_else(|| IssuerServiceError::MissingSdJwtVcTypeMetadata(not_found_vct.to_owned()))?;

    let mapped_ids: HashSet<_> = matching_format
        .claim_mappings
        .as_ref()
        .await?
        .iter()
        .map(|m| m.claim_schema_id)
        .collect();

    let all_claims = schema.claim_schemas.as_ref().await?.to_owned();
    let filtered_claims: Vec<ClaimSchema> = all_claims
        .into_iter()
        .filter(|cs| mapped_ids.contains(&cs.id))
        .collect();

    schema.claim_schemas = RelatedVec::from(filtered_claims);
    schema.formats = RelatedVec::from(vec![matching_format]);

    Ok(schema)
}

impl SSIIssuerService {
    pub async fn get_json_ld_context(
        &self,
        id: &str,
        format: Option<&CredentialFormat>,
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
        self.get_json_ld_context_for_credential_schema(credential_schema_id, format)
            .await
    }

    async fn get_json_ld_context_for_credential_schema(
        &self,
        credential_schema_id: CredentialSchemaId,
        format: Option<&CredentialFormat>,
    ) -> Result<JsonLDContextResponseDTO, IssuerServiceError> {
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(&credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let (schema_format, claim_mappings) = if let Some(format) = format {
            let formats = credential_schema.formats.as_ref().await?;
            let Some(format) = formats.iter().find(|f| f.format == *format) else {
                return Err(IssuerServiceError::InvalidFormat);
            };
            (
                format.format.clone(),
                Some(format.claim_mappings.as_ref().await?.to_vec()),
            )
        } else {
            (credential_schema.format().await?, None)
        };

        let config = self
            .config
            .format
            .get_fields(&schema_format)
            .error_while("getting format config")?;
        if ![FormatType::JsonLdBbsPlus, FormatType::JsonLdClassic].contains(&config.r#type) {
            return Err(IssuerServiceError::InvalidFormat);
        }

        let base_url = format!(
            "{}/ssi/context/v1/{credential_schema_id}/{schema_format}",
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

        let claim_schemas = credential_schema.claim_schemas.as_ref().await?;
        entities.extend(generate_jsonld_context_response(
            &claim_schemas,
            &base_url,
            &claim_mappings,
        )?);

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
            .get_credential_schema_list(CredentialSchemaListQuery {
                pagination: None,
                sorting: None,
                filtering: Some(
                    CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                        & CredentialSchemaFilterValue::EcosystemSchemaId(StringMatch::equals(&vct))
                            .condition(),
                ),
                include: Some(vec![
                    CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
                ]),
            })
            .await
            .error_while("getting credential schemas")?;

        let Some(credential_schema) = schema_list.values.pop() else {
            return Err(IssuerServiceError::MissingSdJwtVcTypeMetadata(vct));
        };
        credential_schema_to_sd_jwt_vc_metadata(vct_type, vct, credential_schema).await
    }

    pub async fn get_vct_metadata_v2(
        &self,
        organisation_id: OrganisationId,
        credential_schema_id: String,
        format: CredentialFormat,
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
                // /ssi/vct/v2/:organisation_id/:credential_schema_id/:format
                segments.extend(["ssi", "vct", "v2", &organisation_id, &credential_schema_id]);
                segments.push(format.as_ref());
            }

            vct.to_string()
        };

        let filter = CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
            & CredentialSchemaFilterValue::EcosystemSchemaId(StringMatch::equals(&vct)).condition()
            & CredentialSchemaFilterValue::Formats(vec![format.to_owned()]).condition();

        let mut schema_list = self
            .credential_schema_repository
            .get_credential_schema_list(CredentialSchemaListQuery {
                pagination: None,
                sorting: None,
                filtering: Some(filter),
                include: Some(vec![
                    CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
                ]),
            })
            .await
            .error_while("getting credential schemas")?;

        let Some(credential_schema) = schema_list.values.pop() else {
            return Err(IssuerServiceError::MissingSdJwtVcTypeMetadata(vct));
        };

        let credential_schema = filter_schema_to_format(credential_schema, &format, &vct).await?;

        credential_schema_to_sd_jwt_vc_metadata(credential_schema_id, vct, credential_schema).await
    }

    pub async fn get_sd_jwt_vc_issuer_metadata(
        &self,
        protocol_id: &String,
        identifier_id: &IdentifierId,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<SdJwtVcIssuerMetadata, IssuerServiceError> {
        let core_base_url = self
            .core_base_url
            .as_ref()
            .ok_or(IssuerServiceError::MappingError(
                "Missing core_base_url for jwt vc issuer metadata".to_string(),
            ))?;
        let _protocol = self
            .issuance_protocol_provider
            .get_protocol(protocol_id)
            .map_err(|_| IssuerServiceError::MissingProtocol(protocol_id.to_string()))?;
        let identifier = self.fetch_identifier(identifier_id).await?;
        let credential_schema = self.fetch_credential_schema(credential_schema_id).await?;

        let issuer = if let IdentifierData::Did(issuer_did) = &identifier.data {
            issuer_did.as_ref().await?.did.as_str().to_string()
        } else {
            format!(
                "{core_base_url}/ssi/openid4vci/{protocol_id}/{}/{}",
                identifier.id, credential_schema.id
            )
        };

        let jwks = self.collect_identifier_jwks(&identifier).await?;
        Ok(SdJwtVcIssuerMetadata {
            issuer,
            jwks: SdJwtVcIssuerMetadataJwks::Jwks(jwks),
        })
    }

    async fn collect_identifier_jwks(
        &self,
        identifier: &Identifier,
    ) -> Result<Vec<PublicJwk>, IssuerServiceError> {
        let keys = identifier
            .list_keys(None, None)
            .await
            .error_while("selecting identifier keys")?;
        let mut result = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(key) = self.calculate_jwk_for_key(key.key()).await? {
                result.push(key);
            }
        }
        Ok(result)
    }

    async fn calculate_jwk_for_key(
        &self,
        key: &Key,
    ) -> Result<Option<PublicJwk>, IssuerServiceError> {
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_key(key)
            .error_while("getting key algorithm")?;

        /*
         * TODO(ONE-5428): Azure vault doesn't work directly with encrypted JWE params
         * This needs more investigation and a refactor to support creating shared secret
         * through key storage
         */
        let r#use = if self
            .config
            .key_storage
            .get_type(&key.storage_type)
            .error_while("getting key storage type")?
            != KeyStorageType::AzureVault
        {
            Some(JwkUse::Encryption)
        } else {
            return Ok(None);
        };

        let mut jwk = key_algorithm
            .reconstruct_key(&key.public_key, None, r#use)
            .error_while("reconstructing encryption key")?
            .public_key_as_jwk()
            .error_while("creating JWK")?;
        jwk.set_kid(key.id.to_string());
        Ok(Some(jwk))
    }

    async fn fetch_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<CredentialSchema, IssuerServiceError> {
        Ok(self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("fetching credential schema")?)
    }

    async fn fetch_identifier(
        &self,
        identifier_id: &IdentifierId,
    ) -> Result<Identifier, IssuerServiceError> {
        Ok(self
            .identifier_repository
            .get(*identifier_id)
            .await
            .error_while("fetching identifier")?)
    }
}
