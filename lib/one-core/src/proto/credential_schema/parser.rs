use std::sync::Arc;

use indexmap::IndexMap;
use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialFormat, CredentialSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::Error;
use super::dto::{
    CredentialClaimSchemaMappingDTO, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesDTO, CredentialSchemaLogoPropertiesRequestDTO,
    ImportCredentialSchemaClaimSchemaDTO, ImportCredentialSchemaLayoutPropertiesDTO,
    ImportCredentialSchemaRequestDTO, ImportCredentialSchemaV2FormatDTO,
    ImportCredentialSchemaV2RequestDTO,
};
use crate::config::core_config::{ConfigExt, CoreConfig, DatatypeType, FormatType};
use crate::error::ContextWithErrorCode;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::credential_schema_claim::{
    claim_name_translations_from_dto, claim_schema_from_metadata_claim_schema,
};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{
    BackgroundProperties, CodeProperties, CredentialSchema, LayoutProperties, LogoProperties,
};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::relation::RelatedVec;
use crate::proto::credential_schema::dto::ImportCredentialSchemaV2RequestSchemaDTO;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{Features, FormatterCapabilities};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::model::Operation;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::service::credential_schema::dto::CredentialSchemaWalletAttestationDTO;
use crate::service::credential_schema::mapper::schema_translations_from_dto;
use crate::validator::schema::validate_imported_source_url;

pub(crate) struct CredentialSchemaImportParserImpl {
    config: Arc<CoreConfig>,
    core_base_url: Option<String>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait CredentialSchemaImportParser: Send + Sync {
    fn parse_import_credential_schema(
        &self,
        dto: ImportCredentialSchemaRequestDTO,
    ) -> Result<CredentialSchema, Error>;

    fn parse_import_credential_schema_v2(
        &self,
        dto: ImportCredentialSchemaV2RequestDTO,
    ) -> Result<CredentialSchema, Error>;
}

impl CredentialSchemaImportParser for CredentialSchemaImportParserImpl {
    fn parse_import_credential_schema(
        &self,
        dto: ImportCredentialSchemaRequestDTO,
    ) -> Result<CredentialSchema, Error> {
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&dto.schema.format)?;
        let format_type = self
            .config
            .format
            .get_fields(&dto.schema.format)
            .error_while("getting format type")?
            .r#type();
        let revocation_method = match &dto.schema.revocation_method {
            Some(method_id) => Some(
                self.revocation_method_provider
                    .get_revocation_method(method_id)?,
            ),
            None => None,
        };
        let claims = self.transform_claim_schemas_v1_to_v2(
            dto.schema.claims,
            *format_type,
            &dto.schema.format,
        )?;

        let layout_properties = match dto.schema.layout_properties {
            Some(layout_properties) if format_type == &FormatType::Mdoc => {
                Some(transform_mdoc_layout_properties_v1_to_v2(layout_properties))
            }
            unchanged => unchanged,
        };

        let request_v2 = ImportCredentialSchemaV2RequestSchemaDTO {
            id: dto.schema.id,
            created_date: dto.schema.created_date,
            last_modified: dto.schema.last_modified,
            name: dto.schema.name,
            wallet_attestation: Some(CredentialSchemaWalletAttestationDTO {
                require_instance_attestation: dto
                    .schema
                    .requires_wallet_instance_attestation
                    .unwrap_or(false),
                key_storage_security_level: dto.schema.key_storage_security,
                preferred_key_storage_attestation_lifetime: None,
                preferred_instance_attestation_lifetime: None,
            }),
            layout_properties,
            imported_source_url: dto.schema.imported_source_url,
            allow_revocation: Some(
                self.parse_allow_revocation(revocation_method.as_deref(), formatter.as_ref())?,
            ),
            allow_suspension: Some(self.parse_allow_suspension(
                dto.schema.allow_suspension,
                revocation_method.as_deref(),
            )?),
            claims,
            organisation_id: dto.schema.organisation_id,
            formats: vec![ImportCredentialSchemaV2FormatDTO {
                format: dto.schema.format,
                ecosystem_schema_id: dto.schema.schema_id,
            }],
            transaction_code: dto.schema.transaction_code,
            batch_size: None,
            translations: None,
            embedded_disclosure_policy: None,
            expiration: dto.schema.expiration,
            ecosystem: dto.schema.ecosystem,
        };

        self.parse_import_credential_schema_v2(ImportCredentialSchemaV2RequestDTO {
            organisation: dto.organisation,
            schema: request_v2,
        })
    }

    fn parse_import_credential_schema_v2(
        &self,
        dto: ImportCredentialSchemaV2RequestDTO,
    ) -> Result<CredentialSchema, Error> {
        if dto.schema.formats.is_empty() {
            return Err(Error::MissingFormats);
        }
        self.validate_unique_formats(&dto.schema.formats)?;
        if let Some(batch_size) = dto.schema.batch_size
            && batch_size < 2
        {
            return Err(Error::BatchSizeTooSmall);
        }
        let now = crate::clock::now_utc();

        let mut formatters = Vec::with_capacity(dto.schema.formats.len());
        for format_req in &dto.schema.formats {
            self.parse_format(format_req.format.clone())?;
            let format_type = self
                .config
                .format
                .get_fields(&format_req.format)
                .error_while("getting format type")?
                .r#type()
                .to_owned();
            let formatter = self
                .formatter_provider
                .get_credential_formatter(&format_req.format)?;
            formatters.push((format_type, formatter));
        }

        let claim_schemas_with_raw_mappings =
            self.parse_all_claim_schemas_v2(now, dto.schema.claims, formatters.as_ref())?;

        let credential_schema_id = Uuid::new_v4().into();
        if !self.config.global_settings.rehost_imported_schemas || self.core_base_url.is_none() {
            validate_imported_source_url(&dto.schema.imported_source_url)
                .error_while("validating imported source URL")?;
        }

        let mut formats = vec![];
        let mut claim_schemas: Vec<_> = claim_schemas_with_raw_mappings
            .iter()
            .map(|(cs, _)| cs.clone())
            .collect();
        let mut metadata_claim_schemas = IndexMap::new();
        for format_req in &dto.schema.formats {
            let formatter = self
                .formatter_provider
                .get_credential_formatter(&format_req.format)?;

            let schema_id =
                self.parse_schema_id(format_req.ecosystem_schema_id.clone(), formatter.as_ref())?;
            let format = self.parse_format_with_claim_mappings(
                credential_schema_id,
                schema_id,
                format_req.format.clone(),
                now,
                &claim_schemas_with_raw_mappings,
                formatter.as_ref(),
                &mut metadata_claim_schemas,
            )?;

            formats.push(format);
        }
        claim_schemas.extend(metadata_claim_schemas.into_values());

        Ok(CredentialSchema {
            ecosystem: dto.schema.ecosystem,
            id: credential_schema_id,
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: dto.schema.name,
            wallet_attestation: dto
                .schema
                .wallet_attestation
                .map(Into::into)
                .unwrap_or_default(),
            layout_properties: self.parse_layout_properties(
                dto.schema.layout_properties,
                &claim_schemas,
                formatters.as_ref(),
            )?,
            imported_source_url: dto.schema.imported_source_url,
            allow_suspension: dto.schema.allow_suspension.unwrap_or(false),
            claim_schemas: claim_schemas.into(),
            organisation: dto.organisation.into(),
            formats: formats.into(),
            transaction_code: convert_inner(dto.schema.transaction_code),
            batch_size: dto.schema.batch_size,
            allow_revocation: dto.schema.allow_revocation.unwrap_or(false),
            translations: match dto.schema.translations {
                Some(translations) => {
                    schema_translations_from_dto(credential_schema_id, translations, now).into()
                }
                None => Default::default(),
            },
            embedded_disclosure_policy: dto
                .schema
                .embedded_disclosure_policy
                .map(|policy| serde_json::to_string(&policy))
                .transpose()
                .map_err(|e| Error::MappingError(e.to_string()))?,
            expiration: dto.schema.expiration,
        })
    }
}

impl CredentialSchemaImportParserImpl {
    pub(crate) fn new(
        config: Arc<CoreConfig>,
        core_base_url: Option<String>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    ) -> Self {
        Self {
            config,
            core_base_url,
            formatter_provider,
            revocation_method_provider,
        }
    }

    fn parse_allow_revocation(
        &self,
        revocation_method: Option<&dyn RevocationMethod>,
        formatter: &dyn CredentialFormatter,
    ) -> Result<bool, Error> {
        Ok(match revocation_method {
            None => false,
            Some(method) => {
                if formatter.revocation_method_id() != Some(method.config_name()) {
                    return Err(Error::RevocationMethodNotCompatibleWithSelectedFormat);
                }

                method
                    .get_capabilities()
                    .operations
                    .contains(&Operation::Revoke)
            }
        })
    }

    pub(super) fn parse_allow_suspension(
        &self,
        allow_suspension: Option<bool>,
        revocation_method: Option<&dyn RevocationMethod>,
    ) -> Result<bool, Error> {
        let operations = match revocation_method {
            Some(method) => method.get_capabilities().operations,
            None => vec![],
        };

        match allow_suspension {
            Some(true) => {
                if !operations.contains(&Operation::Suspend) {
                    return Err(Error::SuspensionNotAvailableForSelectedRevocationMethod);
                }
            }
            _ => {
                if operations == vec![Operation::Suspend] {
                    return Err(Error::SuspensionNotEnabledForSuspendOnlyRevocationMethod);
                }
            }
        };
        Ok(allow_suspension.unwrap_or(false))
    }

    pub(super) fn parse_layout_properties(
        &self,
        layout_properties: Option<ImportCredentialSchemaLayoutPropertiesDTO>,
        claim_schemas: &[ClaimSchema],
        formatters: &[(FormatType, Arc<dyn CredentialFormatter>)],
    ) -> Result<Option<LayoutProperties>, Error> {
        if layout_properties.is_some()
            && !formatters.iter().all(|(_, f)| {
                f.get_capabilities()
                    .features
                    .contains(&Features::SupportsCredentialDesign)
            })
        {
            return Err(Error::LayoutPropertiesNotSupported);
        }

        let Some(layout_properties) = layout_properties else {
            return Ok(None);
        };

        Ok(Some(LayoutProperties {
            background: layout_properties
                .background
                .map(|bg| self.parse_background_properties(bg))
                .transpose()?,
            logo: layout_properties
                .logo
                .map(|logo| self.parse_logo_properties(logo))
                .transpose()?,
            primary_attribute: layout_properties
                .primary_attribute
                .map(|a| self.parse_layout_attribute(a, claim_schemas, "Primary"))
                .transpose()?,
            secondary_attribute: layout_properties
                .secondary_attribute
                .map(|a| self.parse_layout_attribute(a, claim_schemas, "Secondary"))
                .transpose()?,
            picture_attribute: layout_properties
                .picture_attribute
                .map(|a| self.parse_layout_attribute(a, claim_schemas, "Picture"))
                .transpose()?,
            code: layout_properties
                .code
                .map(|a| self.parse_code_attribute(a, claim_schemas))
                .transpose()?,
        }))
    }

    pub(super) fn parse_schema_id(
        &self,
        ecosystem_schema_id: String,
        formatter: &dyn CredentialFormatter,
    ) -> Result<String, Error> {
        let FormatterCapabilities { features, .. } = formatter.get_capabilities();

        // Supports -> required here because the system that the schema is parsed from is supposed
        // to have generated the ecosystem_schema_id if it was not set manually.
        let is_schema_id_required = features.contains(&Features::SupportsSchemaId);
        if is_schema_id_required && ecosystem_schema_id.is_empty() {
            return Err(Error::MissingSchemaId);
        }
        Ok(ecosystem_schema_id)
    }

    pub(super) fn parse_format(&self, format: CredentialFormat) -> Result<CredentialFormat, Error> {
        self.config
            .format
            .get_if_enabled(&format)
            .error_while("checking format")?;
        Ok(format)
    }

    fn transform_claim_schemas_v1_to_v2(
        &self,
        mut claim_schemas: Vec<ImportCredentialSchemaClaimSchemaDTO>,
        format_type: FormatType,
        format: &CredentialFormat,
    ) -> Result<Vec<ImportCredentialSchemaClaimSchemaDTO>, Error> {
        if claim_schemas.is_empty() {
            return Err(Error::MissingClaims);
        }

        if format_type == FormatType::Mdoc {
            let mut result: Vec<ImportCredentialSchemaClaimSchemaDTO> = vec![];
            for mut root_claim in claim_schemas {
                let data_type = self
                    .config
                    .datatype
                    .get_fields(&root_claim.datatype)
                    .error_while("checking claims")?
                    .r#type;
                if data_type != DatatypeType::Object || root_claim.array == Some(true) {
                    return Err(Error::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed);
                }

                let namespace = root_claim.key;
                add_mappings(&mut root_claim.claims, format, Some(&namespace), None);

                // prefix element-level DB key with the namespace in case of conflict with another namespace's element's key
                for element_claim in root_claim.claims.iter_mut() {
                    if result.iter().any(|another_namespace_element| {
                        another_namespace_element.key == element_claim.key
                    }) {
                        element_claim.key = format!("{namespace}_{}", element_claim.key);
                    }
                }

                result.extend(root_claim.claims);
            }

            return Ok(result);
        }

        add_mappings(&mut claim_schemas, format, None, None);
        Ok(claim_schemas)
    }

    pub(super) fn parse_all_claim_schemas_v2(
        &self,
        now: OffsetDateTime,
        claim_schemas: Vec<ImportCredentialSchemaClaimSchemaDTO>,
        formatters: &[(FormatType, Arc<dyn CredentialFormatter>)],
    ) -> Result<Vec<(ClaimSchema, Vec<CredentialClaimSchemaMappingDTO>)>, Error> {
        if claim_schemas.is_empty() {
            return Err(Error::MissingClaims);
        }
        self.parse_level_claim_schemas(now, None, claim_schemas, formatters)
    }

    pub(super) fn parse_level_claim_schemas(
        &self,
        now: OffsetDateTime,
        parent_key: Option<&str>,
        claim_schemas: Vec<ImportCredentialSchemaClaimSchemaDTO>,
        formatters: &[(FormatType, Arc<dyn CredentialFormatter>)],
    ) -> Result<Vec<(ClaimSchema, Vec<CredentialClaimSchemaMappingDTO>)>, Error> {
        self.validate_claim_schema_keys_unique(&claim_schemas)
            .error_while("checking claims")?;

        claim_schemas
            .into_iter()
            .map(|c| self.parse_claim_schema(now, parent_key, c, formatters))
            .flatten_ok()
            .try_collect()
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn parse_format_with_claim_mappings(
        &self,
        credential_schema_id: CredentialSchemaId,
        ecosystem_schema_id: String,
        format: CredentialFormat,
        now: OffsetDateTime,
        claim_schemas_to_mappings: &[(ClaimSchema, Vec<CredentialClaimSchemaMappingDTO>)],
        formatter: &dyn CredentialFormatter,
        metadata_claim_schemas: &mut IndexMap<String, ClaimSchema>,
    ) -> Result<CredentialSchemaFormat, Error> {
        let format_id = Uuid::new_v4().into();
        let uses_namespaces = formatter
            .get_capabilities()
            .features
            .contains(&Features::RequiresNamespaces);

        let mut mappings = vec![];
        for (claim_schema, claim_mappings) in claim_schemas_to_mappings {
            let mapping_for_format = claim_mappings.iter().find(|m| m.format == format);

            let technical_key = mapping_for_format
                .map(|m| m.technical_key.clone())
                .unwrap_or_else(|| claim_schema.key.clone());

            let namespace = if uses_namespaces {
                Some(
                    mapping_for_format
                        .ok_or(Error::MissingNamespace)?
                        .namespace
                        .as_ref()
                        .ok_or(Error::MissingNamespace)?
                        .to_owned(),
                )
            } else {
                None
            };

            mappings.push(CredentialSchemaFormatClaimSchema {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                credential_schema_format_id: format_id,
                claim_schema_id: claim_schema.id,
                technical_key,
                namespace,
            });
        }

        for metadata_claim in formatter.get_metadata_claims() {
            // the metadata claim could already have been created by a different formatter of the same type
            let claim_schema = metadata_claim_schemas
                .entry(metadata_claim.key.clone())
                .or_insert_with(|| claim_schema_from_metadata_claim_schema(metadata_claim, now));

            mappings.push(CredentialSchemaFormatClaimSchema {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                credential_schema_format_id: format_id,
                claim_schema_id: claim_schema.id,
                technical_key: claim_schema.key.clone(),
                namespace: None,
            });
        }

        Ok(CredentialSchemaFormat {
            id: format_id,
            created_date: now,
            last_modified: now,
            credential_schema_id,
            format,
            ecosystem_schema_id,
            claim_mappings: RelatedVec::from(mappings),
        })
    }

    pub(super) fn parse_claim_schema(
        &self,
        now: OffsetDateTime,
        parent_key: Option<&str>,
        claim_schema_dto: ImportCredentialSchemaClaimSchemaDTO,
        formatters: &[(FormatType, Arc<dyn CredentialFormatter>)],
    ) -> Result<Vec<(ClaimSchema, Vec<CredentialClaimSchemaMappingDTO>)>, Error> {
        self.validate_claim_schema_mappings_unique_formats(&claim_schema_dto)?;
        let mut flattened_claim_schemas = vec![];
        let key = claim_schema_dto.key.clone();
        let flattened_key =
            self.parse_claim_schema_key(parent_key, claim_schema_dto.key, formatters)?;
        let id = Uuid::new_v4().into();
        let translations = match &claim_schema_dto.translations {
            Some(t) => claim_name_translations_from_dto(id, t, now).into(),
            None => Default::default(),
        };
        let claim_schema = ClaimSchema {
            id,
            key: flattened_key.clone(),
            data_type: self.parse_claim_schema_datatype(
                &key,
                &claim_schema_dto.claims,
                claim_schema_dto.datatype,
                formatters,
            )?,
            created_date: now,
            last_modified: now,
            array: self.parse_claim_schema_array(&key, claim_schema_dto.array, formatters)?,
            metadata: false,
            required: claim_schema_dto.required,
            translations,
        };
        let mut childs = self.parse_level_claim_schemas(
            now,
            Some(&flattened_key),
            claim_schema_dto.claims,
            formatters,
        )?;

        flattened_claim_schemas.push((claim_schema, claim_schema_dto.mappings.unwrap_or_default()));
        flattened_claim_schemas.append(&mut childs);
        Ok(flattened_claim_schemas)
    }

    pub(super) fn parse_claim_schema_key(
        &self,
        parent_key: Option<&str>,
        key: String,
        formatters: &[(FormatType, Arc<dyn CredentialFormatter>)],
    ) -> Result<String, Error> {
        if key.find(NESTED_CLAIM_MARKER).is_some() {
            return Err(Error::ClaimSchemaSlashInKeyName(key));
        }
        if formatters
            .iter()
            .any(|(_, f)| f.get_capabilities().forbidden_claim_names.contains(&key))
        {
            return Err(Error::ForbiddenClaimName);
        }

        const MAX_KEY_LENGTH: usize = 255;
        let flattened_key = match parent_key {
            None => key,
            Some(parent_key) => format!("{parent_key}{NESTED_CLAIM_MARKER}{key}"),
        };
        if flattened_key.len() > MAX_KEY_LENGTH {
            return Err(Error::ClaimSchemaKeyTooLong);
        }
        Ok(flattened_key)
    }

    pub(super) fn parse_claim_schema_array(
        &self,
        claim_name: &str,
        is_array: Option<bool>,
        formatters: &[(FormatType, Arc<dyn CredentialFormatter>)],
    ) -> Result<bool, Error> {
        if let Some(true) = is_array {
            self.config
                .datatype
                .get_if_enabled("ARRAY")
                .error_while("checking claims")?;
            self.validate_datatype_formatter_capabilities(claim_name, "ARRAY", formatters)
                .error_while("checking claims")?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(super) fn parse_claim_schema_datatype(
        &self,
        claim_shema_key: &str,
        claim_schema_claims: &[ImportCredentialSchemaClaimSchemaDTO],
        claim_schema_data_type: String,
        formatters: &[(FormatType, Arc<dyn CredentialFormatter>)],
    ) -> Result<String, Error> {
        self.config
            .datatype
            .get_if_enabled(&claim_schema_data_type)
            .error_while("checking claims datatype")?;
        let claim_type = self
            .config
            .datatype
            .get_fields(&claim_schema_data_type)
            .error_while("checking claims datatype")?
            .r#type();
        self.validate_claim_schema_datatype(claim_shema_key, claim_type, claim_schema_claims)
            .error_while("checking claims datatype")?;
        self.validate_datatype_formatter_capabilities(
            claim_shema_key,
            &claim_schema_data_type,
            formatters,
        )
        .error_while("checking claims datatype")?;
        Ok(claim_schema_data_type)
    }

    pub(super) fn validate_claim_schema_datatype(
        &self,
        claim_shema_key: &str,
        claim_type: &DatatypeType,
        claim_schema_claims: &[ImportCredentialSchemaClaimSchemaDTO],
    ) -> Result<(), Error> {
        match claim_type {
            DatatypeType::Object => {
                if claim_schema_claims.is_empty() {
                    return Err(Error::MissingNestedClaims(claim_shema_key.to_owned()));
                }
            }
            _ => {
                if !claim_schema_claims.is_empty() {
                    return Err(Error::NestedClaimsShouldBeEmpty(claim_shema_key.to_owned()));
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_claim_schema_keys_unique(
        &self,
        claim_schemas: &[ImportCredentialSchemaClaimSchemaDTO],
    ) -> Result<(), Error> {
        if !claim_schemas.iter().map(|c| &c.key).all_unique() {
            return Err(Error::DuplicitClaim);
        }
        Ok(())
    }

    pub(super) fn validate_datatype_formatter_capabilities(
        &self,
        claim_name: &str,
        datatype: &str,
        formatters: &[(FormatType, Arc<dyn CredentialFormatter>)],
    ) -> Result<(), Error> {
        for (_, formatter) in formatters {
            if !formatter
                .get_capabilities()
                .datatypes
                .iter()
                .any(|d| d == datatype)
            {
                return Err(Error::ClaimSchemaUnsupportedDatatype {
                    claim_name: claim_name.to_owned(),
                    data_type: datatype.to_owned(),
                });
            };
        }
        Ok(())
    }

    fn validate_unique_formats(
        &self,
        formats: &[ImportCredentialSchemaV2FormatDTO],
    ) -> Result<(), Error> {
        if !formats.iter().map(|format| &format.format).all_unique() {
            return Err(Error::DuplicateFormats);
        }
        Ok(())
    }

    fn validate_claim_schema_mappings_unique_formats(
        &self,
        claim_schema: &ImportCredentialSchemaClaimSchemaDTO,
    ) -> Result<(), Error> {
        if !claim_schema
            .mappings
            .iter()
            .flatten()
            .map(|mapping| &mapping.format)
            .all_unique()
        {
            return Err(Error::DuplicateMappingFormats(claim_schema.key.clone()));
        }

        Ok(())
    }

    pub(super) fn parse_logo_properties(
        &self,
        logo: CredentialSchemaLogoPropertiesRequestDTO,
    ) -> Result<LogoProperties, Error> {
        match (logo.background_color, logo.font_color, logo.image) {
            (Some(background), Some(font), None) => Ok(LogoProperties {
                font_color: Some(font),
                background_color: Some(background),
                image: None,
            }),
            (None, None, Some(image)) => Ok(LogoProperties {
                font_color: None,
                background_color: None,
                image: Some(image.into()),
            }),
            _ => Err(Error::AttributeCombinationNotAllowed),
        }
    }

    pub(super) fn parse_background_properties(
        &self,
        background: CredentialSchemaBackgroundPropertiesRequestDTO,
    ) -> Result<BackgroundProperties, Error> {
        match (background.color, background.image) {
            (Some(color), None) => Ok(BackgroundProperties {
                color: Some(color),
                image: None,
            }),
            (None, Some(image)) => Ok(BackgroundProperties {
                color: None,
                image: Some(image.into()),
            }),
            _ => Err(Error::AttributeCombinationNotAllowed),
        }
    }

    pub(super) fn parse_layout_attribute(
        &self,
        attribute: String,
        claim_schemas: &[ClaimSchema],
        attribute_name: &str,
    ) -> Result<String, Error> {
        if claim_schemas.iter().any(|c| c.key == attribute) {
            Ok(attribute)
        } else {
            Err(Error::MissingLayoutAttribute(attribute_name.to_owned()))
        }
    }

    pub(super) fn parse_code_attribute(
        &self,
        code_properties: CredentialSchemaCodePropertiesDTO,
        claim_schemas: &[ClaimSchema],
    ) -> Result<CodeProperties, Error> {
        if claim_schemas
            .iter()
            .any(|c| c.key == code_properties.attribute)
        {
            Ok(CodeProperties {
                attribute: code_properties.attribute,
                r#type: code_properties.r#type,
            })
        } else {
            Err(Error::MissingLayoutAttribute("Code attribute".to_owned()))
        }
    }
}

fn add_mappings(
    claims: &mut [ImportCredentialSchemaClaimSchemaDTO],
    format: &CredentialFormat,
    namespace: Option<&String>,
    parent_technical_key: Option<&String>,
) {
    for claim in claims.iter_mut() {
        let technical_key = if let Some(parent_technical_key) = parent_technical_key {
            format!("{parent_technical_key}{NESTED_CLAIM_MARKER}{}", claim.key)
        } else {
            claim.key.to_string()
        };

        add_mappings(&mut claim.claims, format, namespace, Some(&technical_key));

        claim.mappings = Some(vec![CredentialClaimSchemaMappingDTO {
            format: format.to_owned(),
            technical_key,
            namespace: namespace.cloned(),
        }]);
    }
}

fn transform_mdoc_layout_properties_v1_to_v2(
    mut layout_properties: ImportCredentialSchemaLayoutPropertiesDTO,
) -> ImportCredentialSchemaLayoutPropertiesDTO {
    let remove_namespace = |path: Option<&mut String>| {
        if let Some(path) = path
            && let Some((_namespace, element_path)) = path.split_once(NESTED_CLAIM_MARKER)
        {
            *path = element_path.to_string();
        }
    };

    remove_namespace(layout_properties.primary_attribute.as_mut());
    remove_namespace(layout_properties.secondary_attribute.as_mut());
    remove_namespace(layout_properties.picture_attribute.as_mut());
    remove_namespace(
        layout_properties
            .code
            .as_mut()
            .map(|code| &mut code.attribute),
    );

    layout_properties
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use assert2::{assert, let_assert};
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::Error;
    use crate::config::core_config::{
        ConfigEntryDisplay, CoreConfig, DatatypeType, Fields, FormatType,
    };
    use crate::error::{ErrorCode, ErrorCodeMixin};
    use crate::model::claim_schema::ClaimSchema;
    use crate::model::credential_schema::CodeTypeEnum;
    use crate::proto::credential_schema::dto::{
        CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesDTO,
        CredentialSchemaLogoPropertiesRequestDTO, ImportCredentialSchemaClaimSchemaDTO,
        ImportCredentialSchemaLayoutPropertiesDTO,
    };
    use crate::proto::credential_schema::parser::CredentialSchemaImportParserImpl;
    use crate::provider::credential_formatter::model::{Features, FormatterCapabilities};
    use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
    use crate::provider::credential_formatter::{CredentialFormatter, MockCredentialFormatter};
    use crate::provider::revocation::MockRevocationMethod;
    use crate::provider::revocation::model::{Operation, RevocationMethodCapabilities};
    use crate::provider::revocation::provider::MockRevocationMethodProvider;
    use crate::service::test_utilities::{generic_config, get_dummy_date};

    fn setup_parser(
        config: CoreConfig,
        formatter_provider: MockCredentialFormatterProvider,
        revocation_method_provider: MockRevocationMethodProvider,
    ) -> CredentialSchemaImportParserImpl {
        CredentialSchemaImportParserImpl::new(
            Arc::new(config),
            Some("http://localhost".to_string()),
            Arc::new(formatter_provider),
            Arc::new(revocation_method_provider),
        )
    }

    #[test]
    fn test_parse_format_success() {
        // given
        let mut config = generic_config().core;
        config.format.insert(
            "JWT".into(),
            Fields {
                r#type: FormatType::Jwt,
                display: ConfigEntryDisplay::TranslationId("test".to_string()),
                order: None,
                priority: None,
                enabled: true,
                capabilities: None,
                params: None,
            },
        );

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_format("JWT".into());

        // then
        let_assert!(Ok(format) = result);
        assert_eq!("JWT", format.to_string());
    }

    #[test]
    fn test_parse_allow_suspension_success_true() {
        // given
        let mut revocation_method = MockRevocationMethod::default();
        revocation_method
            .expect_get_capabilities()
            .returning(|| RevocationMethodCapabilities {
                operations: vec![Operation::Suspend],
            });

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_allow_suspension(Some(true), Some(&revocation_method));

        // then
        let_assert!(Ok(true) = result);
    }

    #[test]
    fn test_parse_allow_suspension_success_false() {
        // given
        let mut revocation_method = MockRevocationMethod::default();
        revocation_method
            .expect_get_capabilities()
            .returning(|| RevocationMethodCapabilities {
                operations: vec![Operation::Suspend, Operation::Revoke],
            });

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_allow_suspension(Some(false), Some(&revocation_method));

        // then
        let_assert!(Ok(false) = result);
    }

    #[test]
    fn test_parse_allow_suspension_failure_not_available() {
        // given
        let mut revocation_method = MockRevocationMethod::default();
        revocation_method
            .expect_get_capabilities()
            .returning(|| RevocationMethodCapabilities { operations: vec![] });

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_allow_suspension(Some(true), Some(&revocation_method));

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0162);
    }

    #[test]
    fn test_parse_allow_suspension_failure_not_enabled_for_suspend_only() {
        // given
        let mut revocation_method = MockRevocationMethod::default();
        revocation_method
            .expect_get_capabilities()
            .returning(|| RevocationMethodCapabilities {
                operations: vec![Operation::Suspend],
            });

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_allow_suspension(Some(false), Some(&revocation_method));

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0191);
    }

    #[test]
    fn test_parse_schema_id_failure_empty_when_required() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                features: vec![Features::SupportsSchemaId],
                ..Default::default()
            });

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_schema_id("".to_string(), &formatter);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0138);
    }

    #[test]
    fn test_parse_layout_properties_success_none() {
        // given
        let formatter = MockCredentialFormatter::default();
        let formatters: Vec<(FormatType, Arc<dyn CredentialFormatter>)> =
            vec![(FormatType::SdJwtVc, Arc::new(formatter))];
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_layout_properties(None, &[], formatters.as_ref());

        // then
        let_assert!(Ok(None) = result);
    }

    #[test]
    fn test_parse_layout_properties_success() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                features: vec![Features::SupportsCredentialDesign],
                ..Default::default()
            });

        let formatters: Vec<(FormatType, Arc<dyn CredentialFormatter>)> =
            vec![(FormatType::SdJwtVc, Arc::new(formatter))];

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = crate::clock::now_utc();
        let claim_schemas = vec![ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "claim1".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        }];

        let layout_props = Some(ImportCredentialSchemaLayoutPropertiesDTO {
            background: None,
            logo: None,
            primary_attribute: Some("claim1".to_string()),
            secondary_attribute: None,
            picture_attribute: None,
            code: None,
        });

        // when
        let result =
            parser.parse_layout_properties(layout_props, &claim_schemas, formatters.as_ref());

        // then
        let_assert!(Ok(Some(props)) = result);
        assert!(Some("claim1".to_string()) == props.primary_attribute);
    }

    #[test]
    fn test_parse_layout_properties_failure_not_supported() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(FormatterCapabilities::default);

        let formatters: Vec<(FormatType, Arc<dyn CredentialFormatter>)> =
            vec![(FormatType::SdJwtVc, Arc::new(formatter))];

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let layout_props = Some(ImportCredentialSchemaLayoutPropertiesDTO {
            background: None,
            logo: None,
            primary_attribute: Some("claim1".to_string()),
            secondary_attribute: None,
            picture_attribute: None,
            code: None,
        });

        // when
        let result = parser.parse_layout_properties(layout_props, &[], formatters.as_ref());

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0131);
    }

    #[test]
    fn test_parse_layout_attribute_success() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = crate::clock::now_utc();
        let claim_schemas = vec![ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "claim1".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        }];

        // when
        let result = parser.parse_layout_attribute("claim1".to_string(), &claim_schemas, "primary");

        // then
        let_assert!(Ok(attribute) = result);
        assert!("claim1" == attribute);
    }

    #[test]
    fn test_parse_layout_attribute_failure_missing_claim() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_layout_attribute("nonexistent".to_string(), &[], "primary");

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0105);
    }

    #[test]
    fn test_parse_background_properties_success_color() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let bg = CredentialSchemaBackgroundPropertiesRequestDTO {
            color: Some("#FFFFFF".to_string()),
            image: None,
        };

        // when
        let result = parser.parse_background_properties(bg);

        // then
        let_assert!(Ok(props) = result);
        assert!(Some("#FFFFFF".to_string()) == props.color);
        let_assert!(None = props.image);
    }

    #[test]
    fn test_parse_background_properties_success_image() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let bg = CredentialSchemaBackgroundPropertiesRequestDTO {
            color: None,
            image: Some("data:image/png;base64,AAAA".to_string().try_into().unwrap()),
        };

        // when
        let result = parser.parse_background_properties(bg);

        // then
        let_assert!(Ok(props) = result);
        let_assert!(None = props.color);
        let_assert!(Some(image) = props.image);
        assert!("data:image/png;base64,AAAA" == image);
    }

    #[test]
    fn test_parse_background_properties_failure_both_set() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let bg = CredentialSchemaBackgroundPropertiesRequestDTO {
            color: Some("#FFFFFF".to_string()),
            image: Some("data:image/png;base64,AAAA".to_string().try_into().unwrap()),
        };

        // when
        let result = parser.parse_background_properties(bg);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0118);
    }

    #[test]
    fn test_parse_background_properties_failure_none_set() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let bg = CredentialSchemaBackgroundPropertiesRequestDTO {
            color: None,
            image: None,
        };

        // when
        let result = parser.parse_background_properties(bg);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0118);
    }

    #[test]
    fn test_parse_logo_properties_success_image() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let logo = CredentialSchemaLogoPropertiesRequestDTO {
            font_color: None,
            background_color: None,
            image: Some("data:image/png;base64,AAAA".to_string().try_into().unwrap()),
        };

        // when
        let result = parser.parse_logo_properties(logo);

        // then
        let_assert!(Ok(props) = result);
        let_assert!(Some(image) = props.image);
        assert!("data:image/png;base64,AAAA" == image);
        let_assert!(None = props.font_color);
        let_assert!(None = props.background_color);
    }

    #[test]
    fn test_parse_logo_properties_success_colors() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let logo = CredentialSchemaLogoPropertiesRequestDTO {
            font_color: Some("#000000".to_string()),
            background_color: Some("#FFFFFF".to_string()),
            image: None,
        };

        // when
        let result = parser.parse_logo_properties(logo);

        // then
        let_assert!(Ok(props) = result);
        let_assert!(None = props.image);
        let_assert!(Some(font_color) = props.font_color);
        assert!("#000000" == font_color);
        let_assert!(Some(background_color) = props.background_color);
        assert!("#FFFFFF" == background_color);
    }

    #[test]
    fn test_parse_logo_properties_failure_mixed() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let logo = CredentialSchemaLogoPropertiesRequestDTO {
            font_color: Some("#000000".to_string()),
            background_color: None,
            image: Some("data:image/png;base64,AAAA".to_string().try_into().unwrap()),
        };

        // when
        let result = parser.parse_logo_properties(logo);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0118);
    }

    #[test]
    fn test_parse_code_attribute_success() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = crate::clock::now_utc();
        let claim_schemas = vec![ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "code_claim".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        }];

        let code = CredentialSchemaCodePropertiesDTO {
            attribute: "code_claim".to_string(),
            r#type: CodeTypeEnum::Barcode,
        };

        // when
        let result = parser.parse_code_attribute(code, &claim_schemas);

        // then
        let_assert!(Ok(code) = result);
        assert!("code_claim" == code.attribute);
    }

    #[test]
    fn test_parse_code_attribute_failure_missing_claim() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let code = CredentialSchemaCodePropertiesDTO {
            attribute: "nonexistent".to_string(),
            r#type: CodeTypeEnum::Barcode,
        };

        // when
        let result = parser.parse_code_attribute(code, &[]);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0105);
    }

    #[test]
    fn test_parse_claim_schema_datatype_success_string() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                datatypes: vec!["STRING".into()],
                ..Default::default()
            });

        let formatters: Vec<(FormatType, Arc<dyn CredentialFormatter>)> =
            vec![(FormatType::SdJwtVc, Arc::new(formatter))];
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result =
            parser.parse_claim_schema_datatype("claim1", &[], "STRING".to_string(), &formatters);

        // then
        let_assert!(Ok(datatype) = result);
        assert!("STRING" == datatype);
    }

    #[test]
    fn test_parse_claim_schema_datatype_success_object() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                datatypes: vec!["STRING".into(), "OBJECT".into()],
                ..Default::default()
            });
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let formatters: Vec<(FormatType, Arc<dyn CredentialFormatter>)> =
            vec![(FormatType::SdJwtVc, Arc::new(formatter))];

        let claim_schema_claims = vec![ImportCredentialSchemaClaimSchemaDTO {
            id: Uuid::new_v4(),
            key: "inner_claim1".to_string(),
            datatype: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: false,
            array: None,
            claims: vec![],
            mappings: None,
            translations: None,
        }];

        // when
        let result = parser.parse_claim_schema_datatype(
            "claim1",
            &claim_schema_claims,
            "OBJECT".to_string(),
            &formatters,
        );

        // then
        let_assert!(Ok(datatype) = result);
        assert!("OBJECT" == datatype);
    }

    #[test]
    fn test_parse_claim_schema_datatype_failure_not_supported() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                datatypes: vec!["STRING".into()],
                ..Default::default()
            });

        let mut config = generic_config().core;
        config.datatype.insert(
            "STRING".to_string(),
            Fields {
                r#type: DatatypeType::String,
                display: ConfigEntryDisplay::TranslationId("test".to_string()),
                order: None,
                priority: None,
                enabled: true,
                capabilities: None,
                params: None,
            },
        );

        let parser = setup_parser(
            config,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let formatters: Vec<(FormatType, Arc<dyn CredentialFormatter>)> =
            vec![(FormatType::SdJwtVc, Arc::new(formatter))];

        // when
        let result = parser.parse_claim_schema_datatype(
            "claim1",
            &[],
            "INVALID_TYPE".to_string(),
            &formatters,
        );

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0089);
    }

    #[test]
    fn test_parse_claim_schema_array_success_true() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                datatypes: vec!["ARRAY".into()],
                ..Default::default()
            });

        let mut config = generic_config().core;
        config.datatype.insert(
            "ARRAY".to_string(),
            Fields {
                r#type: DatatypeType::Array,
                display: ConfigEntryDisplay::TranslationId("test".to_string()),
                order: None,
                priority: None,
                enabled: true,
                capabilities: None,
                params: None,
            },
        );

        let parser = setup_parser(
            config,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let formatters: Vec<(FormatType, Arc<dyn CredentialFormatter>)> =
            vec![(FormatType::SdJwtVc, Arc::new(formatter))];

        // when
        let result = parser.parse_claim_schema_array("claim1", Some(true), &formatters);

        // then
        let_assert!(Ok(is_array) = result);
        assert!(is_array);
    }

    #[test]
    fn test_parse_claim_schema_array_failure_not_supported() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(FormatterCapabilities::default);

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let formatters: Vec<(FormatType, Arc<dyn CredentialFormatter>)> =
            vec![(FormatType::SdJwtVc, Arc::new(formatter))];

        // when
        let result = parser.parse_claim_schema_array("claim1", Some(true), &formatters);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0089);
    }

    #[test]
    fn test_validate_claim_schema_keys_unique_success() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = crate::clock::now_utc();
        let claims = vec![
            ImportCredentialSchemaClaimSchemaDTO {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                key: "claim1".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
                mappings: None,
                translations: None,
            },
            ImportCredentialSchemaClaimSchemaDTO {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                key: "claim2".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
                mappings: None,
                translations: None,
            },
        ];

        // when
        let result = parser.validate_claim_schema_keys_unique(&claims);

        // then
        let_assert!(Ok(()) = result);
    }

    #[test]
    fn test_validate_claim_schema_keys_unique_failure() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = crate::clock::now_utc();
        let claims = vec![
            ImportCredentialSchemaClaimSchemaDTO {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                key: "claim1".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
                mappings: None,
                translations: None,
            },
            ImportCredentialSchemaClaimSchemaDTO {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                key: "claim1".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
                mappings: None,
                translations: None,
            },
        ];

        // when
        let result = parser.validate_claim_schema_keys_unique(&claims);

        // then
        let_assert!(Err(Error::DuplicitClaim) = result);
    }

    #[test]
    fn test_transform_claim_schemas_v1_to_v2_success_simple() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = crate::clock::now_utc();
        let claims = vec![ImportCredentialSchemaClaimSchemaDTO {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            key: "name".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
            mappings: None,
            translations: None,
        }];

        // when
        let result =
            parser.transform_claim_schemas_v1_to_v2(claims, FormatType::Jwt, &"JWT".into());

        // then
        let_assert!(Ok(schemas) = result);
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0].key, "name");
        assert_eq!(schemas[0].datatype, "STRING");
        assert!(schemas[0].required);

        let mappings = schemas[0].mappings.as_ref().unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].format, "JWT".into());
        assert_eq!(mappings[0].technical_key, "name");
        assert_eq!(mappings[0].namespace, None);
    }

    #[test]
    fn test_transform_claim_schemas_v1_to_v2_success_nested() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = crate::clock::now_utc();
        let claims = vec![ImportCredentialSchemaClaimSchemaDTO {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            key: "address".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            array: None,
            claims: vec![ImportCredentialSchemaClaimSchemaDTO {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                key: "street".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: None,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            mappings: None,
            translations: None,
        }];

        // when
        let result =
            parser.transform_claim_schemas_v1_to_v2(claims, FormatType::Jwt, &"JWT".into());

        // then
        let_assert!(Ok(schemas) = result);
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0].key, "address");
        assert_eq!(schemas[0].datatype, "OBJECT");
        assert!(schemas[0].required);

        let mappings = schemas[0].mappings.as_ref().unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].format, "JWT".into());
        assert_eq!(mappings[0].technical_key, "address");
        assert_eq!(mappings[0].namespace, None);

        let claims = &schemas[0].claims;
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].key, "street");
        assert_eq!(claims[0].datatype, "STRING");
        let mappings = claims[0].mappings.as_ref().unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].format, "JWT".into());
        assert_eq!(mappings[0].technical_key, "address/street");
        assert_eq!(mappings[0].namespace, None);
    }

    #[test]
    fn test_transform_claim_schemas_v1_to_v2_success_mdoc() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = crate::clock::now_utc();
        let claims = vec![ImportCredentialSchemaClaimSchemaDTO {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            key: "namespace".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            array: None,
            claims: vec![ImportCredentialSchemaClaimSchemaDTO {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                key: "element".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: None,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            mappings: None,
            translations: None,
        }];

        // when
        let result =
            parser.transform_claim_schemas_v1_to_v2(claims, FormatType::Mdoc, &"MDOC".into());

        // then
        let_assert!(Ok(schemas) = result);
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0].key, "element");
        assert_eq!(schemas[0].datatype, "STRING");
        assert!(schemas[0].required);
        assert_eq!(schemas[0].claims.len(), 0);

        let mappings = schemas[0].mappings.as_ref().unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].format, "MDOC".into());
        assert_eq!(mappings[0].technical_key, "element");
        assert_eq!(mappings[0].namespace.as_ref().unwrap(), "namespace");
    }

    #[test]
    fn test_transform_claim_schemas_v1_to_v2_failure_empty() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result =
            parser.transform_claim_schemas_v1_to_v2(vec![], FormatType::Jwt, &"JWT".into());

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0008);
    }

    #[test]
    fn test_parse_all_claim_schemas_failure_mdoc_non_object_top_level() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = crate::clock::now_utc();
        let claims = vec![ImportCredentialSchemaClaimSchemaDTO {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            key: "name".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: None,
            claims: vec![],
            mappings: None,
            translations: None,
        }];

        // when
        let result =
            parser.transform_claim_schemas_v1_to_v2(claims, FormatType::Mdoc, &"MDOC".into());

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0117);
    }
}
