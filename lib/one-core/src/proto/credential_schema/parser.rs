use std::sync::Arc;

use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialFormat, RevocationMethodId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::Error;
use super::dto::{
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesDTO,
    CredentialSchemaLogoPropertiesRequestDTO, ImportCredentialSchemaClaimSchemaDTO,
    ImportCredentialSchemaLayoutPropertiesDTO, ImportCredentialSchemaRequestDTO,
};
use crate::config::core_config::{ConfigExt, CoreConfig, DatatypeType, FormatType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{
    BackgroundProperties, CodeProperties, CredentialSchema, CredentialSchemaClaim,
    LayoutProperties, LayoutType, LogoProperties,
};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{Features, FormatterCapabilities};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::model::Operation;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::service::error::{BusinessLogicError, MissingProviderError, ValidationError};

pub(crate) struct CredentialSchemaImportParserImpl {
    config: Arc<CoreConfig>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait CredentialSchemaImportParser: Send + Sync {
    fn parse_import_credential_schema(
        &self,
        dto: ImportCredentialSchemaRequestDTO,
    ) -> Result<CredentialSchema, Error>;
}

impl CredentialSchemaImportParser for CredentialSchemaImportParserImpl {
    fn parse_import_credential_schema(
        &self,
        dto: ImportCredentialSchemaRequestDTO,
    ) -> Result<CredentialSchema, Error> {
        let now = OffsetDateTime::now_utc();
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&dto.schema.format)
            .ok_or(MissingProviderError::Formatter(
                dto.schema.format.to_string(),
            ))
            .error_while("getting formatter")?;
        let format = self
            .config
            .format
            .get_fields(&dto.schema.format)
            .error_while("getting format type")?
            .r#type();
        let revocation_method = match &dto.schema.revocation_method {
            Some(method_id) => Some(
                self.revocation_method_provider
                    .get_revocation_method(method_id)
                    .ok_or(MissingProviderError::RevocationMethod(method_id.clone()))
                    .error_while("getting revocation provider")?,
            ),
            None => None,
        };
        let claim_schemas =
            self.parse_all_claim_schemas(now, format, dto.schema.claims, formatter.as_ref())?;
        Ok(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: dto.schema.name,
            format: self.parse_format(dto.schema.format)?,
            revocation_method: self
                .parse_revocation_method(dto.schema.revocation_method, formatter.as_ref())?,
            key_storage_security: dto.schema.key_storage_security,
            layout_type: dto.schema.layout_type.unwrap_or(LayoutType::Card),
            layout_properties: self.parse_layout_properties(
                dto.schema.layout_properties,
                &claim_schemas,
                formatter.as_ref(),
            )?,
            schema_id: self.parse_schema_id(dto.schema.schema_id, formatter.as_ref())?,
            imported_source_url: dto.schema.imported_source_url,
            allow_suspension: self.parse_allow_suspension(
                dto.schema.allow_suspension,
                revocation_method.as_deref(),
            )?,
            requires_wallet_instance_attestation: dto
                .schema
                .requires_wallet_instance_attestation
                .unwrap_or(false),
            claim_schemas: Some(claim_schemas),
            organisation: Some(dto.organisation),
            transaction_code: convert_inner(dto.schema.transaction_code),
        })
    }
}

impl CredentialSchemaImportParserImpl {
    pub(crate) fn new(
        config: Arc<CoreConfig>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    ) -> Self {
        Self {
            config,
            formatter_provider,
            revocation_method_provider,
        }
    }

    fn parse_revocation_method(
        &self,
        revocation_method_type: Option<RevocationMethodId>,
        formatter: &dyn CredentialFormatter,
    ) -> Result<Option<RevocationMethodId>, Error> {
        let Some(revocation_method_type) = revocation_method_type else {
            return Ok(None);
        };

        let revocation_method_config = self
            .config
            .revocation
            .get_if_enabled(&revocation_method_type)
            .error_while("checking revocation")?;

        if formatter
            .get_capabilities()
            .revocation_methods
            .contains(revocation_method_config.r#type())
        {
            Ok(Some(revocation_method_type.clone()))
        } else {
            Err(
                BusinessLogicError::RevocationMethodNotCompatibleWithSelectedFormat
                    .error_while("checking revocation")
                    .into(),
            )
        }
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
                    return Err(
                        BusinessLogicError::SuspensionNotAvailableForSelectedRevocationMethod
                            .error_while("checking suspension")
                            .into(),
                    );
                }
            }
            _ => {
                if operations == vec![Operation::Suspend] {
                    return Err(
                        BusinessLogicError::SuspensionNotEnabledForSuspendOnlyRevocationMethod
                            .error_while("checking suspension")
                            .into(),
                    );
                }
            }
        };
        Ok(allow_suspension.unwrap_or(false))
    }

    pub(super) fn parse_layout_properties(
        &self,
        layout_properties: Option<ImportCredentialSchemaLayoutPropertiesDTO>,
        claim_schemas: &[CredentialSchemaClaim],
        formatter: &dyn CredentialFormatter,
    ) -> Result<Option<LayoutProperties>, Error> {
        if layout_properties.is_some()
            && !formatter
                .get_capabilities()
                .features
                .contains(&Features::SupportsCredentialDesign)
        {
            return Err(BusinessLogicError::LayoutPropertiesNotSupported
                .error_while("checking design")
                .into());
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
        schema_id: String,
        formatter: &dyn CredentialFormatter,
    ) -> Result<String, Error> {
        let FormatterCapabilities {
            features,
            allowed_schema_ids,
            ..
        } = formatter.get_capabilities();

        let is_schema_id_required = features.contains(&Features::SupportsSchemaId);
        if is_schema_id_required && schema_id.is_empty() {
            return Err(BusinessLogicError::MissingSchemaId
                .error_while("checking schemaId")
                .into());
        }

        if !allowed_schema_ids.is_empty() && !allowed_schema_ids.iter().any(|v| v == &schema_id) {
            return Err(ValidationError::SchemaIdNotAllowedForFormat
                .error_while("checking schemaId")
                .into());
        }
        Ok(schema_id)
    }

    pub(super) fn parse_format(&self, format: CredentialFormat) -> Result<CredentialFormat, Error> {
        self.config
            .format
            .get_if_enabled(&format)
            .error_while("checking format")?;
        Ok(format)
    }

    pub(super) fn parse_all_claim_schemas(
        &self,
        now: OffsetDateTime,
        format: &FormatType,
        claim_schemas: Vec<ImportCredentialSchemaClaimSchemaDTO>,
        formatter: &dyn CredentialFormatter,
    ) -> Result<Vec<CredentialSchemaClaim>, Error> {
        if claim_schemas.is_empty() {
            return Err(ValidationError::CredentialSchemaMissingClaims
                .error_while("checking claims")
                .into());
        }
        self.validate_top_level_claims_mdoc_types(format, &claim_schemas)?;
        self.parse_level_claim_schemas(now, None, claim_schemas, formatter)
    }

    pub(super) fn parse_level_claim_schemas(
        &self,
        now: OffsetDateTime,
        parent_key: Option<&str>,
        claim_schemas: Vec<ImportCredentialSchemaClaimSchemaDTO>,
        formatter: &dyn CredentialFormatter,
    ) -> Result<Vec<CredentialSchemaClaim>, Error> {
        self.validate_claim_schema_keys_unique(&claim_schemas)
            .error_while("checking claims")?;

        claim_schemas
            .into_iter()
            .map(|c| self.parse_claim_schema(now, parent_key, c, formatter))
            .flatten_ok()
            .try_collect()
    }

    pub(super) fn parse_claim_schema(
        &self,
        now: OffsetDateTime,
        parent_key: Option<&str>,
        claim_schema_dto: ImportCredentialSchemaClaimSchemaDTO,
        formatter: &dyn CredentialFormatter,
    ) -> Result<Vec<CredentialSchemaClaim>, Error> {
        let mut flattened_claim_schemas = vec![];
        let key = claim_schema_dto.key.clone();
        let flattened_key =
            self.parse_claim_schema_key(parent_key, claim_schema_dto.key, formatter)?;
        let claim_schema = CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: flattened_key.clone(),
                data_type: self.parse_claim_schema_datatype(
                    &key,
                    &claim_schema_dto.claims,
                    claim_schema_dto.datatype,
                    formatter,
                )?,
                created_date: now,
                last_modified: now,
                array: self.parse_claim_schema_array(&key, claim_schema_dto.array, formatter)?,
                metadata: false,
            },
            required: claim_schema_dto.required,
        };
        let mut childs = self.parse_level_claim_schemas(
            now,
            Some(&flattened_key),
            claim_schema_dto.claims,
            formatter,
        )?;

        flattened_claim_schemas.push(claim_schema);
        flattened_claim_schemas.append(&mut childs);
        Ok(flattened_claim_schemas)
    }

    pub(super) fn parse_claim_schema_key(
        &self,
        parent_key: Option<&str>,
        key: String,
        formatter: &dyn CredentialFormatter,
    ) -> Result<String, Error> {
        if key.find(NESTED_CLAIM_MARKER).is_some() {
            return Err(
                ValidationError::CredentialSchemaClaimSchemaSlashInKeyName(key)
                    .error_while("checking claims")
                    .into(),
            );
        }
        if formatter
            .get_capabilities()
            .forbidden_claim_names
            .contains(&key)
        {
            return Err(ValidationError::ForbiddenClaimName
                .error_while("checking claims")
                .into());
        }

        const MAX_KEY_LENGTH: usize = 255;
        let flattened_key = match parent_key {
            None => key,
            Some(parent_key) => format!("{parent_key}{NESTED_CLAIM_MARKER}{key}"),
        };
        if flattened_key.len() > MAX_KEY_LENGTH {
            return Err(BusinessLogicError::ClaimSchemaKeyTooLong
                .error_while("checking claims")
                .into());
        }
        Ok(flattened_key)
    }

    pub(super) fn parse_claim_schema_array(
        &self,
        claim_name: &str,
        is_array: Option<bool>,
        formatter: &dyn CredentialFormatter,
    ) -> Result<bool, Error> {
        if let Some(true) = is_array {
            self.config
                .datatype
                .get_if_enabled("ARRAY")
                .error_while("checking claims")?;
            self.validate_datatype_formatter_capabilities(claim_name, "ARRAY", formatter)
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
        formatter: &dyn CredentialFormatter,
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
            formatter,
        )
        .error_while("checking claims datatype")?;
        Ok(claim_schema_data_type)
    }

    pub(super) fn validate_claim_schema_datatype(
        &self,
        claim_shema_key: &str,
        claim_type: &DatatypeType,
        claim_schema_claims: &[ImportCredentialSchemaClaimSchemaDTO],
    ) -> Result<(), ValidationError> {
        match claim_type {
            DatatypeType::Object => {
                if claim_schema_claims.is_empty() {
                    return Err(ValidationError::CredentialSchemaMissingNestedClaims(
                        claim_shema_key.to_owned(),
                    ));
                }
            }
            _ => {
                if !claim_schema_claims.is_empty() {
                    return Err(ValidationError::CredentialSchemaNestedClaimsShouldBeEmpty(
                        claim_shema_key.to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_claim_schema_keys_unique(
        &self,
        claim_schemas: &[ImportCredentialSchemaClaimSchemaDTO],
    ) -> Result<(), ValidationError> {
        if !claim_schemas.iter().map(|c| &c.key).all_unique() {
            return Err(ValidationError::CredentialSchemaDuplicitClaim);
        }
        Ok(())
    }

    pub(super) fn validate_datatype_formatter_capabilities(
        &self,
        claim_name: &str,
        datatype: &str,
        formatter: &dyn CredentialFormatter,
    ) -> Result<(), ValidationError> {
        if !formatter
            .get_capabilities()
            .datatypes
            .iter()
            .any(|d| d == datatype)
        {
            return Err(
                ValidationError::CredentialSchemaClaimSchemaUnsupportedDatatype {
                    claim_name: claim_name.to_owned(),
                    data_type: datatype.to_owned(),
                },
            );
        };
        Ok(())
    }

    pub(super) fn validate_top_level_claims_mdoc_types(
        &self,
        format_type: &FormatType,
        claim_schemas: &[ImportCredentialSchemaClaimSchemaDTO],
    ) -> Result<(), Error> {
        if *format_type != FormatType::Mdoc {
            return Ok(());
        }

        for claim in claim_schemas {
            let data_type = self
                .config
                .datatype
                .get_fields(&claim.datatype)
                .error_while("checking claims")?
                .r#type;
            if data_type != DatatypeType::Object {
                return Err(
                    BusinessLogicError::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed
                        .error_while("checking claims")
                        .into(),
                );
            }
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
            _ => Err(ValidationError::AttributeCombinationNotAllowed
                .error_while("checking logo")
                .into()),
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
            _ => Err(ValidationError::AttributeCombinationNotAllowed
                .error_while("checking background")
                .into()),
        }
    }

    pub(super) fn parse_layout_attribute(
        &self,
        attribute: String,
        claim_schemas: &[CredentialSchemaClaim],
        attribute_name: &str,
    ) -> Result<String, Error> {
        tracing::debug!(
            "{:?} {:?} {:?}",
            &attribute,
            &claim_schemas,
            &attribute_name
        );
        if claim_schemas.iter().any(|c| c.schema.key == attribute) {
            Ok(attribute)
        } else {
            Err(
                ValidationError::MissingLayoutAttribute(attribute_name.to_owned())
                    .error_while("checking layout")
                    .into(),
            )
        }
    }

    pub(super) fn parse_code_attribute(
        &self,
        code_properties: CredentialSchemaCodePropertiesDTO,
        claim_schemas: &[CredentialSchemaClaim],
    ) -> Result<CodeProperties, Error> {
        if claim_schemas
            .iter()
            .any(|c| c.schema.key == code_properties.attribute)
        {
            Ok(CodeProperties {
                attribute: code_properties.attribute,
                r#type: code_properties.r#type,
            })
        } else {
            Err(
                ValidationError::MissingLayoutAttribute("Code attribute".to_owned())
                    .error_while("checking code")
                    .into(),
            )
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use assert2::{assert, let_assert};
    use similar_asserts::assert_eq;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::config::core_config::{
        ConfigEntryDisplay, CoreConfig, DatatypeType, Fields, FormatType, RevocationType,
    };
    use crate::error::{ErrorCode, ErrorCodeMixin};
    use crate::model::claim_schema::ClaimSchema;
    use crate::model::credential_schema::{CodeTypeEnum, CredentialSchemaClaim};
    use crate::proto::credential_schema::dto::{
        CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesDTO,
        CredentialSchemaLogoPropertiesRequestDTO, ImportCredentialSchemaClaimSchemaDTO,
        ImportCredentialSchemaLayoutPropertiesDTO,
    };
    use crate::proto::credential_schema::parser::CredentialSchemaImportParserImpl;
    use crate::provider::credential_formatter::MockCredentialFormatter;
    use crate::provider::credential_formatter::model::{Features, FormatterCapabilities};
    use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
    use crate::provider::revocation::MockRevocationMethod;
    use crate::provider::revocation::model::{Operation, RevocationMethodCapabilities};
    use crate::provider::revocation::provider::MockRevocationMethodProvider;
    use crate::service::error::ValidationError;
    use crate::service::test_utilities::{generic_config, get_dummy_date};

    fn setup_parser(
        config: CoreConfig,
        formatter_provider: MockCredentialFormatterProvider,
        revocation_method_provider: MockRevocationMethodProvider,
    ) -> CredentialSchemaImportParserImpl {
        CredentialSchemaImportParserImpl::new(
            Arc::new(config),
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
    fn test_parse_revocation_method_success() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                revocation_methods: vec![RevocationType::Lvvc],
                ..Default::default()
            });

        let mut config = generic_config().core;
        config.revocation.insert(
            "LVVC".into(),
            Fields {
                r#type: RevocationType::Lvvc,
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

        // when
        let result = parser.parse_revocation_method(Some("LVVC".to_owned().into()), &formatter);

        // then
        let_assert!(Ok(revocation_method) = result);
        assert_eq!(revocation_method, Some("LVVC".to_owned().into()));
    }

    #[test]
    fn test_parse_revocation_method_failure_not_found() {
        // given
        let formatter = MockCredentialFormatter::default();
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_revocation_method(Some("INVALID".to_owned().into()), &formatter);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0051);
    }

    #[test]
    fn test_parse_revocation_method_failure_incompatible() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                revocation_methods: vec![RevocationType::Lvvc],
                ..Default::default()
            });

        let mut config = generic_config().core;
        config.revocation.insert(
            "BITSTRINGSTATUSLIST".into(),
            Fields {
                r#type: RevocationType::BitstringStatusList,
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
        let result = parser
            .parse_revocation_method(Some("BITSTRINGSTATUSLIST".to_owned().into()), &formatter);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0110);
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
    fn test_parse_schema_id_success() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                allowed_schema_ids: vec!["TEST_SCHEMA_ID".to_string()],
                ..Default::default()
            });

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_schema_id("TEST_SCHEMA_ID".to_string(), &formatter);

        // then
        let_assert!(Ok(schema_id) = result);
        assert!("TEST_SCHEMA_ID" == schema_id);
    }

    #[test]
    fn test_parse_schema_id_failure_not_allowed() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                allowed_schema_ids: vec!["TEST_SCHEMA_ID".to_string()],
                ..Default::default()
            });

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_schema_id("OTHER_TEST_SCHEMA_ID".to_string(), &formatter);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0146);
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
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result = parser.parse_layout_properties(None, &[], &formatter);

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

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = OffsetDateTime::now_utc();
        let claim_schemas = vec![CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "claim1".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
                array: false,
                metadata: false,
            },
            required: true,
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
        let result = parser.parse_layout_properties(layout_props, &claim_schemas, &formatter);

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
        let result = parser.parse_layout_properties(layout_props, &[], &formatter);

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

        let now = OffsetDateTime::now_utc();
        let claim_schemas = vec![CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "claim1".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
                array: false,
                metadata: false,
            },
            required: true,
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

        let now = OffsetDateTime::now_utc();
        let claim_schemas = vec![CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "code_claim".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
                array: false,
                metadata: false,
            },
            required: true,
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

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        // when
        let result =
            parser.parse_claim_schema_datatype("claim1", &[], "STRING".to_string(), &formatter);

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

        let claim_schema_claims = vec![ImportCredentialSchemaClaimSchemaDTO {
            id: Uuid::new_v4(),
            key: "inner_claim1".to_string(),
            datatype: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: false,
            array: None,
            claims: vec![],
        }];

        // when
        let result = parser.parse_claim_schema_datatype(
            "claim1",
            &claim_schema_claims,
            "OBJECT".to_string(),
            &formatter,
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

        // when
        let result = parser.parse_claim_schema_datatype(
            "claim1",
            &[],
            "INVALID_TYPE".to_string(),
            &formatter,
        );

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0051);
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

        // when
        let result = parser.parse_claim_schema_array("claim1", Some(true), &formatter);

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

        // when
        let result = parser.parse_claim_schema_array("claim1", Some(true), &formatter);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0051);
    }

    #[test]
    fn test_validate_claim_schema_keys_unique_success() {
        // given
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = OffsetDateTime::now_utc();
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

        let now = OffsetDateTime::now_utc();
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
            },
        ];

        // when
        let result = parser.validate_claim_schema_keys_unique(&claims);

        // then
        let_assert!(Err(ValidationError::CredentialSchemaDuplicitClaim) = result);
    }

    #[test]
    fn test_parse_all_claim_schemas_success_simple() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                datatypes: vec!["STRING".into()],
                ..Default::default()
            });

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = OffsetDateTime::now_utc();
        let claims = vec![ImportCredentialSchemaClaimSchemaDTO {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            key: "name".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
        }];

        // when
        let result = parser.parse_all_claim_schemas(now, &FormatType::Jwt, claims, &formatter);

        // then
        let_assert!(Ok(schemas) = result);
        assert!(1 == schemas.len());
        assert!("name" == schemas[0].schema.key);
        assert!("STRING" == schemas[0].schema.data_type);
        assert!(schemas[0].required);
    }

    #[test]
    fn test_parse_all_claim_schemas_success_nested() {
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

        let now = OffsetDateTime::now_utc();
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
            }],
        }];

        // when
        let result = parser.parse_all_claim_schemas(now, &FormatType::Jwt, claims, &formatter);

        // then
        let_assert!(Ok(schemas) = result);
        assert!(2 == schemas.len());
        assert!("address" == schemas[0].schema.key);
        assert!("address/street" == schemas[1].schema.key);
    }

    #[test]
    fn test_parse_all_claim_schemas_failure_empty() {
        // given
        let formatter = MockCredentialFormatter::default();
        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = OffsetDateTime::now_utc();

        // when
        let result = parser.parse_all_claim_schemas(now, &FormatType::Jwt, vec![], &formatter);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0008);
    }

    #[test]
    fn test_parse_all_claim_schemas_failure_mdoc_non_object_top_level() {
        // given
        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .returning(|| FormatterCapabilities {
                datatypes: vec!["STRING".into()],
                ..Default::default()
            });

        let parser = setup_parser(
            generic_config().core,
            MockCredentialFormatterProvider::default(),
            MockRevocationMethodProvider::new(),
        );

        let now = OffsetDateTime::now_utc();
        let claims = vec![ImportCredentialSchemaClaimSchemaDTO {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            key: "name".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: None,
            claims: vec![],
        }];

        // when
        let result = parser.parse_all_claim_schemas(now, &FormatType::Mdoc, claims, &formatter);

        // then
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0117);
    }
}
