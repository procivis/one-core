use std::collections::HashMap;

use proc_macros::Model;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{CredentialFormat, CredentialSchemaId, EcosystemId, RevocationMethodId};
use strum::Display;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use super::claim_schema::ClaimSchema;
use super::common::GetListResponse;
use super::list_query::ListQuery;
use super::organisation::Organisation;
use super::relation::{Related, RelatedVec};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::localized_text::LocalizedText;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, CredentialSchemaListIncludeEntityTypeEnum,
};
use crate::service::error::ServiceError;

pub type CredentialSchemaName = String;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct CredentialSchema {
    #[model(id)]
    pub id: CredentialSchemaId,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: CredentialSchemaName,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub layout_properties: Option<LayoutProperties>,
    pub imported_source_url: String,
    pub requires_wallet_instance_attestation: bool,
    pub transaction_code: Option<TransactionCode>,
    pub batch_size: Option<i32>,

    pub embedded_disclosure_policy: Option<String>,

    pub allow_revocation: bool,
    pub allow_suspension: bool,

    /// Administrative/business lifetime of credentials issued from this schema.
    /// `None` means an indefinite lifetime.
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,

    pub claim_schemas: RelatedVec<ClaimSchema>,
    pub organisation: Related<Organisation>,
    pub formats: RelatedVec<CredentialSchemaFormat>,
    pub translations: RelatedVec<LocalizedText>,
}

#[derive(Debug, Error)]
pub enum CredentialSchemaModelError {
    #[error("Unsupported key algorithm `{0}`")]
    UnsupportedKeyAlgorithmType(String),
}

impl ErrorCodeMixin for CredentialSchemaModelError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedKeyAlgorithmType(_) => ErrorCode::BR_0432,
        }
    }
}

impl CredentialSchema {
    // #[deprecated(note = "Use `formats` instead")] TODO: remove after we support multiformat schema
    pub async fn matches_schema_id(
        &self,
        other_schema_ids: &[String],
    ) -> Result<bool, NestedError> {
        Ok(self
            .get_formats()
            .await?
            .iter()
            .any(|f| other_schema_ids.contains(&f.schema_id)))
    }

    // #[deprecated(note = "Use `formats` instead")] TODO: remove after we support multiformat schema
    pub async fn format(&self) -> Result<CredentialFormat, NestedError> {
        Ok(self.first_format().await?.format)
    }

    // #[deprecated(note = "Use `formats` instead")] TODO: remove after we support multiformat schema
    pub async fn schema_id(&self) -> Result<String, NestedError> {
        Ok(self.first_format().await?.schema_id)
    }

    // #[deprecated(note = "Use `formats` instead")] TODO: remove after we support multiformat schema
    async fn first_format(&self) -> Result<CredentialSchemaFormat, NestedError> {
        self.get_formats()
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| {
                ServiceError::MappingError(format!(
                    "Credential schema {} has no credential schema format",
                    self.id
                ))
            })
            .error_while("Failed to retrieve credential format")
    }

    async fn get_formats(&self) -> Result<Vec<CredentialSchemaFormat>, NestedError> {
        Ok(self.formats.as_ref().await?.to_owned())
    }

    pub fn revocation_method_id<'a>(
        &'a self,
        format: &'a dyn CredentialFormatter,
    ) -> Option<&'a RevocationMethodId> {
        if self.allow_revocation || self.allow_suspension {
            return format.revocation_method_id();
        }

        None
    }
}

#[derive(Debug)]
pub(crate) struct CredentialSchemaClaimsNestedView {
    pub fields: HashMap<String, Arrayed<CredentialSchemaClaimsNestedTypeView>>,
}

#[derive(Debug)]
pub enum Arrayed<T> {
    InArray(T),
    Single(T),
}

#[derive(Debug)]
pub(crate) enum CredentialSchemaClaimsNestedTypeView {
    Field(ClaimSchema),
    Object(CredentialSchemaClaimsNestedObjectView),
}

#[derive(Debug)]
pub(crate) struct CredentialSchemaClaimsNestedObjectView {
    pub claim: ClaimSchema,
    pub fields: HashMap<String, Arrayed<CredentialSchemaClaimsNestedTypeView>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableCredentialSchemaColumn {
    Name,
    CreatedDate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialSchemaExactColumn {
    Name,
    SchemaId,
}

#[derive(
    Clone, Copy, Debug, Eq, Serialize, Deserialize, PartialEq, Display, Hash, PartialOrd, Ord,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyStorageSecurity {
    High,
    Moderate,
    EnhancedBasic,
    Basic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionCode {
    pub r#type: TransactionCodeType,
    pub length: u32,
    pub description: Option<String>,
}

#[derive(
    Clone, Copy, Debug, Eq, Serialize, Deserialize, PartialEq, Display, Hash, PartialOrd, Ord,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionCodeType {
    Numeric,
    Alphanumeric,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct LayoutProperties {
    pub background: Option<BackgroundProperties>,
    pub logo: Option<LogoProperties>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    pub code: Option<CodeProperties>,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundProperties {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogoProperties {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CodeProperties {
    pub attribute: String,
    pub r#type: CodeTypeEnum,
}

#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodeTypeEnum {
    Barcode,
    Mrz,
    QrCode,
}

pub type GetCredentialSchemaList = GetListResponse<CredentialSchema>;
pub type CredentialSchemaListQuery = ListQuery<
    SortableCredentialSchemaColumn,
    CredentialSchemaFilterValue,
    CredentialSchemaListIncludeEntityTypeEnum,
>;

#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UpdateCredentialSchemaRequest {
    pub claim_schemas: Option<Vec<ClaimSchema>>,
    pub claim_mappings: Option<Vec<CredentialSchemaFormatClaimSchema>>,
    pub layout_properties: Option<LayoutProperties>,
}
