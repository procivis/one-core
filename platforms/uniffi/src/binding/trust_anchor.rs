use one_core::service::trust_anchor::dto::{
    CreateTrustAnchorRequestDTO, GetTrustAnchorDetailResponseDTO, GetTrustAnchorsResponseDTO,
    SortableTrustAnchorColumn, TrustAnchorsListItemResponseDTO,
};
use one_dto_mapper::{convert_inner, From, Into};
use shared_types::TrustAnchorId;

use super::common::SortDirection;
use super::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::{into_id, TimestampFormat};

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn create_trust_anchor(
        &self,
        anchor: CreateTrustAnchorRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = anchor.into();

        let core = self.use_core().await?;
        let id = core
            .trust_anchor_service
            .create_trust_anchor(request)
            .await?;
        Ok(id.to_string())
    }

    #[uniffi::method]
    pub async fn get_trust_anchor(
        &self,
        trust_anchor_id: String,
    ) -> Result<GetTrustAnchorResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .trust_anchor_service
            .get_trust_anchor(into_id(&trust_anchor_id)?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn list_trust_anchors(
        &self,
        filters: ListTrustAnchorsFiltersBindings,
    ) -> Result<TrustAnchorsListBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .trust_anchor_service
            .list_trust_anchors(filters.try_into()?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn delete_trust_anchor(&self, anchor_id: String) -> Result<(), BindingError> {
        let trust_anchor_id: TrustAnchorId = into_id(&anchor_id)?;

        let core = self.use_core().await?;
        Ok(core
            .trust_anchor_service
            .delete_trust_anchor(trust_anchor_id)
            .await?)
    }
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(CreateTrustAnchorRequestDTO)]
pub struct CreateTrustAnchorRequestBindingDTO {
    pub name: String,
    pub r#type: String,
    pub is_publisher: Option<bool>,
    pub publisher_reference: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetTrustAnchorDetailResponseDTO)]
pub struct GetTrustAnchorResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub name: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub r#type: String,
    pub is_publisher: bool,
    pub publisher_reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, uniffi::Enum)]
#[into(SortableTrustAnchorColumn)]
pub enum SortableTrustAnchorColumnBindings {
    Name,
    CreatedDate,
    Type,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum ExactTrustAnchorFilterColumnBindings {
    Name,
    Type,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ListTrustAnchorsFiltersBindings {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableTrustAnchorColumnBindings>,
    pub sort_direction: Option<SortDirection>,

    pub name: Option<String>,
    pub is_publisher: Option<bool>,
    pub r#type: Option<String>,

    pub exact: Option<Vec<ExactTrustAnchorFilterColumnBindings>>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(TrustAnchorsListItemResponseDTO)]
pub struct TrustAnchorsListItemResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub name: String,

    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,

    pub r#type: String,
    pub is_publisher: bool,
    pub publisher_reference: String,
    pub entities: u64,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetTrustAnchorsResponseDTO)]
pub struct TrustAnchorsListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<TrustAnchorsListItemResponseBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}
