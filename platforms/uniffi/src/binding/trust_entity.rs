use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};
use one_core::service::trust_entity::dto::{
    CreateRemoteTrustEntityRequestDTO, CreateTrustEntityRequestDTO, GetTrustEntitiesResponseDTO,
    GetTrustEntityResponseDTO, SortableTrustEntityColumnEnum, TrustEntitiesResponseItemDTO,
    UpdateTrustEntityActionFromDidRequestDTO, UpdateTrustEntityFromDidRequestDTO,
};
use one_dto_mapper::{convert_inner, try_convert_inner, From, Into, TryInto};

use super::common::SortDirection;
use super::did::DidListItemBindingDTO;
use super::mapper::OptionalString;
use super::trust_anchor::GetTrustAnchorResponseBindingDTO;
use super::OneCoreBinding;
use crate::error::{BindingError, ErrorResponseBindingDTO};
use crate::utils::{from_id_opt, into_id, into_id_opt, TimestampFormat};

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn create_trust_entity(
        &self,
        request: CreateTrustEntityRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        let core = self.use_core().await?;
        let id = core
            .trust_entity_service
            .create_trust_entity(request)
            .await?;
        Ok(id.to_string())
    }

    #[uniffi::method]
    pub async fn create_remote_trust_entity(
        &self,
        request: CreateRemoteTrustEntityRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .trust_entity_service
            .create_remote_trust_entity_for_did(request.try_into()?)
            .await?
            .to_string())
    }

    #[uniffi::method]
    pub async fn get_remote_trust_entity(
        &self,
        did_id: String,
    ) -> Result<GetTrustEntityResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .trust_entity_service
            .get_remote_trust_entity_for_did(into_id(&did_id)?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn update_remote_trust_entity(
        &self,
        request: UpdateRemoteTrustEntityFromDidRequestBindingDTO,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .trust_entity_service
            .update_remote_trust_entity_for_did(into_id(&request.did_id)?, request.try_into()?)
            .await?)
    }

    #[uniffi::method]
    pub async fn get_trust_entity(
        &self,
        trust_entity_id: String,
    ) -> Result<GetTrustEntityResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .trust_entity_service
            .get_trust_entity(into_id(&trust_entity_id)?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn get_trust_entity_by_did(
        &self,
        did_id: String,
    ) -> Result<GetTrustEntityResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let trust_entity = core
            .trust_entity_service
            .lookup_did(into_id(&did_id)?)
            .await?;

        Ok(trust_entity.into())
    }

    #[uniffi::method]
    pub async fn list_trust_entities(
        &self,
        filters: ListTrustEntitiesFiltersBindings,
    ) -> Result<TrustEntitiesListBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .trust_entity_service
            .list_trust_entities(filters.try_into()?)
            .await?
            .into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Into, uniffi::Enum)]
#[into(SortableTrustEntityColumnEnum)]
pub enum SortableTrustEntityColumnBindings {
    Name,
    Role,
    LastModified,
    State,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum ExactTrustEntityFilterColumnBindings {
    Name,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ListTrustEntitiesFiltersBindings {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableTrustEntityColumnBindings>,
    pub sort_direction: Option<SortDirection>,

    pub name: Option<String>,
    pub role: Option<TrustEntityRoleBindingEnum>,
    pub trust_anchor: Option<String>,
    pub did_id: Option<String>,
    pub organisation_id: Option<String>,

    pub exact: Option<Vec<ExactTrustEntityFilterColumnBindings>>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(TrustEntitiesResponseItemDTO)]
pub struct TrustEntitiesListItemResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub name: String,

    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub state: TrustEntityStateBindingEnum,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleBindingEnum,
    pub trust_anchor: GetTrustAnchorResponseBindingDTO,
    pub did: DidListItemBindingDTO,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetTrustEntitiesResponseDTO)]
pub struct TrustEntitiesListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<TrustEntitiesListItemResponseBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateTrustEntityRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct CreateTrustEntityRequestBindingDTO {
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn=try_convert_inner)]
    pub logo: Option<String>,
    #[try_into(infallible)]
    pub website: Option<String>,
    #[try_into(infallible)]
    pub terms_url: Option<String>,
    #[try_into(infallible)]
    pub privacy_url: Option<String>,
    #[try_into(infallible)]
    pub role: TrustEntityRoleBindingEnum,
    #[try_into(with_fn_ref = into_id)]
    pub trust_anchor_id: String,
    #[try_into(with_fn_ref = into_id)]
    pub did_id: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateRemoteTrustEntityRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct CreateRemoteTrustEntityRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub did_id: String,
    #[try_into(with_fn = into_id_opt)]
    pub trust_anchor_id: Option<String>,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn = try_convert_inner)]
    pub logo: Option<String>,
    #[try_into(infallible)]
    pub terms_url: Option<String>,
    #[try_into(infallible)]
    pub privacy_url: Option<String>,
    #[try_into(infallible)]
    pub website: Option<String>,
    #[try_into(infallible)]
    pub role: TrustEntityRoleBindingEnum,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(TrustEntityRole)]
#[into(TrustEntityRole)]
pub enum TrustEntityRoleBindingEnum {
    Issuer,
    Verifier,
    Both,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(TrustEntityState)]
#[into(TrustEntityState)]
pub enum TrustEntityStateBindingEnum {
    Active,
    Removed,
    Withdrawn,
    RemovedAndWithdrawn,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetTrustEntityResponseDTO)]
pub struct GetTrustEntityResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn = from_id_opt)]
    pub organisation_id: Option<String>,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleBindingEnum,
    pub trust_anchor: GetTrustAnchorResponseBindingDTO,
    pub did: DidListItemBindingDTO,
    pub state: TrustEntityStateBindingEnum,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(UpdateTrustEntityActionFromDidRequestDTO)]
pub enum TrustEntityUpdateActionBindingEnum {
    AdminActivate,
    Activate,
    Withdraw,
    Remove,
}

#[derive(TryInto, uniffi::Record)]
#[try_into(T = UpdateTrustEntityFromDidRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct UpdateRemoteTrustEntityFromDidRequestBindingDTO {
    #[try_into(skip)]
    pub did_id: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub action: Option<TrustEntityUpdateActionBindingEnum>,
    #[try_into(infallible)]
    pub name: Option<String>,
    #[try_into(with_fn = try_convert_inner)]
    pub logo: Option<OptionalString>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub website: Option<OptionalString>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub terms_url: Option<OptionalString>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub privacy_url: Option<OptionalString>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub role: Option<TrustEntityRoleBindingEnum>,
}
