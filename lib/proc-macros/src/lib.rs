use proc_macro::TokenStream;

mod options_not_nullable;
mod permission_check;

/// Marks all optional fields in the struct as `#[schema(nullable = false)]` and also adds a
/// `#[serde_with::skip_serializing_none]` to the struct.
/// The latter can be disabled by setting `skip_serializing_none = false`
///
/// The attribute can be added to structs and enums.
/// The `#[skip_serializing_none]` attribute must be placed *before* the `#[derive]` attribute.
///
/// ```rust
/// use proc_macros::options_not_nullable;
/// use utoipa::{ToSchema};
/// use serde::Serialize;
///
/// #[allow(dead_code)]
/// #[options_not_nullable]
/// #[derive(Serialize, ToSchema)]
/// struct Data {
///     a: Option<String>,
/// }
///
/// #[allow(dead_code)]
/// #[options_not_nullable(skip_serializing_none = false)]
/// #[derive(Serialize, ToSchema)]
/// struct DataNoSerdeSkip {
///     a: Option<String>,
/// }
/// ```
///
/// # Limitations
///
/// Must only be used on structs and enums that derive `utoipa::ToSchema` and either
/// `serde::Serialize` or `serde::Deserialize`.
///
/// The `options_not_nullable` only works if the type is called `Option`,
/// `std::option::Option`, or `core::option::Option`. Type aliasing an [`Option`] and giving it
/// another name, will cause this field to be ignored. This cannot be supported, as proc-macros run
/// before type checking, thus it is not possible to determine if a type alias refers to an
/// [`Option`].
#[proc_macro_attribute]
pub fn options_not_nullable(args: TokenStream, input: TokenStream) -> TokenStream {
    options_not_nullable::options_not_nullable(args, input)
}

/// Add permission check to request handler. Only usable within the `one-core` crate, as it assumes
/// the existence of the `permission_check` function.
///
/// # Usage
///
/// ```ignore
/// #[require_permissions(Permission::DummyPermission, Permission::DummyPermission2)]
/// pub(crate) async fn post_request(
///     state: State<AppState>,
///     WithRejection(Json(request), _): WithRejection<Json<RequestRestDTO>, ErrorResponseRestDTO>,
/// ) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
///     todo!(handler code)
/// }
/// ```
///
/// # Limitations
/// Takes a list of `Permission` enum variants as arguments, anything is valid that could also be
/// passed to `vec![]`.
/// The handler must not already have an argument called `authorized` and must return any
/// `<HappyCase>OrErrorResponse` DTO.
#[proc_macro_attribute]
pub fn require_permissions(args: TokenStream, input: TokenStream) -> TokenStream {
    permission_check::require_permissions(args, input)
}
