#![allow(clippy::indexing_slicing)]

use proc_macro::TokenStream;

mod modify_schema;
mod modify_schema_autodetect;
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
/// #[expect(dead_code)]
/// #[options_not_nullable]
/// #[derive(Serialize, ToSchema)]
/// struct Data {
///     a: Option<String>,
/// }
///
/// #[expect(dead_code)]
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

/// Derive macro: `#[derive(ModifySchema)]` with `#[modify_schema(...)]` attributes
///
/// Purpose
/// - Generate an implementation of a schema-modification trait for types whose OpenAPI schema
///   must depend on runtime configuration.
/// - The derive inspects either:
///   - Structs: selected fields annotated with `#[modify_schema(allowed_values_fn = path::to::fn)]` or `#[modify_schema(field = field_of_core_config)]`,
///     and updates each field’s `allowed_values` values dynamically.
///   - Enums: the whole enum annotated with `#[modify_schema(allowed_values_fn = path::to::fn)]`,
///     and updates the type’s `allowed_values` values dynamically.
///
/// High-level behavior
/// - For structs with named fields:
///   - For every field carrying `#[modify_schema(allowed_values_fn = ...)]`, generated code:
///     - Reads the current `allowed_values` values from the field’s schema object,
///     - Calls your provided function with `(core_config, old_enum_values)`,
///     - Writes back the returned `allowed_values` values.
///   - For every field carrying `#[modify_schema(field = ...)]`, generated code:
///     - Reads provided field from `core_config` and transforms it to valid format,
///     - Writes back the returned `allowed_values` values.
/// - For enums with the attribute at the type level:
///   - Generated code performs the same update at the type’s schema object level.
///
/// The generated impl (conceptual)
/// - For each annotated type `T`, this derive emits an implementation equivalent to:
///   - `impl crate::openapi::CoreConfigModifySchema for T { fn core_config_modify_schema(core_config: &one_core::config::core_config::CoreConfig, object: &mut utoipa::openapi::Object) { /* mutate enum_values */ } }`
/// - Structs: mutates `object.properties["field_name"]` when the field is annotated.
/// - Enums: mutates `object.enum_values` directly when the enum is annotated.
///
/// Example usage (struct fields)
/// ```ignore
/// use serde::Serialize;
/// use utoipa::ToSchema;
///
/// // Your function decides allowed values from core_config and the previously generated values.
/// // Signature must match: fn(&CoreConfig, Option<Vec<utoipa::openapi::schema::SchemaTypeValue>>) -> Option<Vec<...>>
/// fn allowed_colors(
///     core: &one_core::config::core_config::CoreConfig,
///     old: Option<Vec<utoipa::openapi::Value>>,
/// ) -> Option<Vec<utoipa::openapi::Value>> {
///     let mut values = old.unwrap_or_default();
///     if core.feature.enable_extra_colors {
///         values.push(utoipa::openapi::Value::from("magenta"));
///     }
///     Some(values)
/// }
///
/// #[derive(Serialize, ToSchema, ModifySchema)]
/// struct PaintRequest {
///     #[modify_schema(allowed_values_fn = crate::allowed_colors)]
///     color: String,
///     #[modify_schema(field = producers)]
///     producer: String
///     amount_liters: u32,
/// }
/// ```
///
/// Example usage (enum)
/// ```ignore
/// use serde::Serialize;
/// use utoipa::ToSchema;
///
/// fn allowed_kinds(
///     _core: &one_core::config::core_config::CoreConfig,
///     _old: Option<Vec<utoipa::openapi::Value>>,
/// ) -> Option<Vec<utoipa::openapi::Value>> {
///     Some(vec!["basic".into(), "premium".into()])
/// }
///
/// #[derive(Serialize, ToSchema, ModifySchema)]
/// #[modify_schema(allowed_values_fn = crate::allowed_kinds)]
/// enum PackageKind {
///     Basic,
///     Premium,
///     // Enum variants themselves are not inspected; `allowed_kinds` defines the enum values.
/// }
/// ```
///
/// Resulting output (what the derive adds)
/// - An impl of `crate::openapi::CoreConfigModifySchema` for your type.
/// - A function `core_config_modify_schema(&CoreConfig, &mut utoipa::openapi::Object)` that:
///   - For structs: visits fields marked with `#[modify_schema(allowed_values_fn = ...)]`,
///     and updates the field schema’s `enum_values`.
///   - For structs: visits fields marked with `#[modify_schema(field = ...)]`,
///     and updates the field schema’s `enum_values`.
///   - For enums: updates the type schema’s `enum_values`.
///
/// Limitations and requirements
/// - The following symbols must exist and be accessible where the generated code is compiled:
///   - Trait: `crate::openapi::CoreConfigModifySchema` with method
///     `fn core_config_modify_schema(&one_core::config::core_config::CoreConfig, &mut utoipa::openapi::Object)`.
///   - Type: `one_core::config::core_config::CoreConfig`.
///   - Types from `utoipa::openapi`, in particular `Object` and `Value` used in `enum_values`.
/// - The attribute parameter `allowed_values_fn` must be a path to a function with the signature:
///   `fn(&one_core::config::core_config::CoreConfig, Option<Vec<utoipa::openapi::Value>>) -> Option<Vec<utoipa::openapi::Value>>`
///   (the exact `Value` element type should match what your `utoipa` version uses to represent enum values).
/// - Only named struct fields are supported; unit structs and tuple structs are ignored.
/// - For structs, only fields explicitly annotated are modified; other fields are untouched.
/// - The derive does not rename schemas or properties; it relies on the property identifier names
///   as they appear in the OpenAPI object’s `properties` map.
/// - Build-time dependencies are typical for proc-macros (`syn`, `quote`, `darling`), whereas
///   the consumer must have `utoipa` and the referenced trait/types available.
///
/// Parameters
/// - `#[modify_schema(allowed_values_fn = path::to::function)]`
///   - Applied to either the enum type (once) or to individual struct fields.
/// - `#[modify_schema(field = core_config_field)]`
///   - Applied to individual struct fields.
///
/// Notes
/// - If the attribute is missing or the function path is invalid, no code is generated for that item,
///   or a compile-time error is emitted by the derive macro.
#[proc_macro_derive(ModifySchema, attributes(modify_schema))]
pub fn core_config_dependant_schema(input: TokenStream) -> TokenStream {
    modify_schema::core_config_dependant_schema(input)
}

/// Attribute macro: `#[modify_schema_autodetect(path = "...")]`
///
/// Purpose
/// - Generates an implementation of `utoipa::Modify` for the annotated struct.
/// - At compile time, it recursively scans a given source directory for Rust items
///   (structs or enums) that `#[derive(ModifySchema)]` and wires their schema
///   mutators into the OpenAPI document’s `components.schemas`.
///
/// How it works (high level)
/// - The macro walks the directory specified by `path`, collecting all `.rs` files.
/// - It parses each file and finds structs/enums that have `#[derive(ModifySchema)]`.
/// - For each such item `T` found at module path `module::...::T`, it generates code that:
///   - Looks up the schema named `T` from `openapi.components.schemas`.
///   - Imports `module::...::T`.
///   - Calls `T::core_config_modify_schema(self.core_config.as_ref(), object)` where
///     `object` is the mutable `SchemaObject` associated with `T`.
/// - The macro then implements `utoipa::Modify` for the annotated struct, calling
///   all discovered mutators in sequence inside `fn modify(&self, openapi: &mut OpenApi)`.
///
/// Example usage
/// ```ignore
/// use utoipa::OpenApi;
///
/// // In your proc-macro consumer crate:
/// // Annotate a struct that will act as the OpenAPI modifier.
/// // The struct must provide a field `core_config` (see limitations).
/// #[modify_schema_autodetect(path = "src")]
/// pub struct ApiDocModifier {
///     pub core_config: Option<CoreConfig>,
/// }
///
/// // Elsewhere in your codebase, types deriving `ModifySchema`:
/// // #[derive(ModifySchema)]
/// // pub struct MyType { /* ... */ }
/// // #[derive(ModifySchema)]
/// // pub enum MyEnum { /* ... */ }
///
/// // Later, attach the modifier to your OpenAPI building pipeline, e.g.:
/// // OpenApi::builder()
/// //     .modify(ApiDocModifier { core_config: Some(CoreConfig::default()) })
/// //     .build();
/// ```
///
/// What gets generated (conceptual)
/// - An implementation roughly equivalent to:
/// ```ignore
/// impl utoipa::Modify for ApiDocModifier {
///     fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
///         if let Some(components) = openapi.components.as_mut() {
///             // For every `T` with `#[derive(ModifySchema)]` discovered under `path`:
///             // if let Some(RefOr::T(Schema::Object(object))) = components.schemas.get_mut("T") {
///             //     use crate::<module_path>::T;
///             //     T::core_config_modify_schema(self.core_config.as_ref(), object);
///             // }
///         }
///     }
/// }
/// ```
///
/// Limitations and requirements
/// - Requires `utoipa` because it implements `utoipa::Modify` and manipulates `utoipa::openapi` types.
/// - Expects all target types to `#[derive(ModifySchema)]` and to expose an associated
///   function: `fn core_config_modify_schema(core: Option<&CoreConfigLike>, object: &mut SchemaObject)`
///   generated by the derive macro. The exact name and signature must match what your
///   `ModifySchema` derive provides.
/// - The annotated struct must have a field named `core_config` that is accessible within the
///   generated `impl` and supports `.as_ref()`; its concrete type is not enforced here but must
///   be what `core_config_modify_schema` expects.
/// - The schema lookup assumes the schema keys match the Rust type names (stringified identifier).
///   If your OpenAPI schema uses different names (e.g., with renames), the lookup will not find them.
/// - Module path resolution from filesystem paths is naive. It assumes a conventional Cargo layout
///   (`src/` under the crate root), simple file-to-module mapping, and `crate::...` addressing.
///   Unusual module setups (e.g., out-of-tree modules, macro-generated modules, or nonstandard
///   layouts) may not resolve correctly.
/// - Only `.rs` files are scanned and only items in those files at parse time are considered.
///   Items generated purely by macros that don’t reflect in the parsed file may be missed.
/// - This macro runs at compile time and will traverse the directory tree under `path`; very large
///   trees may impact build time.
///
/// Proc-macro crate side dependencies (informational)
/// - This implementation uses `syn`, `quote`, `proc_macro`, `darling` (for parsing macro args),
///   and `walkdir` (for filesystem traversal). These are dependencies of the macro crate itself;
///   consumer crates mainly need `utoipa` and whatever provides `#[derive(ModifySchema)]`.
///
/// Parameters
/// - `path: &str` – Directory to recursively scan for Rust files containing types that
///   derive `ModifySchema`.
///
/// Output
/// - An `impl utoipa::Modify` for the annotated struct that applies all discovered schema
///   modifications into `openapi.components.schemas` during OpenAPI generation.
#[proc_macro_attribute]
pub fn modify_schema_autodetect(args: TokenStream, input: TokenStream) -> TokenStream {
    match modify_schema_autodetect::modify_schema_autodetect(args, input) {
        Ok(tokens) => tokens,
        Err(e) => TokenStream::from(e.write_errors()),
    }
}
