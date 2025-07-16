//! Code in this crate is _heavily_ inspired by the serde_with_macros crate.

use darling::ast::NestedMeta;
use darling::{Error, FromMeta};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{Field, Fields, ItemEnum, ItemStruct, Type, parse_quote};

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
    #[derive(FromMeta)]
    struct SerdeContainerOptions {
        skip_serializing_none: Option<bool>,
    }

    match NestedMeta::parse_meta_list(args.into()) {
        Ok(list) => {
            let container_options = match SerdeContainerOptions::from_list(&list) {
                Ok(v) => v,
                Err(e) => {
                    return TokenStream::from(e.write_errors());
                }
            };

            let res = apply_function_to_struct_and_enum_fields(input, |field| {
                add_utoipa_nullable_false(field)
            })
            .unwrap_or_else(Error::write_errors);

            // if not explicitly disabled also add the serde skip_serializing_none attribute
            let res = match container_options.skip_serializing_none {
                Some(false) => res,
                _ => {
                    quote!(
                        #[serde_with::skip_serializing_none]
                        #res
                    )
                }
            };

            TokenStream::from(res)
        }
        Err(e) => TokenStream::from(Error::from(e).write_errors()),
    }
}

/// Add the `schema(nullable = false)` annotation to a field of a struct
fn add_utoipa_nullable_false(field: &mut Field) -> Result<(), Error> {
    if !is_std_option(&field.ty) {
        return Ok(());
    }

    let has_schema = field_has_attribute(field, "schema");
    // Do nothing if `schema`  is already present
    if has_schema {
        return Ok(());
    }

    // Add the `schema` attribute
    let attr = parse_quote!(
        #[schema(nullable = false)]
    );
    field.attrs.push(attr);
    Ok(())
}

fn is_std_option(type_: &Type) -> bool {
    match type_ {
        Type::Array(_)
        | Type::BareFn(_)
        | Type::ImplTrait(_)
        | Type::Infer(_)
        | Type::Macro(_)
        | Type::Never(_)
        | Type::Ptr(_)
        | Type::Reference(_)
        | Type::Slice(_)
        | Type::TraitObject(_)
        | Type::Tuple(_)
        | Type::Verbatim(_) => false,

        Type::Group(syn::TypeGroup { elem, .. })
        | Type::Paren(syn::TypeParen { elem, .. })
        | Type::Path(syn::TypePath {
            qself: Some(syn::QSelf { ty: elem, .. }),
            ..
        }) => is_std_option(elem),

        Type::Path(syn::TypePath { qself: None, path }) => {
            (path.leading_colon.is_none()
                && path.segments.len() == 1
                && path.segments[0].ident == "Option")
                || (path.segments.len() == 3
                    && (path.segments[0].ident == "std" || path.segments[0].ident == "core")
                    && path.segments[1].ident == "option"
                    && path.segments[2].ident == "Option")
        }
        _ => false,
    }
}

fn field_has_attribute(field: &Field, namespace: &str) -> bool {
    for attr in &field.attrs {
        if attr.path().is_ident(namespace) {
            return true;
        }
    }
    false
}

/// Apply function on every field of structs or enums
fn apply_function_to_struct_and_enum_fields<F>(
    input: TokenStream,
    function: F,
) -> Result<TokenStream2, Error>
where
    F: Copy,
    F: Fn(&mut Field) -> Result<(), Error>,
{
    if let Ok(mut input) = syn::parse::<ItemStruct>(input.clone()) {
        apply_on_fields(&mut input.fields, function)?;
        Ok(quote!(#input))
    } else if let Ok(mut input) = syn::parse::<ItemEnum>(input) {
        let errors = input
            .variants
            .iter_mut()
            .map(|variant| apply_on_fields(&mut variant.fields, function))
            .filter_map(|res| res.err())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(quote!(#input))
        } else {
            Err(Error::multiple(errors))
        }
    } else {
        Err(
            Error::custom("The attribute can only be applied to struct or enum definitions.")
                .with_span(&Span::call_site()),
        )
    }
}

/// Handle a single struct or a single enum variant
fn apply_on_fields<F>(fields: &mut Fields, function: F) -> Result<(), Error>
where
    F: Fn(&mut Field) -> Result<(), Error>,
{
    match fields {
        // simple, no fields, do nothing
        Fields::Unit => Ok(()),
        Fields::Named(fields) => {
            let errors: Vec<Error> = fields
                .named
                .iter_mut()
                .map(|field| function(field).map_err(|err| err.with_span(&field)))
                .filter_map(|res| res.err())
                .collect();
            if errors.is_empty() {
                Ok(())
            } else {
                Err(Error::multiple(errors))
            }
        }
        Fields::Unnamed(fields) => {
            let errors: Vec<Error> = fields
                .unnamed
                .iter_mut()
                .map(|field| function(field).map_err(|err| err.with_span(&field)))
                .filter_map(|res| res.err())
                .collect();
            if errors.is_empty() {
                Ok(())
            } else {
                Err(Error::multiple(errors))
            }
        }
    }
}
