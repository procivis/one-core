//! Code in this crate is _heavily_ inspired by the serde_with_macros crate.

use darling::ast::NestedMeta;
use darling::{Error, FromMeta};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{Field, Fields, ItemEnum, ItemStruct, Meta, Type, parse_quote};

pub(super) fn options_not_nullable(args: TokenStream, input: TokenStream) -> TokenStream {
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

/// Add `nullable = false` to the `schema` attribute of an `Option` field, unless the attribute
/// already declares `nullable`.
fn add_utoipa_nullable_false(field: &mut Field) -> Result<(), Error> {
    if !is_std_option(&field.ty) {
        return Ok(());
    }

    let schema = field
        .attrs
        .iter_mut()
        .find(|attr| attr.path().is_ident("schema"));
    let Some(schema) = schema else {
        field.attrs.push(parse_quote!(#[schema(nullable = false)]));
        return Ok(());
    };

    let Meta::List(list) = &mut schema.meta else {
        return Err(Error::custom("expected `#[schema(...)]`").with_span(schema));
    };
    let declares_nullable =
        list.tokens.clone().into_iter().any(
            |token| matches!(token, proc_macro2::TokenTree::Ident(ident) if ident == "nullable"),
        );
    if !declares_nullable {
        let existing = &list.tokens;
        list.tokens = quote!(#existing, nullable = false);
    }
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
