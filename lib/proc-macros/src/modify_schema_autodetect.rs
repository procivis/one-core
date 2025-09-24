use std::fs::File;
use std::io::Read;

use darling::ast::NestedMeta;
use darling::{Error, FromMeta};
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{Attribute, ItemStruct, Meta, Token};

#[derive(FromMeta)]
struct AutoDetectOptions {
    path: String,
}

pub(super) fn modify_schema_autodetect(
    args: TokenStream,
    input: TokenStream,
) -> darling::Result<TokenStream> {
    let Ok(input) = syn::parse::<ItemStruct>(input) else {
        return Err(
            Error::custom("The attribute can only be applied to struct definitions.")
                .with_span(&Span::call_site()),
        );
    };
    let meta_list = NestedMeta::parse_meta_list(args.into())?;
    let options = AutoDetectOptions::from_list(&meta_list)?;

    let rust_files = walkdir::WalkDir::new(options.path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file() && e.path().extension().and_then(|a| a.to_str()) == Some("rs")
        })
        .collect::<Vec<_>>();

    let mut struct_items = Vec::new();

    for file in rust_files {
        let path = file.path();
        let mut file = File::open(path).expect("Unable to open file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Unable to read file");
        let syntax_tree = syn::parse_file(&contents)?;
        let structs_with_attr = find_idents_with_attr(syntax_tree, "ModifySchema")?;
        let module_path = path_to_module_path(path.to_str().expect("Unable to parse file path"));
        for struct_with_attr in structs_with_attr {
            let module = syn::Path::from_string(&module_path)?;
            let ident = &struct_with_attr.ident;
            let ident_str = struct_with_attr.ident.to_string();
            let quote = quote! {
                let std::option::Option::Some(utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(object))) = components.schemas.get_mut(#ident_str) else {
                    return;
                };
                use #module::#ident;
                #ident::core_config_modify_schema(self.core_config.as_ref(), object);
            };
            struct_items.push(quote);
        }
    }

    let ident = &input.ident;
    Ok(quote! {
        #input

        impl utoipa::Modify for #ident {
            fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
                let Some(components) = openapi.components.as_mut() else {
                    return;
                };
                #(#struct_items)*
            }
        }
    }
    .into())
}

struct InnerItem {
    ident: Ident,
    attrs: Vec<Attribute>,
}

fn find_idents_with_attr(syntax_tree: syn::File, attribute: &str) -> syn::Result<Vec<InnerItem>> {
    syntax_tree
        .items
        .into_iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) => Some(InnerItem {
                ident: item.ident,
                attrs: item.attrs,
            }),
            syn::Item::Enum(item) => Some(InnerItem {
                ident: item.ident,
                attrs: item.attrs,
            }),
            _ => None,
        })
        .filter_map(|item| match has_derive_attr(&item, attribute) {
            Ok(bool) => {
                if bool {
                    Some(Ok(item))
                } else {
                    None
                }
            }
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn has_derive_attr(item_struct: &InnerItem, attribute: &str) -> syn::Result<bool> {
    for attr in &item_struct.attrs {
        if attr.meta.path().is_ident("derive") {
            let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
            for nested_meta in nested {
                if nested_meta.path().is_ident(attribute) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

// naive implementation of filesystem path to rust module path
fn path_to_module_path(path: &str) -> String {
    let path = path.strip_prefix("./").unwrap_or(path);
    let path = &path[0..path.find(".").unwrap_or(path.len())];
    let path = path.replace("/", "::");
    let path = &path[path.find("src::").unwrap_or(0)..path.len()];
    path.replace("src::", "crate::")
}
