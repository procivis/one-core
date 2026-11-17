use darling::{Error, FromAttributes};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Field, Fields, ItemEnum, ItemStruct};

#[derive(FromAttributes)]
#[darling(attributes(modify_schema))]
struct ModifySchemaAttributes {
    allowed_values_fn: Option<syn::ExprPath>,
    field: Option<syn::ExprPath>,
}

pub(super) fn core_config_dependant_schema(input: TokenStream) -> TokenStream {
    if let Ok(input) = syn::parse::<ItemStruct>(input.clone()) {
        on_struct(input)
    } else if let Ok(item_enum) = syn::parse::<ItemEnum>(input) {
        on_enum(&item_enum)
    } else {
        TokenStream::from(
            Error::custom("The attribute can only be applied to struct or enum definitions.")
                .with_span(&Span::call_site())
                .write_errors(),
        )
    }
}

fn on_struct(input: ItemStruct) -> TokenStream {
    let struct_name = input.ident.to_string();
    let fields: Vec<proc_macro2::TokenStream> = match input.fields {
        Fields::Named(named_fields) => named_fields
            .named
            .into_iter()
            .filter_map(|field| on_struct_field(&struct_name, field))
            .collect(),
        Fields::Unnamed(_) | Fields::Unit => {
            // We do nothing on unit or unnamed fields
            vec![]
        }
    };
    let ident = input.ident;

    if fields.is_empty() {
        quote!().into()
    } else {
        quote! {
            impl crate::openapi::CoreConfigModifySchema for #ident {
                fn core_config_modify_schema(core_config: &one_core::config::core_config::CoreConfig, object: &mut utoipa::openapi::Object) {
                    use one_core::config::core_config::{ConfigExt};
                    #(#fields)*
                }
            }
        }.into()
    }
}

fn on_struct_field(struct_name: &str, named_field: Field) -> Option<proc_macro2::TokenStream> {
    let deprecated = named_field
        .attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("deprecated"));
    let attributes = match ModifySchemaAttributes::from_attributes(&named_field.attrs) {
        Ok(v) => v,
        Err(e) => {
            return Some(e.write_errors());
        }
    };
    let field_ident = named_field.ident?;
    let field_ty = named_field.ty;

    let deprecated = deprecated.then(|| {
        let field_name = to_camel_case(&field_ident.to_string());
        quote! {
            if let Some(schema) = object.properties.get_mut(#field_name) {
                let item = std::mem::replace(
                    schema,
                    utoipa::openapi::RefOr::T(utoipa::openapi::Schema::OneOf(
                        utoipa::openapi::schema::OneOf::new()
                    )),
                );
                let mut deprecated = utoipa::openapi::schema::OneOf::new();
                deprecated.items.push(item);
                deprecated.extensions = Some(
                    utoipa::openapi::extensions::Extensions::from_iter([("deprecated", true)])
                );
                *schema = utoipa::openapi::RefOr::T(
                    utoipa::openapi::Schema::OneOf(deprecated)
                );
            }
        }
    });
    let configured = if let Some(allowed_values_fn) = attributes.allowed_values_fn {
        on_struct_fields_allowed_values_fn(field_ident, allowed_values_fn)
    } else if let Some(field) = attributes.field {
        on_struct_fields_field(struct_name, field_ident, &field_ty, field)
    } else {
        None
    };

    if deprecated.is_some() || configured.is_some() {
        // `configured` must run first: `deprecated` wraps the property in a `oneOf`
        Some(quote! {
            #configured
            #deprecated
        })
    } else {
        None
    }
}

fn on_struct_fields_allowed_values_fn(
    field_ident: proc_macro2::Ident,
    allowed_values_fn: syn::ExprPath,
) -> Option<proc_macro2::TokenStream> {
    let field_ident = field_ident.to_string();
    let ident_str = field_ident.strip_prefix("r#").unwrap_or(&field_ident);
    Some(quote! {
        if let std::option::Option::Some(utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(field_obj))) = object.properties.get_mut(#ident_str) {
            let old_values = field_obj.enum_values.clone();
            let values = #allowed_values_fn(core_config, old_values);
            if let Some(values) = values {
                field_obj.examples = values;
            }
        };
    })
}

fn on_struct_fields_field(
    struct_name: &str,
    field_ident: proc_macro2::Ident,
    field_ty: &syn::Type,
    field: syn::ExprPath,
) -> Option<proc_macro2::TokenStream> {
    let field_ident = field_ident.to_string();
    let ident_str = field_ident.strip_prefix("r#").unwrap_or(&field_ident);
    let ident_camel_case = to_camel_case(ident_str);
    let location = format!("{struct_name}.{ident_camel_case}");
    // compile-time check that the field type is supported, reported on the field type
    let type_check = quote_spanned! {field_ty.span()=>
        crate::openapi::assert_config_field_type::<#field_ty>();
    };
    Some(quote! {
        #type_check
        if let std::option::Option::Some(schema) = object.properties.get_mut(#ident_camel_case)
            && let std::option::Option::Some(field_obj) = crate::openapi::config_field_schema(schema, #location)
        {
            let values: Vec<String> = core_config
                .#field
                .iter_enabled()
                .map(|(k, _)| std::string::ToString::to_string(k))
                .collect();
            if !values.is_empty() {
                let formatted: Vec<String> = values.iter().map(|value| format!("`{value}`")).collect();
                let description = format!("Possible values: {}", formatted.join(", "));
                field_obj.description = Some(match &field_obj.description {
                    Some(current) => format!("{current}  \n{description}"),
                    None => description,
                });
            }
            field_obj.examples = values.into_iter().map(utoipa::r#gen::serde_json::Value::String).collect();
        }
    })
}

fn on_enum(item_enum: &ItemEnum) -> TokenStream {
    let attributes = match ModifySchemaAttributes::from_attributes(&item_enum.attrs) {
        Ok(v) => v,
        Err(e) => {
            return TokenStream::from(e.write_errors());
        }
    };

    if let Some(allowed_values_fn) = attributes.allowed_values_fn {
        let ident = &item_enum.ident;
        quote! {
            impl crate::openapi::CoreConfigModifySchema for #ident {
                fn core_config_modify_schema(core_config: &one_core::config::core_config::CoreConfig, object: &mut utoipa::openapi::Object) {
                    let old_values = object.enum_values.clone();
                    let values = #allowed_values_fn(core_config, old_values);
                    if let Some(values) = values {
                        object.examples = values;
                    }
                }
            }
        }
            .into()
    } else {
        quote! {}.into()
    }
}

fn to_camel_case(input: &str) -> String {
    let mut pascal = String::new();
    let mut capitalize = true;
    for ch in input.chars() {
        if ch == '_' {
            capitalize = true;
        } else if capitalize {
            pascal.push(ch.to_ascii_uppercase());
            capitalize = false;
        } else {
            pascal.push(ch);
        }
    }
    pascal[..1].to_ascii_lowercase() + &pascal[1..]
}
