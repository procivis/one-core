use darling::{Error, FromAttributes};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
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
    let fields: Vec<proc_macro2::TokenStream> = match input.fields {
        Fields::Named(named_fields) => named_fields
            .named
            .into_iter()
            .filter_map(on_struct_field)
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

fn on_struct_field(named_field: Field) -> Option<proc_macro2::TokenStream> {
    let attributes = match ModifySchemaAttributes::from_attributes(&named_field.attrs) {
        Ok(v) => v,
        Err(e) => {
            return Some(e.write_errors());
        }
    };
    let field_ident = named_field.ident?;

    if let Some(allowed_values_fn) = attributes.allowed_values_fn {
        on_struct_fields_allowed_values_fn(field_ident, allowed_values_fn)
    } else if let Some(field) = attributes.field {
        on_struct_fields_field(field_ident, field)
    } else {
        None
    }
}

fn on_struct_fields_allowed_values_fn(
    field_ident: proc_macro2::Ident,
    allowed_values_fn: syn::ExprPath,
) -> Option<proc_macro2::TokenStream> {
    let ident_str = field_ident.to_string();
    Some(quote! {
        if let std::option::Option::Some(utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(field_obj))) = object.properties.get_mut(#ident_str) {
            let old_values = std::mem::take(&mut field_obj.enum_values);
            let values = #allowed_values_fn(core_config, old_values);
            field_obj.enum_values = values;
        };
    })
}

fn on_struct_fields_field(
    field_ident: proc_macro2::Ident,
    field: syn::ExprPath,
) -> Option<proc_macro2::TokenStream> {
    let ident_camel_case = to_camel_case(&field_ident.to_string());
    Some(quote! {
        if let std::option::Option::Some(utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(field_obj))) = object.properties.get_mut(#ident_camel_case) {
            let values: Vec<utoipa::r#gen::serde_json::Value> = core_config
                .#field
                .iter_enabled()
                .map(|(k, _)| std::string::ToString::to_string(k))
                .map(utoipa::r#gen::serde_json::Value::String)
                .collect();
            let values = if values.is_empty() { None } else { Some(values) };
            field_obj.enum_values = values;
        } else if let std::option::Option::Some(utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Array(field_obj))) = object.properties.get_mut(#ident_camel_case) {
            if let utoipa::openapi::schema::ArrayItems::RefOrSchema(s) = &mut field_obj.items {
                if let utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(field_obj)) = s.as_mut() {
                    let values: Vec<utoipa::r#gen::serde_json::Value> = core_config
                        .#field
                        .iter_enabled()
                        .map(|(k, _)| std::string::ToString::to_string(k))
                        .map(utoipa::r#gen::serde_json::Value::String)
                        .collect();
                    let values = if values.is_empty() { None } else { Some(values) };
                    field_obj.enum_values = values;
                }
            }
        };
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
                    let old_values = std::mem::take(&mut object.enum_values);
                    let values = #allowed_values_fn(core_config, old_values);
                    object.enum_values = values;
                }
            }
        }
            .into()
    } else {
        quote! {}.into()
    }
}

pub fn to_camel_case(input: &str) -> String {
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
