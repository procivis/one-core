use darling::util::Flag;
use darling::{Error, FromAttributes};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Member, parse_macro_input};

#[cfg(test)]
mod test;

pub(super) fn repository_model(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    process_model(input)
        .unwrap_or_else(Error::write_errors)
        .into()
}

struct IdentifierField {
    member: Member,
    field_type: syn::Type,
}

fn process_model(input: DeriveInput) -> Result<TokenStream2, Error> {
    if let Some(attribute) = input
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("model"))
    {
        return Err(
            Error::custom("#[model] attributes not allowed on struct or enum level")
                .with_span(attribute),
        );
    }

    let (field_type, body) = match input.data {
        Data::Struct(struct_data) => {
            if !matches!(struct_data.fields, Fields::Named(_)) {
                return Err(Error::custom(
                    "`Model` macro only usable on structs with named fields",
                )
                .with_span(&input.ident));
            }
            let IdentifierField { member, field_type } =
                extract_identifier_from_fields(struct_data.fields)
                    .map_err(|err| err.with_span(&input.ident))?;
            (field_type, quote! { &self.#member })
        }
        Data::Enum(enum_data) => {
            let mut identifier_type = None;
            let mut arms = Vec::new();
            for variant in enum_data.variants {
                if let Some(attribute) = variant
                    .attrs
                    .iter()
                    .find(|attr| attr.path().is_ident("model"))
                {
                    return Err(
                        Error::custom("#[model] attributes not allowed on variant level")
                            .with_span(attribute),
                    );
                }
                let IdentifierField { member, field_type } =
                    extract_identifier_from_fields(variant.fields)
                        .map_err(|err| err.with_span(&variant.ident))?;
                // Let Rust check type compatibility so aliases work across variants.
                identifier_type.get_or_insert(field_type);
                let variant_name = variant.ident;
                // Numeric members allow this pattern to work for tuple variants too.
                arms.push(quote! { Self::#variant_name { #member: id, .. } => id });
            }
            let field_type = identifier_type.ok_or_else(|| {
                Error::custom("`Model` macro requires an enum with at least one variant")
                    .with_span(&input.ident)
            })?;
            (field_type, quote! { match self { #(#arms,)* } })
        }
        Data::Union(_) => {
            return Err(
                Error::custom("`Model` macro can only be applied to a struct or enum.")
                    .with_span(&input.ident),
            );
        }
    };

    let model_name = input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics crate::model::relation::Model for #model_name #type_generics #where_clause {
            type Id = #field_type;
            fn id(&self) -> &Self::Id {
                #body
            }
        }
    })
}

fn extract_identifier_from_fields(fields: Fields) -> Result<IdentifierField, Error> {
    let mut identifier_field: Option<IdentifierField> = None;

    for (index, field) in fields.into_iter().enumerate() {
        let attributes = ModelAttributes::from_attributes(&field.attrs)?;
        if !attributes.id.is_present() {
            continue;
        }
        if identifier_field.is_some() {
            return Err(
                Error::custom("Multiple model identifier fields specified").with_span(&field)
            );
        }

        identifier_field = Some(IdentifierField {
            member: field
                .ident
                .map(Member::Named)
                .unwrap_or_else(|| Member::Unnamed(index.into())),
            field_type: field.ty,
        });
    }

    match identifier_field {
        Some(field) => Ok(field),
        None => Err(Error::custom(
            "No model identifier field specified. Mark the identifier field with `#[model(id)]`.",
        )),
    }
}

#[derive(FromAttributes)]
#[darling(attributes(model))]
struct ModelAttributes {
    id: Flag,
}
