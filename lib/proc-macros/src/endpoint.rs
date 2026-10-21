use darling::Error;
use proc_macro::TokenStream;
use proc_macro2::{Delimiter, TokenTree};
use quote::quote;
use syn::parse::Parse;
use syn::{
    ExprArray, GenericArgument, Ident, PathArguments, ReturnType, Token, Type, parse_macro_input,
};

pub fn endpoint(args: TokenStream, input: TokenStream) -> TokenStream {
    let function: syn::ItemFn = match syn::parse(input) {
        Ok(fn_decl) => fn_decl,
        Err(e) => return Error::from(e).write_errors().into(),
    };

    let Attrs {
        permissions,
        mut utoipa,
    } = parse_macro_input!(args);

    let permissions = permissions.as_ref().map(|p| &p.elems);

    let mut additions = vec![];

    if !declares(&utoipa, "responses") {
        match derive_responses(&function.sig.output) {
            Some(responses) => additions.push(responses),
            None => {
                return Error::custom(
                    "declare `responses(...)`: the return type is not a known response wrapper",
                )
                .with_span(&function.sig.output)
                .write_errors()
                .into();
            }
        }
    }

    if let Some(permissions) = permissions {
        additions.push(quote! {
            extensions(("x-permissions" = json!([#permissions])))
        });
    }

    if !additions.is_empty() {
        let tokens: Vec<TokenTree> = utoipa.into_iter().collect();
        let Some(last) = tokens.last() else {
            return Error::too_few_items(1).write_errors().into();
        };
        let ends_with_comma = matches!(last, TokenTree::Punct(p) if p.as_char() == ',');

        utoipa = tokens.into_iter().collect();
        if !ends_with_comma {
            utoipa.extend(quote! {,});
        }
        utoipa.extend(quote! { #(#additions),* });
    }

    let mut declarations = quote! {
        #[utoipa::path(#utoipa)]
    };

    if let Some(permissions) = permissions {
        declarations.extend(quote! {
            #[proc_macros::require_permissions(#permissions)]
        });
    }

    quote! {
        #declarations
        #function
    }
    .into()
}

fn declares(utoipa: &proc_macro2::TokenStream, name: &str) -> bool {
    let mut tokens = utoipa.clone().into_iter().peekable();
    while let Some(token) = tokens.next() {
        if let TokenTree::Ident(ident) = token
            && ident == name
            && let Some(TokenTree::Group(group)) = tokens.peek()
            && group.delimiter() == Delimiter::Parenthesis
        {
            return true;
        }
    }
    false
}

fn derive_responses(output: &ReturnType) -> Option<proc_macro2::TokenStream> {
    let ReturnType::Type(_, ty) = output else {
        return None;
    };
    let (wrapper, body) = split_generic(ty)?;

    let success = match wrapper.to_string().as_str() {
        "OkOrErrorResponse" => {
            let body = body?;
            let body = match split_generic(body) {
                Some((vec, Some(item))) if vec == "VecResponse" => quote! { Vec<#item> },
                _ => quote! { #body },
            };
            quote! { (status = OK, description = "OK", body = #body) }
        }
        "CreatedOrErrorResponse" => {
            let body = body?;
            quote! { (status = CREATED, description = "Created", body = #body) }
        }
        "EmptyOrErrorResponse" => quote! { (status = NO_CONTENT, description = "No Content") },
        _ => return None,
    };

    Some(quote! { responses(#success, crate::dto::response::ErrorResponse) })
}

fn split_generic(ty: &Type) -> Option<(&Ident, Option<&Type>)> {
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    let argument = match &segment.arguments {
        PathArguments::AngleBracketed(arguments) => {
            arguments.args.iter().find_map(|argument| match argument {
                GenericArgument::Type(ty) => Some(ty),
                _ => None,
            })
        }
        _ => None,
    };
    Some((&segment.ident, argument))
}

#[derive(Debug)]
pub struct Attrs {
    permissions: Option<ExprArray>,
    utoipa: proc_macro2::TokenStream,
}

impl Parse for Attrs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let iden: Ident = input.parse()?;
        if iden != "permissions" {
            return Err(syn::Error::new_spanned(
                iden,
                "`permissions` must be declared first",
            ));
        }
        input.parse::<Token![=]>()?;
        let permissions: ExprArray = input.parse()?;
        input.parse::<Token![,]>()?;

        Ok(Self {
            permissions: if permissions.elems.is_empty() {
                None
            } else {
                Some(permissions)
            },
            utoipa: input.parse()?,
        })
    }
}
