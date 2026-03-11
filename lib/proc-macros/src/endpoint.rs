use darling::Error;
use proc_macro::TokenStream;
use proc_macro2::TokenTree;
use quote::quote;
use syn::parse::Parse;
use syn::{ExprArray, Ident, Token, parse_macro_input};

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

    if let Some(permissions) = permissions {
        let tokens: Vec<TokenTree> = utoipa.into_iter().collect();
        let Some(last) = tokens.last() else {
            return Error::too_few_items(1).write_errors().into();
        };
        let ends_with_comma = matches!(last, TokenTree::Punct(p) if p.as_char() == ',');

        utoipa = tokens.into_iter().collect();
        if !ends_with_comma {
            utoipa.extend(quote! {,});
        }
        utoipa.extend(quote! {
            extensions(("x-permissions" = json!([#permissions])))
        });
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
