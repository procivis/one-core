use darling::Error;
use proc_macro::TokenStream;
use quote::quote;
use syn::__private::TokenStream2;
use syn::{FnArg, Stmt, parse_quote};

pub fn require_permissions(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = TokenStream2::from(args);
    let mut function: syn::ItemFn = match syn::parse(input) {
        Ok(fn_decl) => fn_decl,
        Err(e) => return TokenStream::from(Error::from(e).write_errors()),
    };
    let authz_arg: FnArg =
        parse_quote!(axum::Extension(authorized): axum::Extension<crate::middleware::Authorized>);
    function.sig.inputs.insert(0, authz_arg);
    let config_arg: FnArg =
        parse_quote!(axum::Extension(config): axum::Extension<std::sync::Arc<crate::ServerConfig>>);
    function.sig.inputs.insert(0, config_arg);
    let mut new_statements: Vec<Stmt> = parse_quote! {
        let required_permissions = vec![#args];
        match crate::permissions::permission_check(&authorized, &config, &required_permissions) {
            Ok(()) => {}
            Err(err) => return err.into(),
        };
    };
    new_statements.append(&mut function.block.stmts);
    function.block.stmts = new_statements;
    TokenStream::from(quote! {
        #function
    })
}
