use similar_asserts::assert_eq;
use syn::parse_quote;

use super::process_model;

#[test]
fn rejects_variant_without_identifier() {
    let error = process_model(parse_quote! {
        enum Example {
            Valid { #[model(id)] id: String },
            Invalid { id: String },
        }
    })
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("No model identifier field specified")
    );
}

#[test]
fn rejects_duplicate_identifiers_in_variant() {
    for input in [
        parse_quote! {
            enum Example {
                Invalid { #[model(id)] first: String, #[model(id)] second: String },
            }
        },
        parse_quote! {
            enum Example {
                Invalid(#[model(id)] String, #[model(id)] String),
            }
        },
    ] {
        let error = process_model(input).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Multiple model identifier fields specified"
        );
    }
}

#[test]
fn rejects_variants_without_fields() {
    for input in [
        parse_quote! { enum Example { Unit } },
        parse_quote! { enum Example { EmptyNamed {} } },
        parse_quote! { enum Example { EmptyTuple() } },
    ] {
        let error = process_model(input).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("No model identifier field specified")
        );
    }
}

#[test]
fn rejects_empty_enum() {
    let error = process_model(parse_quote! { enum Example {} }).unwrap_err();
    assert_eq!(
        error.to_string(),
        "`Model` macro requires an enum with at least one variant"
    );
}

#[test]
fn rejects_model_attributes_outside_fields() {
    for input in [
        parse_quote! {
            #[model(id)]
            enum Example { Variant { #[model(id)] id: String } }
        },
        parse_quote! {
            enum Example { #[model(id)] Variant { #[model(id)] id: String } }
        },
        parse_quote! {
            #[model(id)]
            struct Example { #[model(id)] id: String }
        },
    ] {
        let error = process_model(input).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("#[model] attributes not allowed")
        );
    }
}

#[test]
fn rejects_invalid_field_attributes() {
    let error = process_model(parse_quote! {
        enum Example {
            Variant { #[model(unknown)] id: String },
        }
    })
    .unwrap_err();

    assert!(error.to_string().contains("Unknown field"));
}

#[test]
fn rejects_union() {
    let error = process_model(parse_quote! {
        union Example { #[model(id)] id: u64 }
    })
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "`Model` macro can only be applied to a struct or enum."
    );
}

#[test]
fn preserves_struct_identifier_validation() {
    for input in [
        parse_quote! { struct Example { id: String } },
        parse_quote! {
            struct Example { #[model(id)] first: String, #[model(id)] second: String }
        },
        parse_quote! { struct Example(#[model(id)] String); },
        parse_quote! { struct Example; },
    ] {
        assert!(process_model(input).is_err());
    }
}
