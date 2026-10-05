use model::relation::Model;
use proc_macros::Model;
use similar_asserts::assert_eq;

mod model {
    pub mod relation {
        pub trait Model {
            type Id: Clone + std::fmt::Debug + std::fmt::Display;
            fn id(&self) -> &Self::Id;
        }
    }
}

#[test]
fn struct_returns_identifier_reference() {
    #[derive(Model)]
    struct Example {
        _payload: Vec<u8>,
        #[model(id)]
        identifier: String,
    }

    let model = Example {
        _payload: vec![1, 2, 3],
        identifier: "struct-id".to_owned(),
    };

    assert!(std::ptr::eq(model.id(), &model.identifier));
}

#[test]
fn enum_returns_each_variants_identifier_reference() {
    type Identifier = String;

    #[derive(Model)]
    enum Example {
        Named {
            _payload: Vec<u8>,
            #[model(id)]
            identifier: String,
        },
        Other {
            #[model(id)]
            r#type: Identifier,
        },
        Tuple(usize, #[model(id)] String, bool),
        Newtype(#[model(id)] String),
    }

    let models = [
        Example::Named {
            _payload: vec![1, 2, 3],
            identifier: "named-id".to_owned(),
        },
        Example::Other {
            r#type: "other-id".to_owned(),
        },
        Example::Tuple(42, "tuple-id".to_owned(), true),
        Example::Newtype("newtype-id".to_owned()),
    ];

    for model in models {
        let expected = match &model {
            Example::Named { identifier, .. } => identifier,
            Example::Other { r#type } => r#type,
            Example::Tuple(payload, identifier, enabled) => {
                assert_eq!(*payload, 42);
                assert!(*enabled);
                identifier
            }
            Example::Newtype(identifier) => identifier,
        };
        assert!(std::ptr::eq(model.id(), expected));
    }
}

#[test]
fn enum_preserves_generics_and_where_clause() {
    #[derive(Model)]
    enum Example<T>
    where
        T: Clone + std::fmt::Debug + std::fmt::Display,
    {
        Named {
            #[model(id)]
            id: T,
        },
        Tuple(#[model(id)] T),
    }

    assert_eq!(Example::Named { id: 42 }.id(), &42);
    assert_eq!(Example::Tuple("generic-id".to_owned()).id(), "generic-id");
}
