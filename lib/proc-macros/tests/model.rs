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

#[derive(Model)]
struct NestedModel {
    #[model(id)]
    identifier: String,
}

impl NestedModel {
    fn id(&self) -> &str {
        "inherent method, not the model identifier"
    }
}

#[test]
fn struct_delegates_to_nested_models_recursively() {
    // Deriving Model must not require importing the trait into this module.
    mod wrappers {
        #[derive(proc_macros::Model)]
        pub(super) struct Inner {
            #[model(nested)]
            pub(super) details: super::NestedModel,
        }

        #[derive(proc_macros::Model)]
        pub(super) struct Outer {
            #[model(nested)]
            pub(super) inner: Inner,
        }
    }

    let model = wrappers::Outer {
        inner: wrappers::Inner {
            details: NestedModel {
                identifier: "nested-id".to_owned(),
            },
        },
    };

    assert_eq!(
        model.inner.details.id(),
        "inherent method, not the model identifier"
    );
    assert!(std::ptr::eq(model.id(), &model.inner.details.identifier));
}

#[test]
fn enum_supports_direct_and_different_nested_models() {
    #[derive(Model)]
    struct OtherModel {
        #[model(id)]
        other_id: String,
    }

    #[derive(Model)]
    enum Example {
        Named {
            _payload: Vec<u8>,
            #[model(nested)]
            details: NestedModel,
        },
        Direct {
            #[model(id)]
            id: String,
        },
        Tuple(bool, #[model(nested)] NestedModel),
        Other(#[model(nested)] OtherModel),
    }

    let models = [
        Example::Named {
            _payload: vec![1, 2, 3],
            details: NestedModel {
                identifier: "named-nested-id".to_owned(),
            },
        },
        Example::Direct {
            id: "direct-id".to_owned(),
        },
        Example::Tuple(
            true,
            NestedModel {
                identifier: "tuple-nested-id".to_owned(),
            },
        ),
        Example::Other(OtherModel {
            other_id: "other-nested-id".to_owned(),
        }),
    ];

    for model in models {
        let expected = match &model {
            Example::Named { details, .. } => &details.identifier,
            Example::Direct { id } => id,
            Example::Tuple(enabled, details) => {
                assert!(*enabled);
                &details.identifier
            }
            Example::Other(details) => &details.other_id,
        };
        assert!(std::ptr::eq(model.id(), expected));
    }
}

#[test]
fn nested_models_support_generics() {
    #[derive(Model)]
    struct Wrapper<T: Model> {
        #[model(nested)]
        details: T,
    }

    #[derive(Model)]
    enum Example<T>
    where
        T: Model<Id = String>,
    {
        Direct {
            #[model(id)]
            id: String,
        },
        Nested(#[model(nested)] T),
    }

    let wrapper = Wrapper {
        details: NestedModel {
            identifier: "generic-nested-id".to_owned(),
        },
    };
    assert!(std::ptr::eq(wrapper.id(), &wrapper.details.identifier));
    assert_eq!(Example::Nested(wrapper).id(), "generic-nested-id");
    assert_eq!(
        Example::<NestedModel>::Direct {
            id: "direct-id".to_owned()
        }
        .id(),
        "direct-id"
    );
}
