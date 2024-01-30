use crate::provider::did_method::{
    universal::{Params, UniversalDidMethod},
    DidMethod, Operation,
};

#[test]
fn test_get_capabilities() {
    let provider = UniversalDidMethod::new(Params {
        resolver_url: "".into(),
    });

    assert_eq!(
        vec![Operation::RESOLVE],
        provider.get_capabilities().operations
    );
}
