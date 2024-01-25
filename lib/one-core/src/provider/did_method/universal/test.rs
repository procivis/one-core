use crate::provider::did_method::{universal::UniversalDidMethod, DidMethod, Operation};

#[test]
fn test_get_capabilities() {
    let provider = UniversalDidMethod {};

    assert_eq!(
        vec![Operation::RESOLVE],
        provider.get_capabilities().operations
    );
}
