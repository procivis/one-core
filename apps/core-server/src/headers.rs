use std::str::FromStr;
use std::sync::LazyLock;

use mime::Mime;

#[allow(clippy::expect_used)]
pub(crate) static APPLICATION_XML: LazyLock<Mime> = LazyLock::new(|| {
    Mime::from_str("application/xml").expect("application/xml is valid mime type")
});

#[expect(clippy::expect_used)]
pub(crate) static APPLICATION_PEM_CHAIN: LazyLock<Mime> = LazyLock::new(|| {
    Mime::from_str("application/pem-certificate-chain")
        .expect("application/pem-certificate-chain is valid mime type")
});

#[expect(clippy::expect_used)]
pub(crate) static APPLICATION_COSE_X509: LazyLock<Mime> = LazyLock::new(|| {
    Mime::from_str("application/cose-x509").expect("application/cose-x509 is valid mime type")
});

#[allow(clippy::expect_used)]
pub(crate) static APPLICATION_JWT: LazyLock<Mime> = LazyLock::new(|| {
    Mime::from_str("application/jwt").expect("application/jwt is valid mime type")
});
