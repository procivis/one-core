use one_core::model::certificate::{Certificate, CertificateState};
use one_core::provider::credential_formatter::mdoc_formatter::Params;
use one_core::provider::credential_formatter::model::CredentialData;
use one_core::util::test_mdoc::format_mdoc_credential as format_mdoc;
use rcgen::CertificateParams;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};

pub(crate) async fn format_mdoc_credential(
    mut credential_data: CredentialData,
    params: Params,
) -> String {
    let ca_cert = create_ca_cert(CertificateParams::default(), eddsa::key());

    let cert = create_cert(
        CertificateParams::default(),
        ecdsa::key(),
        &ca_cert,
        eddsa::key(),
    );

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    // the formatter will only use the chain
    credential_data.issuer_certificate = Some(Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: Uuid::new_v4().into(),
        organisation_id: None,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        expiry_date: OffsetDateTime::now_utc(),
        name: "".to_string(),
        chain,
        fingerprint: "".to_string(),
        state: CertificateState::Active,
        key: None,
    });

    format_mdoc(credential_data, params, ecdsa::signature_provider()).await
}
