use rcgen::{CertificateParams, DistinguishedName, DnType, KeyUsagePurpose};

use crate::fixtures::certificate::eddsa;

pub fn dummy_registration_certificate_payload() -> serde_json::Value {
    serde_json::json!({
        "name": "Jane Doe",
        "sub": {
            "given_name": "Jane",
            "family_name": "Doe",
            "id": "TIN-1234567890"
        },
        "info_uri": "https://example.com",
        "country": "DE",
        "privacy_policy": "https://example-company.com/en/privacy-policy",
        "policy_id": [],
        "certificate_policy": "https://registrar.example.com/certificate-policy",
        "purpose": [],
        "credentials": [],
        "entitlements": [
            "https://uri.etsi.org/19475/Entitlement/PID_Provider"
        ],
        "service": []
    })
}

pub fn test_csr_payload(params: Option<CertificateParams>) -> serde_json::Value {
    let mut params = params.unwrap_or_default();
    if params.key_usages.is_empty() {
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    }
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "test cert");
    params.distinguished_name = distinguished_name;
    let csr = params
        .serialize_request(&eddsa::Key)
        .unwrap()
        .pem()
        .unwrap();
    serde_json::json!({
        "csr": csr
    })
}
