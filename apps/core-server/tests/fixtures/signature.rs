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
        "privacy_policy": [{
            "lang": "en",
            "value": "https://example-company.com/en/privacy-policy"
        }],
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
    let csr = test_csr(params);
    serde_json::json!({
        "csr": csr
    })
}

pub fn test_access_certificate_payload(policy: Option<String>) -> serde_json::Value {
    let mut data = serde_json::json!({
        "csr": test_csr(None),
        "organizationIdentifier": "orgId",
        "countryName": "CH",
        "rfc822Name": "tester@test.com",
        "otherNamePhoneNr": "+4123456789",
        "sanUri": "https://some-uri.com",
        "commonName": "common name",
        "nationalRegistryUrl": "https://some-url.com"
    });
    let policy = policy.unwrap_or_else(|| "NATURAL_PERSON".to_owned());
    match policy.as_str() {
        "NATURAL_PERSON" => {
            data["policy"] = serde_json::json!("NATURAL_PERSON");
            data["givenName"] = serde_json::json!("Max");
            data["familyName"] = serde_json::json!("Muster");
        }
        "LEGAL_PERSON" => {
            data["policy"] = serde_json::json!("LEGAL_PERSON");
            data["organizationName"] = serde_json::json!("Org name");
        }
        _ => panic!("Invalid policy"),
    }
    data
}

pub fn test_csr(params: Option<CertificateParams>) -> String {
    let mut params = params.unwrap_or_default();
    if params.key_usages.is_empty() {
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    }
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "test cert");
    params.distinguished_name = distinguished_name;
    params
        .serialize_request(&eddsa::Key)
        .unwrap()
        .pem()
        .unwrap()
}
